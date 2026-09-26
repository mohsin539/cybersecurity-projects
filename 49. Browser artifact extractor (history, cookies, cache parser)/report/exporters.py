"""Multi-format report exporters.

Supported formats
-----------------
* ``.csv``  - per-category comma separated files (universal ingest)
* ``.html`` - colorised, escaped, self-contained forensic report
* ``.json`` - full structured result (machine ingest / SIEM)
* ``.xml``  - structured result for legacy tooling
* ``.xlsx`` - multi-sheet spreadsheet
* ``.pdf``  - paginated, printable evidence report
* ``.jsonl`` - hash-chained audit log
* ``.md``   - concise Markdown summary

Every exporter receives the same :class:`~core.models.ScanResult`, so all
formats carry identical provenance, integrity and compliance metadata.
"""
from __future__ import annotations

import csv
import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from core.models import ScanResult

from . import templates

# ---------------------------------------------------------------------------
# Column schemas
# ---------------------------------------------------------------------------
SCHEMAS: Dict[str, List[str]] = {
    "history": ["Browser", "Profile", "URL", "Title", "Visit Count", "Typed Count",
                "Last Visit (UTC)", "Visit Time (UTC)", "Duration (s)", "Transition"],
    "downloads": ["Browser", "Profile", "File", "URL", "Saved Path", "Start Time (UTC)",
                  "Received (B)", "Total (B)", "State", "MIME"],
    "cookies": ["Browser", "Profile", "Host", "Name", "Value", "Value Status", "Path",
                "Expires (UTC)", "Created (UTC)", "Secure", "HttpOnly", "SameSite"],
    "bookmarks": ["Browser", "Profile", "Name", "URL", "Folder", "Date Added (UTC)"],
    "autofill": ["Browser", "Profile", "Field", "Value", "Times Used",
                 "First Used (UTC)", "Last Used (UTC)"],
    "logins": ["Browser", "Profile", "Origin", "Username", "Password", "Password Status",
               "Realm", "Created (UTC)", "Last Used (UTC)"],
    "search_terms": ["Browser", "Profile", "Term", "URL", "Title", "Last Visit (UTC)"],
    "cache": ["Browser", "Profile", "File", "URL / Key", "Size (B)",
              "Modified (UTC)", "Cache Type"],
}

_TITLES = {
    "history": "Browsing History",
    "downloads": "Downloads",
    "cookies": "Cookies",
    "bookmarks": "Bookmarks",
    "autofill": "Autofill / Form Data",
    "logins": "Saved Logins",
    "search_terms": "Search Terms",
    "cache": "Cache Entries",
}

# ---------------------------------------------------------------------------
# Row projection
# ---------------------------------------------------------------------------
def _project(category: str, rec: Dict) -> List:
    b, p = rec.get("_browser", ""), rec.get("_profile", "")
    if category == "history":
        return [b, p, rec.get("url"), rec.get("title"), rec.get("visit_count"),
                rec.get("typed_count"), rec.get("last_visit"), rec.get("visit_time"),
                rec.get("visit_duration_sec"), rec.get("transition")]
    if category == "downloads":
        return [b, p, rec.get("file"), rec.get("url"), rec.get("path"),
                rec.get("start_time"), rec.get("received_bytes"), rec.get("total_bytes"),
                rec.get("state"), rec.get("mime_type")]
    if category == "cookies":
        return [b, p, rec.get("host"), rec.get("name"), rec.get("value"),
                rec.get("value_status"), rec.get("path"), rec.get("expires"),
                rec.get("created"), rec.get("secure"), rec.get("http_only"),
                rec.get("same_site")]
    if category == "bookmarks":
        return [b, p, rec.get("name"), rec.get("url"), rec.get("folder"),
                rec.get("date_added")]
    if category == "autofill":
        return [b, p, rec.get("field"), rec.get("value"), rec.get("times_used"),
                rec.get("first_used"), rec.get("last_used")]
    if category == "logins":
        return [b, p, rec.get("origin"), rec.get("username"), rec.get("password"),
                rec.get("password_status"), rec.get("realm"), rec.get("created"),
                rec.get("last_used")]
    if category == "search_terms":
        return [b, p, rec.get("term"), rec.get("url"), rec.get("title"),
                rec.get("last_visit")]
    if category == "cache":
        return [b, p, rec.get("file"), rec.get("url") or rec.get("key"),
                rec.get("size_bytes"), rec.get("modified"), rec.get("source")]
    return [str(rec.get(k, "")) for k in sorted(rec) if not k.startswith("_")]


def _headers(category: str, records: List[Dict]) -> List[str]:
    if category in SCHEMAS:
        return SCHEMAS[category]
    keys = sorted({k for r in records for k in r if not k.startswith("_")})
    return keys


def bundle(scan: ScanResult) -> List[Tuple[str, List[str], List[List]]]:
    """Return ``[(category, headers, rows), ...]`` for every non-empty set."""
    out = []
    for category in SCHEMAS:
        records = scan.artifacts.get(category, [])
        if not records:
            continue
        headers = _headers(category, records)
        rows = [_project(category, r) for r in records]
        out.append((category, headers, rows))
    return out


def category_titles() -> Dict[str, str]:
    return dict(_TITLES)


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------
def _write_csv(path: str, headers: List[str], rows: List[List]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.writer(fh, quoting=csv.QUOTE_ALL)
        writer.writerow(headers)
        writer.writerows(rows)


def export_csv(path: str, scan: ScanResult, category: Optional[str] = None) -> List[str]:
    """Write one CSV per category (or a single category) and return file paths."""
    os.makedirs(path, exist_ok=True)
    written = []
    data = bundle(scan)
    if category:
        data = [d for d in data if d[0] == category]
    for name, headers, rows in data:
        fp = os.path.join(path, f"{name}.csv")
        _write_csv(fp, headers, rows)
        written.append(fp)
    # Always emit a combined, category-tagged file in tidy "long" form so every
    # category can share one rectangular file without ragged columns.
    combined_rows = []
    for name, headers, rows in bundle(scan):
        for row in rows:
            for header, value in zip(headers, row):
                combined_rows.append([name, header, "" if value is None else value])
    if combined_rows:
        fp = os.path.join(path, "all_artifacts_long.csv")
        _write_csv(fp, ["Category", "Field", "Value"], combined_rows)
        written.append(fp)
    return written


# ---------------------------------------------------------------------------
# JSON / XML
# ---------------------------------------------------------------------------
def export_json(path: str, scan: ScanResult) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(scan.to_dict(), fh, indent=2, ensure_ascii=False, default=str)
    return path


def export_xml(path: str, scan: ScanResult) -> str:
    from xml.sax.saxutils import escape, quoteattr

    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    lines = ['<?xml version="1.0" encoding="UTF-8"?>', '<scanReport>']
    meta = {
        "scan_id": scan.scan_id, "started_at": scan.started_at,
        "finished_at": scan.finished_at, "host": scan.host,
        "platform": scan.platform, "operator": scan.operator,
    }
    lines.append("  <metadata>")
    for k, v in meta.items():
        lines.append(f"    <{k}>{escape(str(v))}</{k}>")
    lines.append("  </metadata>")
    lines.append("  <artifacts>")
    for category, headers, rows in bundle(scan):
        lines.append(f"    <category name={quoteattr(category)} count={quoteattr(str(len(rows)))}>")
        for row in rows:
            lines.append("      <record>")
            for header, value in zip(headers, row):
                tag = (header.replace(" ", "_").replace("/", "_").replace("(", "")
                       .replace(")", "").replace("-", "_").lower() or "field")
                lines.append(f"        <{tag}>{escape('' if value is None else str(value))}</{tag}>")
            lines.append("      </record>")
        lines.append("    </category>")
    lines.append("  </artifacts>")
    lines.append("  <integrity>")
    manifest = scan.integrity.get("manifest", {})
    lines.append(f"    <manifest_sha256>{escape(str(manifest.get('manifest_sha256', '')))}</manifest_sha256>")
    lines.append(f"    <audit_chain_valid>{escape(str(scan.integrity.get('audit_chain_valid')))}</audit_chain_valid>")
    lines.append("  </integrity>")
    lines.append("</scanReport>")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------
def export_html(path: str, scan: ScanResult) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    e = templates._e

    cards = []
    stats = scan.statistics
    cards.append(templates.stat_card("Profiles", stats.get("profiles_scanned", 0)))
    cards.append(templates.stat_card("Total Records", f"{stats.get('total_records', 0):,}",
                                     templates.BRAND["accent2"]))
    cards.append(templates.stat_card("Elapsed", f"{stats.get('elapsed_seconds', 0)}s", "#10b981"))
    manifest = scan.integrity.get("manifest", {})
    cards.append(templates.stat_card("Evidence Items", manifest.get("item_count", 0), "#f59e0b"))
    chain = scan.integrity.get("audit_chain_valid")
    cards.append(templates.stat_card("Audit Chain",
                                     "VALID" if chain else "CHECK", "#059669" if chain else "#dc2626"))
    asse = scan.integrity.get("compliance", {})
    cards.append(templates.stat_card("Control Coverage",
                                     f"{asse.get('coverage_percent', 0)}%", "#8b5cf6"))

    meta_rows = "".join(
        f"<div><b>{e(k)}:</b> {e(v)}</div>" for k, v in {
            "Scan ID": scan.scan_id, "Host": scan.host, "Platform": scan.platform,
            "Operator": scan.operator or "-", "Case ref": scan.case_ref or "-",
            "Started": scan.started_at, "Finished": scan.finished_at,
            "Manifest SHA-256": manifest.get("manifest_sha256", "-"),
        }.items()
    )
    body = ['<div class="grid">' + "".join(cards) + "</div>"]
    body.append(templates.section("Collection Metadata", f'<div class="meta">{meta_rows}</div>'))

    # Browser inventory
    b_rows = [[b.browser, b.profile, b.kind, b.root,
               ", ".join(sorted(b.available.keys()))] for b in scan.browsers]
    body.append(templates.section(
        "Browser Inventory",
        templates.table(["Browser", "Profile", "Engine", "Path", "Artifacts"], b_rows,
                        templates.BRAND["accent2"]) + f'<div class="note">{len(b_rows)} profile(s)</div>',
        count=len(b_rows), color=templates.BRAND["accent2"]))

    # Artifact tables
    for category, headers, rows in bundle(scan):
        color = templates.PALETTE.get(category, templates.BRAND["accent"])
        tbl = f'<div class="scroll">{templates.table(headers, rows, color)}</div>'
        tbl += f'<div class="note">Showing {len(rows):,} record(s). Values escaped for safe rendering.</div>'
        body.append(templates.section(_TITLES.get(category, category.title()), tbl,
                                      count=len(rows), color=color))

    # Evidence manifest
    ev_rows = [[i.category, i.source_path, i.source_sha256 or "(directory)",
                i.record_count, i.collected_at] for i in scan.evidence]
    body.append(templates.section(
        "Evidence Manifest &amp; Chain of Custody",
        templates.table(["Category", "Source", "SHA-256", "Records", "Collected (UTC)"],
                        ev_rows, "#0f172a"), count=len(ev_rows), color="#0f172a"))

    # Compliance
    c_rows = [[c["framework"], c["control"], c["title"], c["module"]]
              for c in asse.get("controls", [])]
    body.append(templates.section(
        "Compliance Control Mapping",
        templates.table(["Framework", "Control", "Title", "Implemented in"], c_rows,
                        "#7c3aed") + f'<div class="note">Coverage: {asse.get("coverage_percent", 0)}%</div>',
        count=len(c_rows), color="#7c3aed"))

    if scan.errors:
        body.append(templates.section(
            "Collection Notes / Errors",
            templates.table(["Detail"], [[x] for x in scan.errors], "#dc2626"),
            count=len(scan.errors), color="#dc2626"))

    html = templates.HTML_DOC.format(
        title=f"BAE Report {scan.scan_id}",
        brand=templates.BRAND["name"], tagline=templates.BRAND["tagline"],
        version=templates.BRAND["version"], accent=templates.BRAND["accent"],
        accent2=templates.BRAND["accent2"], ink=templates.BRAND["ink"],
        body="".join(body),
    )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return path


# ---------------------------------------------------------------------------
# XLSX
# ---------------------------------------------------------------------------
def export_xlsx(path: str, scan: ScanResult) -> str:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    wb = Workbook()
    summary = wb.active
    summary.title = "Summary"
    summary.append(["Browser Artifact Extractor - Collection Summary"])
    summary["A1"].font = Font(bold=True, size=14, color="FFFFFF")
    summary["A1"].fill = PatternFill("solid", fgColor="4F46E5")
    summary.append([])
    for k, v in {
        "Scan ID": scan.scan_id, "Host": scan.host, "Platform": scan.platform,
        "Operator": scan.operator, "Started": scan.started_at,
        "Finished": scan.finished_at,
        "Total records": scan.statistics.get("total_records", 0),
        "Manifest SHA-256": scan.integrity.get("manifest", {}).get("manifest_sha256", ""),
        "Audit chain valid": scan.integrity.get("audit_chain_valid"),
    }.items():
        summary.append([k, str(v)])
    summary.column_dimensions["A"].width = 26
    summary.column_dimensions["B"].width = 70

    for category, headers, rows in bundle(scan):
        ws = wb.create_sheet(category[:31])
        ws.append(headers)
        fill = PatternFill("solid", fgColor="4F46E5")
        for col in range(1, len(headers) + 1):
            cell = ws.cell(row=1, column=col)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = fill
            cell.alignment = Alignment(vertical="center")
        for row in rows:
            ws.append(["" if c is None else c for c in row])
        for idx, header in enumerate(headers, start=1):
            width = max(len(str(header)), 14)
            ws.column_dimensions[get_column_letter(idx)].width = min(width + 4, 60)
        ws.freeze_panes = "A2"
        ws.auto_filter.ref = ws.dimensions

    wb.save(path)
    return path


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------
def export_pdf(path: str, scan: ScanResult) -> str:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (PageBreak, Paragraph, SimpleDocTemplate,
                                    Spacer, Table, TableStyle)

    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    doc = SimpleDocTemplate(path, pagesize=landscape(A4),
                            leftMargin=12 * mm, rightMargin=12 * mm,
                            topMargin=12 * mm, bottomMargin=12 * mm,
                            title=f"BAE Report {scan.scan_id}")
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], textColor=colors.HexColor("#4f46e5"))
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], textColor=colors.HexColor("#0f172a"))
    small = ParagraphStyle("small", parent=styles["BodyText"], fontSize=8, leading=10)
    story = [Paragraph("Browser Artifact Extractor", h1),
             Paragraph(f"Forensic collection report &middot; {scan.scan_id}", small),
             Spacer(1, 8)]

    meta = [["Host", scan.host, "Operator", scan.operator or "-"],
            ["Platform", scan.platform, "Case ref", scan.case_ref or "-"],
            ["Started", scan.started_at, "Finished", scan.finished_at],
            ["Total records", str(scan.statistics.get("total_records", 0)),
             "Audit chain", "VALID" if scan.integrity.get("audit_chain_valid") else "CHECK"],
            ["Manifest SHA-256",
             scan.integrity.get("manifest", {}).get("manifest_sha256", ""), "", ""]]
    mt = Table(meta, colWidths=[70, 300, 70, 220])
    mt.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef2ff")),
        ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#eef2ff")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story += [mt, Spacer(1, 12)]

    for category, headers, rows in bundle(scan):
        story.append(Paragraph(_TITLES.get(category, category.title()) +
                               f" &nbsp;<font size=9 color='#64748b'>({len(rows):,})</font>", h2))
        data = [[Paragraph(f"<b>{h}</b>", small) for h in headers]]
        for row in rows[:800]:
            data.append([Paragraph("" if c is None else str(c)[:180], small) for c in row])
        if len(rows) > 800:
            story.append(Paragraph(f"Table truncated to 800 of {len(rows):,} rows for print.", small))
        widths = [min(64 * mm, 380 * mm / max(len(headers), 1))] * len(headers)
        tbl = Table(data, colWidths=widths, repeatRows=1)
        tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4f46e5")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ]))
        story += [tbl, PageBreak()]

    # Compliance page
    story.append(Paragraph("Compliance Control Mapping", h2))
    controls = scan.integrity.get("compliance", {}).get("controls", [])
    cdata = [["Framework", "Control", "Title", "Implemented in"]]
    cdata += [[c["framework"], c["control"], c["title"], c["module"]] for c in controls]
    ct = Table([[Paragraph(str(c), small) for c in row] for row in cdata],
               colWidths=[90, 70, 240, 260], repeatRows=1)
    ct.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#7c3aed")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f3ff")]),
    ]))
    story.append(ct)

    doc.build(story)
    return path


# ---------------------------------------------------------------------------
# Markdown / audit log
# ---------------------------------------------------------------------------
def export_markdown(path: str, scan: ScanResult) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    lines = [f"# Browser Artifact Extractor - {scan.scan_id}", ""]
    lines.append(f"- **Host:** {scan.host}")
    lines.append(f"- **Platform:** {scan.platform}")
    lines.append(f"- **Operator:** {scan.operator or '-'}")
    lines.append(f"- **Started:** {scan.started_at}")
    lines.append(f"- **Finished:** {scan.finished_at}")
    lines.append(f"- **Total records:** {scan.statistics.get('total_records', 0):,}")
    lines.append(f"- **Manifest SHA-256:** `{scan.integrity.get('manifest', {}).get('manifest_sha256', '')}`")
    lines.append("")
    for category, headers, rows in bundle(scan):
        lines.append(f"## {_TITLES.get(category, category.title())} ({len(rows):,})")
        lines.append("")
        lines.append("| " + " | ".join(headers) + " |")
        lines.append("|" + "---|" * len(headers))
        for row in rows[:200]:
            cells = [str(c).replace("|", "\\|") if c is not None else "" for c in row]
            lines.append("| " + " | ".join(cells) + " |")
        lines.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path


def export_audit_log(path: str, entries: List[Dict]) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for record in entries:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
    return path


def export_manifest(path: str, scan: ScanResult) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(scan.integrity, fh, indent=2, default=str)
    return path


# ---------------------------------------------------------------------------
# Registry / orchestration
# ---------------------------------------------------------------------------
EXPORTERS = {
    ".html": export_html,
    ".json": export_json,
    ".xml": export_xml,
    ".xlsx": export_xlsx,
    ".pdf": export_pdf,
    ".md": export_markdown,
}


def export_single(path: str, scan: ScanResult) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".csv":
        folder = os.path.splitext(path)[0] + "_csv"
        export_csv(folder, scan)
        return folder
    fn = EXPORTERS.get(ext)
    if not fn:
        raise ValueError(f"Unsupported format: {ext}")
    return fn(path, scan)


def export_all(out_dir: str, scan: ScanResult,
               formats: Optional[List[str]] = None) -> Dict[str, str]:
    """Write every report artefact into *out_dir* and return a path map."""
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    result: Dict[str, str] = {}

    formats = formats or [".html", ".json", ".xml", ".xlsx", ".pdf", ".md", ".csv"]
    for ext in formats:
        try:
            target = os.path.join(out_dir, f"report_{stamp}{ext}")
            if ext == ".csv":
                folder = os.path.join(out_dir, f"csv_{stamp}")
                export_csv(folder, scan)
                result["csv"] = folder
            else:
                fn = EXPORTERS[ext]
                fn(target, scan)
                result[ext.lstrip(".")] = target
        except ImportError as exc:
            result[ext.lstrip(".") + "_error"] = f"missing dependency: {exc}"
        except Exception as exc:  # noqa: BLE001
            result[ext.lstrip(".") + "_error"] = str(exc)

    result["manifest"] = export_manifest(os.path.join(out_dir, f"evidence_manifest_{stamp}.json"), scan)
    return result
