#!/usr/bin/env python3
"""Report & export engine - industry-standard download formats.

Produces:
  * evidence_manifest.json  - canonical machine-readable evidence pack
  * hash_manifest.csv       - tabular hash manifest
  * hash_manifest.xlsx      - styled spreadsheet manifest (openpyxl)
  * SHA256SUMS              - POSIX-style digest file (dd/FTK compatible)
  * forensic_report.pdf     - signed court-style PDF report (reportlab)
  * chain_of_custody_report.pdf - custody timeline visual report
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import platform
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .config import (APP_NAME, APP_SHORT, AUTHORITATIVE, CUSTODY_PDF_NAME,
                     EXPORT_CSV_NAME, EXPORT_XLSX_NAME, ISO_REFS,
                     MANIFEST_NAME, ORG_DEFAULT, REPORT_PDF_NAME,
                     SHA256SUMS_NAME, VERSION)
from .imaging import fmt_size

ACCENT = "#1f6feb"
DARK = "#0d1117"
TEXTCOL = "#1f2430"
BADGE = "#238636"
WARN = "#9e6a03"


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _argb(hex6: str) -> str:
    """Convert '#rrggbb' to openpyxl 8-digit aRGB."""
    return "FF" + hex6.lstrip("#").upper()


# --------------------------------------------------------------------------
def write_json(path: str, payload: Dict[str, Any]) -> str:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)
    return os.path.basename(path)


def write_csv(path: str, rows: List[Dict[str, Any]]) -> str:
    fields = ["exhibit", "algorithm", "digest", "size_bytes", "source",
              "acquired_utc", "case_id", "tool", "tool_version"]
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return os.path.basename(path)


def write_xlsx(path: str, manifest: Dict[str, Any]) -> str:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    wb = Workbook()
    ws = wb.active
    ws.title = "Evidence Summary"
    ws.sheet_view.showGridLines = False

    header_fill = PatternFill("solid", fgColor=_argb(ACCENT))
    header_font = Font(color="FFFFFFFF", bold=True, size=11)
    title_font = Font(size=14, bold=True, color=_argb(DARK))
    badge_fill = PatternFill("solid", fgColor=_argb(BADGE))

    ws["A1"] = f"{APP_NAME} - Evidence & Hash Manifest"
    ws["A1"].font = title_font
    ws["A2"] = f"Case: {manifest['case_id']} | {manifest['case_name']} | Generated: {manifest['generated_utc']} | Tool v{VERSION}"
    ws["A2"].font = Font(size=10, italic=True, color=_argb(TEXTCOL))

    meta = manifest["meta"]
    row = 4
    for k, v in meta.items():
        ws.cell(row, 1, k.replace("_", " ").title())
        ws.cell(row, 2, v)
        row += 1

    # Hash table
    row += 1
    hs = ws.cell(row, 1, "Hash Manifests")
    hs.font = Font(size=12, bold=True, color=_argb(ACCENT))
    row += 1
    headers = ["Exhibit", "Size", "Source", "Algorithm", "Digest"]
    for c, h in enumerate(headers, 1):
        cell = ws.cell(row, c, h)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(vertical="center")
    row += 1
    for item in manifest["evidence"]:
        for algo, dig in item["hashes"].items():
            ws.cell(row, 1, item["exhibit"])
            ws.cell(row, 2, item["size_display"])
            ws.cell(row, 3, item["source_device"])
            ws.cell(row, 4, algo)
            ws.cell(row, 5, dig)
            row += 1
        if item["hashes"]:
            ws.cell(row - len(item["hashes"]), 1).fill = PatternFill("solid", fgColor=_argb("#f6f8fa"))
    for c in range(1, 6):
        ws.column_dimensions[get_column_letter(c)].width = 46 if c == 5 else 2 + (24 if c else 20)
    ws.column_dimensions["A"].width = 22
    ws.column_dimensions["B"].width = 14
    ws.column_dimensions["C"].width = 28

    # CoC timeline sheet
    ws2 = wb.create_sheet("Chain of Custody")
    ws2.cell(1, 1, "Chain of Custody - Signed Timeline").font = Font(size=13, bold=True, color=_argb(ACCENT))
    h2 = ["Timestamp (UTC)", "Action", "Description", "Exhibit", "Actor"]
    for c, h in enumerate(h2, 1):
        cell = ws2.cell(3, c, h)
        cell.fill = header_fill
        cell.font = header_font
    for i, ev in enumerate(manifest["custody"], start=4):
        ws2.cell(i, 1, ev["ts"])
        ws2.cell(i, 2, ev["action"])
        ws2.cell(i, 3, ev["description"])
        ws2.cell(i, 4, ev.get("exhibit") or "-")
        ws2.cell(i, 5, ev["actor"])
    for c in range(1, 6):
        ws2.column_dimensions[get_column_letter(c)].width = 42 if c == 3 else 24
    wb.save(path)
    return os.path.basename(path)


# --------------------------------------------------------------------------
def write_sha256sums(path: str, entries: Dict[str, str]) -> str:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for name, digest in entries.items():
            fh.write(f"{digest}  {name}\n")
    return os.path.basename(path)


# --------------------------------------------------------------------------
def _report_styles():
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    return colors, ParagraphStyle, getSampleStyleSheet


def build_forensic_pdf(path: str, manifest: Dict[str, Any]) -> str:
    """Court-style signed forensic report (PDF)."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer,
                                    Table, TableStyle)

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Accent", parent=styles["Heading1"],
                              textColor=colors.HexColor(ACCENT)))
    styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"],
                              fontSize=8, textColor=colors.HexColor("#586069")))
    styles.add(ParagraphStyle(name="MonoHash", fontName="Courier", fontSize=8))

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#586069"))
        canvas.drawString(15 * mm, 12 * mm,
                          f"{APP_NAME} v{VERSION}  |  {manifest['case_id']}")
        canvas.drawRightString(A4[0] - 15 * mm, 12 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(path, pagesize=A4,
                            leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=18 * mm,
                            title=f"{APP_SHORT} Forensic Report",
                            author=manifest["meta"].get("examiner", ORG_DEFAULT),
                            subject=f"Case {manifest['case_id']}",
                            creator=f"{APP_NAME} v{VERSION}")
    story = []
    story.append(Paragraph(f"{APP_NAME}", styles["Title"]))
    story.append(Paragraph(f"Forensic Acquisition & Hash Verification Report",
                           styles["Accent"]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        f"Case <b>{manifest['case_id']}</b> — {manifest['case_name']}<br/>"
        f"Generated (UTC): <b>{manifest['generated_utc']}</b> &nbsp;·&nbsp; "
        f"Tool: <b>{APP_NAME} v{VERSION}</b>", styles["BodyText"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f"Frameworks applied: {ISO_REFS}", styles["Small"]))
    story.append(Spacer(1, 10))

    meta_rows = [[k.replace("_", " ").title(), v] for k, v in manifest["meta"].items()]
    t = Table([["Attribute", "Value"]] + meta_rows, colWidths=[46 * mm, 128 * mm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(ACCENT)),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fa")]),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]))
    story.append(t)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Acquired Evidence & Hashes", styles["Heading2"]))
    for item in manifest["evidence"]:
        story.append(Paragraph(
            f"Exhibit: <b>{item['exhibit']}</b> &nbsp;·&nbsp; "
            f"Source: <code>{item['source_device']}</code> &nbsp;·&nbsp; "
            f"Size: <b>{item['size_display']}</b> &nbsp;·&nbsp; "
            f"Bytes: {item['size_bytes']}", styles["BodyText"]))
        hash_rows = [["Algorithm", "Digest (hex)"]]
        for algo, dig in item["hashes"].items():
            hash_rows.append([algo, Paragraph(dig, styles["MonoHash"])])
        h = Table(hash_rows, colWidths=[40 * mm, 134 * mm])
        h.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(BADGE)),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f6f8fa")]),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
        ]))
        story.append(h)
        story.append(Spacer(1, 8))
        ver = item.get("verification")
        if ver and ver.get("algorithm"):
            ok = ver.get("match")
            label = "PASS - digests match" if ok else "FAIL - digest mismatch"
            story.append(Paragraph(
                f"Verification: <b>{'PASS' if ok else 'FAIL'}</b> "
                f"({ver['algorithm']} re-hash · {ver.get('timestamp', '-')})",
                styles["Small"]))
            story.append(Spacer(1, 4))

    story.append(Spacer(1, 8))
    story.append(Paragraph("Chain of Custody — Signed Timeline", styles["Heading2"]))
    coc_rows = [["Timestamp (UTC)", "Action", "Description", "Actor"]]
    for ev in manifest["custody"]:
        coc_rows.append([ev["ts"], ev["action"], ev["description"], ev["actor"]])
    ct = Table(coc_rows, colWidths=[40 * mm, 34 * mm, 70 * mm, 30 * mm])
    ct.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(ACCENT)),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(ct)
    story.append(Spacer(1, 14))

    story.append(Paragraph("Certification & Signature Block", styles["Heading2"]))
    sig_rows = [
        ["Role", "Name / Org", "Signature / Key Fingerprint", "Date (UTC)"],
        ["Examiner / Acquirer",
         f"{manifest['meta'].get('examiner','-')} · {manifest['meta'].get('organization','-')}",
         manifest["signatures"].get("manifest_fingerprint", "-")[:24] + "…",
         manifest["generated_utc"]],
        ["Tool",
         f"{APP_NAME} v{VERSION}",
         hashlib.sha256(json.dumps(manifest, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:24] + "…",
         manifest["generated_utc"]],
    ]
    st = Table(sig_rows, colWidths=[28 * mm, 48 * mm, 66 * mm, 32 * mm])
    st.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(BADGE)),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]))
    story.append(st)
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "This report is machine-generated. Evidence integrity is established by "
        "the hash manifests and the signed chain-of-custody ledger shipped with "
        "the case folder. For certified X.509/eIDAS signatures and RFC 3161 "
        "trusted timestamps, use the certified build of the toolkit.",
        styles["Small"]))
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return os.path.basename(path)