"""Reporting: findings export (json/html/csv/xlsx) + diff store wiring.

Repo constraint: stdlib only — the xlsx exporter writes a minimal but valid
Office Open XML workbook via zipfile, so no third-party dependency is needed.
"""
from __future__ import annotations

import csv as _csv
import json
import zipfile
from pathlib import Path
from typing import List
from xml.sax.saxutils import escape as _xml_escape


def remediation_suggestion(finding: dict) -> str:
    kind = finding.get("kind")
    rid = finding.get("rule_id", "?")
    if kind == "broad_exposure":
        return f"Constrict {rid}: replace src any with specific CIDR; restrict DB port to 10.0.0.0/16"
    if kind == "shadowed":
        return f"Reorder or delete {rid} (earlier rule {finding.get('earlier_id','?')} wins)"
    if kind == "redundant":
        return f"Delete duplicate rule {rid} (twin {finding.get('twin_id','?')})"
    if kind == "default_policy":
        return "Add explicit deny-any/deny-all-inbound rule to eliminate default-allow"
    if kind == "any_any":
        return f"Replace any->any {rid} with scoped source/dest"
    if kind == "logging_disabled":
        return f"Enable logging on {rid}"
    return "Review manually"


def write_report(findings: List[dict], out_dir: Path, snap: str) -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"findings-{snap}.json"
    payload = {
        "snapshot": snap,
        "findings": [
            {**f, "remediation": remediation_suggestion(f)} for f in findings
        ],
        "device_summary": {},
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


REPORT_COLUMNS = ["severity", "kind", "rule_id", "device", "evidence", "remediation"]
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _finding_row(f: dict) -> tuple:
    return (
        f.get("severity", ""),
        f.get("kind", ""),
        f.get("rule_id", ""),
        f.get("device", ""),
        f.get("evidence", ""),
        f.get("remediation", ""),
    )


def _sort_findings(findings: List[dict]) -> List[dict]:
    return sorted(
        findings,
        key=lambda f: (_SEVERITY_ORDER.get(f.get("severity", "low"), 9), f.get("kind", "")),
    )


def _severity_color(sev: str) -> str:
    return {
        "critical": "#e74c3c",
        "high": "#f39c12",
        "medium": "#f1c40f",
        "low": "#2ecc71",
    }.get(sev, "#95a5a6")


def write_report_csv(findings: List[dict], path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = _csv.writer(fh)
        writer.writerow(REPORT_COLUMNS)
        for f in _sort_findings(findings):
            writer.writerow(_finding_row(f))
    return path


def write_report_html(findings: List[dict], out_dir: Path, snap: str,
                      summary: dict) -> Path:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"findings-{snap}.html"
    rows = []
    for f in _sort_findings(findings):
        sev = f.get("severity", "")
        rows.append(
            f"<tr class=\"{_xml_escape(sev)}\">"
            f"<td><span class=\"pill\">{_xml_escape(sev)}</span></td>"
            f"<td>{_xml_escape(f.get('kind', ''))}</td>"
            f"<td>{_xml_escape(f.get('rule_id', ''))}</td>"
            f"<td>{_xml_escape(f.get('device', ''))}</td>"
            f"<td>{_xml_escape(f.get('evidence', ''))}</td>"
            f"<td>{_xml_escape(f.get('remediation', ''))}</td></tr>"
        )
    summary_html = ""
    if summary:
        items = " ".join(
            f"<span class=\"stat\">{_xml_escape(str(k))}: <b>{_xml_escape(str(v))}</b></span>"
            for k, v in summary.items() if k == "score" or k in ("critical", "high", "medium", "low", "count")
        )
        summary_html = f"<div class=\"summary\">{items}</div>"
    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Firewall Rule Audit — {_xml_escape(snap)}</title>
<style>
  body {{ font-family: "Segoe UI", Arial, sans-serif; margin: 24px; color: #222; }}
  h1 {{ font-size: 20px; }}
  .summary {{ margin: 12px 0 16px; }}
  .stat {{ background: #ecf0f1; border-radius: 4px; padding: 6px 10px; margin-right: 8px; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #dfe6e9; padding: 8px 10px; font-size: 13px;
          text-align: left; vertical-align: top; }}
  th {{ background: #2c3e50; color: #fff; }}
  tr.critical td {{ background: #ffeceb; }}
  tr.high td {{ background: #fff4e0; }}
  tr.medium td {{ background: #fef9e0; }}
  tr.low td {{ background: #ecfdf3; }}
  .pill {{ display: inline-block; border-radius: 10px; padding: 2px 10px;
          color: #fff; font-size: 12px; font-weight: 600; }}
  tr.critical .pill {{ background: #e74c3c; }}
  tr.high .pill {{ background: #f39c12; }}
  tr.medium .pill {{ background: #f1c40f; color: #333; }}
  tr.low .pill {{ background: #2ecc71; }}
</style>
</head>
<body>
<h1>Firewall Rule Audit — snapshot {_xml_escape(snap)}</h1>
{summary_html}
<table>
<thead><tr><th>Severity</th><th>Finding</th><th>Rule ID</th><th>Device</th>
<th>Evidence</th><th>Remediation</th></tr></thead>
<tbody>
{chr(10).join(rows)}
</tbody>
</table>
</body>
</html>
"""
    path.write_text(doc, encoding="utf-8")
    return path


_XLSX_HEADER = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">\n'
    '<sheetData>'
)
_XLSX_FOOTER = "</sheetData></worksheet>"


def _xlsx_escape(value) -> str:
    return _xml_escape(str(value), entities={"\"": "&quot;"})


def _xlsx_row(cells) -> str:
    inner = "".join(
        f'<c t="inlineStr"><is><t xml:space="preserve">{_xlsx_escape(v)}</t></is></c>'
        for v in cells
    )
    return f"<row>{inner}</row>"


def write_report_xlsx(findings: List[dict], path: Path) -> Path:
    """Minimal valid .xlsx (Office Open XML) using only the standard library."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    def sheet_xml() -> str:
        rows = [_xlsx_row(REPORT_COLUMNS)]
        rows.extend(_xlsx_row(_finding_row(f)) for f in _sort_findings(findings))
        return _XLSX_HEADER + "".join(rows) + _XLSX_FOOTER

    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        '</Types>'
    )
    rels_root = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        '</Relationships>'
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets><sheet name="Findings" sheetId="1" r:id="rId1"/></sheets>'
        '</workbook>'
    )
    workbook_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
        '</Relationships>'
    )
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels_root)
        zf.writestr("xl/workbook.xml", workbook)
        zf.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        zf.writestr("xl/worksheets/sheet1.xml", sheet_xml())
    return path


FORMAT_WRITERS = {
    "json": lambda findings, out_dir, snap, summary: write_report(findings, out_dir, snap),
    "csv": lambda findings, out_dir, snap, summary: write_report_csv(
        findings, Path(out_dir) / f"findings-{snap}.csv"),
    "html": lambda findings, out_dir, snap, summary: write_report_html(
        findings, out_dir, snap, summary),
    "xlsx": lambda findings, out_dir, snap, summary: write_report_xlsx(
        findings, Path(out_dir) / f"findings-{snap}.xlsx"),
}

VALID_FORMATS = tuple(FORMAT_WRITERS)


def write_reports(findings: List[dict], out_dir: Path, snap: str,
                  formats=(VALID_FORMATS), summary: dict = None) -> List[Path]:
    """Writes each requested format, returns the written file paths."""
    written = []
    for fmt in formats:
        if fmt not in FORMAT_WRITERS:
            continue
        written.append(FORMAT_WRITERS[fmt](findings, out_dir, snap, summary or {}))
    return written


def diff(a: List[dict], b: List[dict]) -> dict:
    """Simple additive/removal diff on rule ids."""
    ids_a = {r.get("rule_id") for r in a}
    ids_b = {r.get("rule_id") for r in b}
    return {"added": sorted(ids_b - ids_a), "removed": sorted(ids_a - ids_b)}