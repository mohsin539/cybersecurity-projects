import csv
import hashlib
import io
from datetime import date, datetime

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill
from openpyxl.utils import get_column_letter

from models import BlueDetection, Case, Control, Evidence, RedAttack, db

RED = "FF4D6D"
BLUE = "4361EE"
PURPLE = "7B2FF7"
GREEN = "2EC4B6"
DARK = "14142A"


def _normalize(case_id=None, kind=None):
    """Single shared schema used by every renderer so formats never disagree."""
    if case_id:
        case = Case.query.get_or_404(case_id)
        rows = []
        for a in case.attacks:
            det = BlueDetection.query.filter_by(red_attack_id=a.id).first()
            rows.append({
                "case": case.title, "tactic": a.technique.tactic,
                "technique_id": a.technique_id, "technique": a.technique.name,
                "payload": a.payload or "", "red_status": a.status,
                "blue_status": det.status if det else "no_feedback",
                "rule_ref": det.rule_ref if det else "",
                "analyst": det.analyst if det else "",
            })
        return {"kind": "case", "case": case, "rows": rows}
    return {"kind": kind, "rows": db.session.query(Control).all() if kind == "controls" else []}


def build_xlsx(case_id=None):
    """Multi-sheet Excel workbook: Summary, MITRE Mapping, Detection Gaps, Controls, Evidence."""
    data = _normalize(case_id=case_id)
    wb = Workbook()

    def style_header(ws, ncols, fill=PURPLE):
        for c in range(1, ncols + 1):
            cell = ws.cell(row=1, column=c)
            cell.font = Font(bold=True, color="FFFFFF")
            cell.fill = PatternFill("solid", fgColor=fill)
            cell.alignment = Alignment(horizontal="center", vertical="center")
        ws.freeze_panes = "A2"

    # Sheet 1: Executive Summary
    ws = wb.active
    ws.title = "Executive Summary"
    ws["A1"] = "PURPLE TEAM CAPSTONE — MITRE ATT&CK EVIDENCE REPORT"
    ws["A1"].font = Font(bold=True, size=16, color=PURPLE)
    ws["A2"] = f"Generated: {datetime.utcnow().isoformat()}  |  Case: {data['case'].title if data['case'] else 'All'}"
    summary = [
        ("Case", data["case"].title if data["case"] else "All cases"),
        ("Owner", data["case"].owner if data["case"] else "-"),
        ("Status", data["case"].status if data["case"] else "-"),
        ("Alignment Score", f"{data['case'].alignment_score}%" if data["case"] else "-"),
        ("Technique occurrences", len(data["rows"])),
        ("Frameworks tracked", "ISO 27001 | NIST CSF | OWASP Top 10"),
    ]
    for r, (k, v) in enumerate(summary, start=4):
        ws.cell(row=r, column=1, value=k).font = Font(bold=True)
        ws.cell(row=r, column=2, value=v)

    # Sheet 2: MITRE Mapping
    ws = wb.create_sheet("MITRE Mapping")
    headers = ["Case", "Tactic", "Technique ID", "Technique", "Payload",
               "Red Status", "Blue Status", "SIEM Rule", "Analyst"]
    ws.append(headers)
    style_header(ws, len(headers), BLUE)
    for r in data["rows"]:
        ws.append([r["case"], r["tactic"], r["technique_id"], r["technique"],
                   r["payload"], r["red_status"], r["blue_status"], r["rule_ref"], r["analyst"]])
    for col, w in zip("ABCDEFGHI", [22, 18, 14, 26, 30, 12, 14, 18, 14]):
        ws.column_dimensions[col].width = w

    # Sheet 3: Detection Gaps
    ws = wb.create_sheet("Detection Gaps")
    ws.append(["Technique ID", "Technique", "Tactic", "Verdict", "Notes"])
    style_header(ws, 5, RED)
    for r in data["rows"]:
        verdict = {"detected": "Covered", "partial": "Partial gap", "missed": "GAP", "no_feedback": "No feedback"}[r["blue_status"]]
        ws.append([r["technique_id"], r["technique"], r["tactic"], verdict, r["rule_ref"]])

    # Sheet 4: Compliance Posture
    ws = wb.create_sheet("Compliance Posture")
    ws.append(["Control", "Title", "ISO 27001", "NIST CSF", "OWASP", "Status"])
    style_header(ws, 6, GREEN)
    for c in Control.query.all():
        ws.append([c.code, c.title, c.iso_ref, c.nist_ref, c.owasp_ref, c.status])
    for col, w in zip("ABCDEF", [12, 30, 14, 12, 10, 14]):
        ws.column_dimensions[col].width = w

    # Sheet 5: Evidence Log
    ws = wb.create_sheet("Evidence Log")
    ws.append(["Attack", "Technique ID", "Kind", "Description", "File", "SHA256", "Captured"])
    style_header(ws, 7, PURPLE)
    if data["case"]:
        for a in data["case"].attacks:
            for ev in a.evidence:
                ws.append([a.title, a.technique_id, ev.kind, ev.description,
                           ev.file_ref, ev.sha256, ev.created_at.strftime("%Y-%m-%d %H:%M")])

    out = io.BytesIO()
    wb.save(out)
    out.seek(0)
    return out


def build_csv(kind="mapping", case_id=None):
    """CSV extracts per entity (RFC 4180, UTF-8 BOM for Excel)."""
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_ALL)
    if kind == "controls":
        w.writerow(["Control", "Title", "ISO 27001", "NIST CSF", "OWASP", "Status"])
        for c in Control.query.all():
            w.writerow([c.code, c.title, c.iso_ref, c.nist_ref, c.owasp_ref, c.status])
    else:
        data = _normalize(case_id=case_id)
        w.writerow(["Case", "Tactic", "Technique ID", "Technique", "Payload",
                    "Red Status", "Blue Status", "SIEM Rule", "Analyst"])
        for r in data["rows"]:
            w.writerow([r["case"], r["tactic"], r["technique_id"], r["technique"],
                        r["payload"], r["red_status"], r["blue_status"], r["rule_ref"], r["analyst"]])
    payload = "\ufeff" + buf.getvalue()
    return io.BytesIO(payload.encode("utf-8"))


def build_html(case_id):
    """Self-contained DOSS-style HTML report (used by the reports page and export)."""
    data = _normalize(case_id=case_id)
    case = data["case"]
    rows = data["rows"]
    controls = Control.query.all()

    def verdict_badge(status):
        return {"detected": '<span class="v g">DETECTED</span>',
                "partial": '<span class="v y">PARTIAL</span>',
                "missed": '<span class="v r">MISSED</span>',
                "no_feedback": '<span class="v n">NO FEEDBACK</span>'}.get(status, status)

    trs = "".join(
        f"<tr><td class='tid'>{r['technique_id']}</td><td>{r['technique']}</td>"
        f"<td>{r['tactic']}</td><td>{r['red_status']}</td><td>{verdict_badge(r['blue_status'])}</td>"
        f"<td>{r['analyst'] or '-'}</td></tr>" for r in rows)

    ctrs = "".join(
        f"<tr><td>{c.code}</td><td>{c.title}</td><td>{c.iso_ref}</td>"
        f"<td>{c.nist_ref}</td><td>{c.owasp_ref}</td><td>{c.status}</td></tr>" for c in controls)

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Purple Team Report — {case.title}</title>
<style>
  body{{font-family:'Segoe UI',sans-serif;background:#f4f3fb;color:#1c1c32;margin:0;padding:40px}}
  .cover{{background:linear-gradient(120deg,#ff4d6d,#7b2ff7 55%,#4361ee 100%);color:#fff;padding:48px;border-radius:18px}}
  h1{{margin:0 0 8px}} .muted{{opacity:.85}}
  .grid{{display:grid;gap:14px}} h2{{color:#7b2ff7}}
  .card{{background:#fff;border-radius:14px;padding:22px;box-shadow:0 6px 22px rgba(28,28,50,.08);margin-top:22px}}
  table{{width:100%;border-collapse:collapse;font-size:14px}}
  th{{background:#7b2ff7;color:#fff;text-align:left;padding:10px}}
  td{{border-bottom:1px solid #e4e2f2;padding:9px}}
  .tid{{font-family:Consolas,monospace;color:#7b2ff7;font-weight:700}}
  .v{{font-size:11px;font-weight:700;padding:3px 9px;border-radius:999px;color:#fff}}
  .g{{background:#2ec4b6}} .y{{background:#fb8500}} .r{{background:#ff4d6d}} .n{{background:#9aa0c7}}
  .toc a{{color:#4361ee}} footer{{margin-top:30px;color:#6b6b8f;font-size:13px;text-align:center}}
</style></head><body>
<div class="cover"><h1>Purple Team Capstone — Case Report</h1>
<p class="muted">{case.title} · Owner: {case.owner or 'N/A'} · Status: {case.status}</p>
<p class="muted">Alignment: <b>{case.alignment_score}%</b> · Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p></div>
<div class="card"><h2>Table of Contents</h2><div class="toc">
<a href="#map">1. MITRE ATT&amp;CK Mapping</a> · <a href="#gaps">2. Detection Gaps</a> · <a href="#controls">3. Compliance Posture</a></div></div>
<div class="card" id="map"><h2>1. MITRE ATT&amp;CK Mapping</h2>
<table><thead><tr><th>T-ID</th><th>Technique</th><th>Tactic</th><th>Red</th><th>Blue</th><th>Analyst</th></tr></thead><tbody>{trs}</tbody></table></div>
<div class="card" id="gaps"><h2>2. Detection Gap Summary</h2>
<p>{len(rows)} technique occurrences recorded; {sum(1 for r in rows if r['blue_status']=='missed')} fully missed.</p></div>
<div class="card" id="controls"><h2>3. Compliance Posture (ISO 27001 / NIST CSF / OWASP)</h2>
<table><thead><tr><th>Control</th><th>Title</th><th>ISO</th><th>NIST</th><th>OWASP</th><th>Status</th></tr></thead><tbody>{ctrs}</tbody></table></div>
<footer>Frameworks: ISO/IEC 27001:2022 · NIST CSF 2.0 · OWASP Top 10 · MITRE ATT&amp;CK is a registered trademark of MITRE</footer>
</body></html>"""
    return html.encode("utf-8")


def sign(payload) -> str:
    """Append a short integrity digest used by the audit trail (ISO A.5.28 / NIST DE)."""
    return hashlib.sha256(payload).hexdigest()[:16]