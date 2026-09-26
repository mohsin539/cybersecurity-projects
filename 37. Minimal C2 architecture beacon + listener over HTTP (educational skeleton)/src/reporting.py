"""Reporting engine - exports operational + audit data to .xlsx, .csv and .html.

Formats (per user requirement):
- .xlsx  : openpyxl workbook with branded colored sheets
- .csv   : plain delimited data (beacons / events / tasks)
- .html  : self-contained colorful HTML dashboard with inline CSS

Reports feed audit & compliance review (ISO 27001 A.12.7, NIST AU-6).
"""
import csv
import json
import os
from datetime import datetime
from typing import Iterable

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

# ---- color palette (brand) -------------------------------------------------
BRAND = {
    "bg": "1E1E2E",
    "panel": "2A2A40",
    "accent": "7C4DFF",
    "green": "27AE60",
    "amber": "F39C12",
    "red": "E74C3C",
    "blue": "2E86DE",
    "text": "ECEFF4",
}

TASK_HEADERS = ["task_id", "beacon_id", "name", "status", "queued_at", "dispatched_at", "completed_at", "output"]
EVENT_HEADERS = ["ts", "event", "actor", "subject", "severity", "detail"]
BEACON_HEADERS = ["beacon_id", "first_seen", "last_seen", "ip", "online", "hostname", "system", "os"]


# ---- helpers ---------------------------------------------------------------
def _flat(src: dict) -> dict:
    out = {}
    for k, v in src.items():
        if isinstance(v, dict):
            for kk, vv in v.items():
                out[f"{k}.{kk}"] = vv
        else:
            out[k] = v
    return out


def _sev_style(severity: str):
    s = (severity or "info").lower()
    if s == "error" or s == "critical":
        return BRAND["red"], "danger"
    if s == "warn":
        return BRAND["amber"], "warn"
    return BRAND["green"], "info"


def _write_rows(path: str, headers: list[str], rows: Iterable[dict]):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    return path


# ---- CSV -------------------------------------------------------------------
def export_csv(beacons, events, tasks, out_dir: str) -> list[str]:
    written = [
        _write_rows(os.path.join(out_dir, "beacons.csv"), BEACON_HEADERS, stream_beacons(beacons)),
        _write_rows(os.path.join(out_dir, "events.csv"), EVENT_HEADERS, stream_events(events)),
        _write_rows(os.path.join(out_dir, "tasks.csv"), TASK_HEADERS, stream_tasks(tasks)),
    ]
    return written


def stream_beacons(beacons):
    for b in beacons:
        m = _flat(b.get("meta") or {})
        yield {
            "beacon_id": b.get("beacon_id"),
            "first_seen": b.get("first_seen"),
            "last_seen": b.get("last_seen"),
            "ip": b.get("ip"),
            "online": b.get("online"),
            "hostname": m.get("hostname"),
            "system": m.get("system"),
            "os": m.get("os"),
        }


def stream_events(events):
    for e in events:
        yield {h: e.get(h) if h != "detail" else json.dumps(e.get("detail") or {}, default=str) for h in EVENT_HEADERS}


def stream_tasks(tasks):
    for t in tasks:
        yield {h: t.get(h) if h != "output" else json.dumps(t.get("output") or {}, default=str) for h in TASK_HEADERS}


# ---- XLSX ------------------------------------------------------------------
def _style_sheet(ws, headers, rows, title_color=BRAND["accent"]):
    ws.append(headers)
    for cell in ws[1]:
        cell.font = Font(bold=True, color="FFFFFF", size=11)
        cell.fill = PatternFill("solid", fgColor=title_color)
        cell.alignment = Alignment(vertical="center")
    widths = [min(38, max(12, len(str(h)) + 4)) for h in headers]
    for r_idx, row in enumerate(rows, start=2):
        ws.append([row.get(h, "") for h in headers])
        for c_idx in range(len(headers)):
            cell = ws.cell(row=r_idx, column=c_idx + 1)
            cell.alignment = Alignment(vertical="top")
            if headers[c_idx] == "severity":
                color, _ = _sev_style(row.get("severity"))
                cell.font = Font(color=color, bold=True)
    for i, w in enumerate(widths, start=1):
        ws.column_dimensions[get_column_letter(i)].width = min(60, max(w, 12))
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions


def export_xlsx(beacons, events, tasks, out_dir: str) -> str:
    wb = Workbook()
    path = os.path.join(out_dir, "C2StudyLab_report.xlsx")

    ws = wb.active
    ws.title = "Summary"
    ws.append(["C2 Study Lab - Operational Report"])
    ws["A1"].font = Font(bold=True, size=16, color=BRAND["accent"])
    ws.append(["Generated", datetime.now().isoformat()])
    ws.append(["Beacons observed", len(beacons)])
    ws.append(["Task events", len(tasks)])
    ws.append(["Audit events", len(events)])
    ws.append([])
    ws.append(["Compliance scope", "ISO 27001:2022 Annex A, NIST CSF/SP 800-53, OWASP Top 10 (2021)"])
    ws.column_dimensions["A"].width = 26
    ws.column_dimensions["B"].width = 70

    ws_b = wb.create_sheet("Beacons")
    _style_sheet(ws_b, BEACON_HEADERS, list(stream_beacons(beacons)), BRAND["blue"])

    ws_t = wb.create_sheet("Tasks")
    _style_sheet(ws_t, TASK_HEADERS, list(stream_tasks(tasks)), BRAND["green"])

    ws_e = wb.create_sheet("Audit Events")
    _style_sheet(ws_e, EVENT_HEADERS, list(stream_events(events)), BRAND["amber"])

    wb.save(path)
    return path


# ---- HTML ------------------------------------------------------------------
_HTML_TMPL = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{APP} - Compliance Report</title>
<style>
:root {{
  --bg:#1E1E2E; --panel:#28283f; --accent:#7C4DFF; --green:#27AE60;
  --amber:#F39C12; --red:#E74C3C; --blue:#2E86DE; --text:#ECEFF4; --muted:#9aa0b5;
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; font-family:'Segoe UI',system-ui,sans-serif; background:var(--bg); color:var(--text); }}
header {{ padding:28px 40px; background:linear-gradient(90deg,#14141f,#241f45 55%,#1d3350);
  border-bottom:3px solid var(--accent); }}
header h1 {{ margin:0; font-size:26px; letter-spacing:.5px; }}
header p {{ margin:4px 0 0; color:var(--muted); font-size:13px; }}
main {{ padding:24px 40px 60px; display:grid; gap:22px; }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:14px; }}
.card {{ background:var(--panel); border:1px solid #3a3a55; border-radius:12px; padding:16px 18px; }}
.card b {{ display:block; font-size:26px; }}
.card span {{ color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:1px; }}
table {{ width:100%; border-collapse:collapse; background:var(--panel); border-radius:12px; overflow:hidden; }}
caption {{ text-align:left; font-weight:700; padding:12px 14px; color:var(--accent); font-size:15px; }}
th {{ background:#34345a; color:#fff; text-align:left; padding:9px 12px; font-size:12px; }}
td {{ padding:8px 12px; border-top:1px solid #343446; font-size:12px; vertical-align:top; word-break:break-word; }}
tr:hover td {{ background:#30304a; }}
.badge {{ display:inline-block; padding:2px 10px; border-radius:20px; font-size:11px; font-weight:700; }}
.b-info  {{ background:#243b52; color:#6fc3ff; }}
.b-warn  {{ background:#4a3a20; color:#ffc46b; }}
.b-danger{{ background:#4a2125; color:#ff8a93; }}
.b-ok    {{ background:#1e4030; color:#67e08f; }}
.b-failed{{ background:#4a2125; color:#ff8a93; }}
.b-pending {{ background:#3a3549; color:#c9b8ff; }}
footer {{ padding:18px 40px; color:var(--muted); font-size:11px; border-top:1px solid #343446; }}
</style>
</head>
<body>
<header>
  <h1>&#x1F512; {APP} &middot; Compliance Report</h1>
  <p>{TAGLINE} &nbsp;|&nbsp; Generated {STAMP}</p>
</header>
<main>
  <div class="cards">
    <div class="card"><b>{BEACONS}</b><span>Beacons</span></div>
    <div class="card"><b>{TASKS}</b><span>Tasks</span></div>
    <div class="card"><b>{EVENTS}</b><span>Audit events</span></div>
    <div class="card" style="border-color:var(--green)"><b>&#10003;</b><span>ISO 27001 / NIST / OWASP tracked</span></div>
  </div>
  {BODY}
</main>
<footer>Generated by {APP} {VERSION} - authorized, educational use only.</footer>
</body>
</html>
"""

_SECTION = """
<section>
  <table>
    <caption>{TITLE}</caption>
    <thead><tr>{HEAD}</tr></thead>
    <tbody>{ROWS}</tbody>
  </table>
</section>
"""


def _html_cell(value) -> str:
    s = "" if value is None else str(value)
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return s


def _html_badge(status: str) -> str:
    key = (status or "info").lower()
    mapping = {"ok": "ok", "done": "ok", "dispatched": "info", "pending": "pending",
               "failed": "failed", "error": "danger", "critical": "danger",
               "warn": "warn", "warning": "warn"}
    cls = mapping.get(key, "info")
    return f'<span class="badge b-{cls}">{_html_cell(status)}</span>'


def export_html(beacons, events, tasks, out_dir: str) -> str:
    sections = []

    # beacons table
    head = "".join(f"<th>{h}</th>" for h in ["Beacon ID", "Hostname", "OS", "IP", "First Seen", "Last Seen", "Status"])
    rows = []
    for b in beacons:
        m = _flat(b.get("meta") or {})
        rows.append("<tr>" + "".join(
            _table_td(*[
                b.get("beacon_id"), m.get("hostname"), m.get("os") or b.get("system"),
                b.get("ip"), b.get("first_seen"), b.get("last_seen"),
                _html_badge("Online" if b.get("online") else "Offline"),
            ])) + "</tr>")
    sections.append(_SECTION.format(TITLE="&#128225; Beacon Inventory", HEAD=head, ROWS="".join(rows)))

    # tasks table
    head = "".join(f"<th>{h}</th>" for h in ["Task ID", "Beacon", "Name", "Status", "Queued", "Output"])
    rows = []
    for t in tasks:
        output = json.dumps(t.get("output") or {}, default=str)
        rows.append("<tr>" + "".join(
            _table_td(t.get("task_id"), t.get("beacon_id"), t.get("name"),
                      _html_badge(t.get("status")), t.get("queued_at"), _html_cell(output if len(output) < 160 else output[:160] + "…"))
        ) + "</tr>")
    sections.append(_SECTION.format(TITLE="&#128203; Task Register", HEAD=head, ROWS="".join(rows)))

    # audit events
    head = "".join(f"<th>{h}</th>" for h in ["Timestamp", "Event", "Actor", "Subject", "Severity", "Detail"])
    rows = []
    for e in events[-300:]:
        detail = json.dumps(e.get("detail") or {}, default=str)
        rows.append("<tr>" + "".join(
            _table_td(e.get("ts"), e.get("event"), e.get("actor"), e.get("subject"),
                      _html_badge(e.get("severity")), _html_cell(detail if len(detail) < 140 else detail[:140] + "…"))
        ) + "</tr>")
    sections.append(_SECTION.format(TITLE="&#128276; Audit Events (last 300)", HEAD=head, ROWS="".join(rows)))

    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "C2StudyLab_report.html")
    html = _HTML_TMPL.format(
        APP="C2 Study Lab",
        TAGLINE="Minimal C2 beacon + listener over HTTP (educational skeleton)",
        STAMP=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        BEACONS=len(beacons), TASKS=len(tasks), EVENTS=len(events),
        VERSION="1.0.0",
        BODY="\n".join(sections),
    )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return path


def _table_td(*cells) -> str:
    return "".join(f"<td>{c}</td>" for c in cells)


def export_all(beacons, events, tasks, out_dir: str) -> dict[str, str]:
    csv_files = export_csv(beacons, events, tasks, out_dir)
    xlsx = export_xlsx(beacons, events, tasks, out_dir)
    html = export_html(beacons, events, tasks, out_dir)
    return {"csv": csv_files, "xlsx": xlsx, "html": html}