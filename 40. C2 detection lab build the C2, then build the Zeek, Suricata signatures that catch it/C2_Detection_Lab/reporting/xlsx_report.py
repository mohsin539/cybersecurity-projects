""".XLSX workbook export - architecture section 6 sheet layout.

Sheets: 1 Lab Run Summary | 2 Detections | 3 IOCs | 4 Compliance Matrix |
5 Evidence. Uses openpyxl with native charts (alert timeline + precision curve).
"""

from __future__ import annotations

from pathlib import Path

from core.compliance import COMPLIANCE_MATRIX
from openpyxl import Workbook
from openpyxl.chart import BarChart, Reference
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

HEAD_FILL = PatternFill("solid", fgColor="1F2437")
HEAD_FONT = Font(color="7DF9FF", bold=True)
ZEBRA = PatternFill("solid", fgColor="0D1330")
ACCENT = Font(color="22D3A8", bold=True)


def _sheet(wb: Workbook, title: str) -> object:
    ws = wb.create_sheet(title)
    ws.sheet_view.showGridLines = False
    return ws


def _write_grid(ws, headers: list[str], rows: list[list], widths: list[int] | None = None):
    ws.append(headers)
    for cell, _ in zip(ws[1], headers):
        cell.fill = HEAD_FILL
        cell.font = HEAD_FONT
        cell.alignment = Alignment(vertical="center")
    for r in rows:
        ws.append(r)
    for i, row in enumerate(ws.iter_rows(min_row=2), start=2):
        if i % 2 == 0:
            for c in row:
                c.fill = ZEBRA
        for c in row:
            c.alignment = Alignment(vertical="top", wrap_text=True)
    if widths:
        for idx, w in enumerate(widths, start=1):
            ws.column_dimensions[get_column_letter(idx)].width = w


def write_xlsx(run_result: dict, path: str | Path) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    metrics = run_result["metrics"]
    alerts = run_result["alerts"]
    cfg = run_result["config"]

    wb = Workbook()
    wb.remove(wb.active)

    # ---- 1 · Summary -------------------------------------------------- #
    ws = _sheet(wb, "1 · Lab Run Summary")
    summary_rows = [
        ["Run ID", run_result["run_id"]],
        ["Generated (UTC)", __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime())],
        ["Beacon interval (s)", cfg["beacon_interval"]],
        ["Jitter (%)", cfg["jitter_pct"]],
        ["Channel", cfg["channel"]],
        ["Agents", cfg["agent_count"]],
        ["C2 port (ephemeral)", cfg["server_port"]],
        ["Total events", metrics["total_events"]],
        ["C2 beacon events", metrics["c2_events"]],
        ["Benign events", metrics["benign_events"]],
        ["True positives", metrics["true_positives"]],
        ["False positives", metrics["false_positives"]],
        ["False negatives", metrics["false_negatives"]],
        ["Precision", metrics["precision"]],
        ["Recall", metrics["recall"]],
        ["F1-score", metrics["f1"]],
        ["Accuracy", metrics["accuracy"]],
        ["Alert latency (avg s)", metrics["avg_alert_latency_s"]],
    ]
    _write_grid(ws, ["KPI", "Value"], summary_rows, [28, 30])
    for r in ws.iter_rows(min_row=2):
        r[0].font = ACCENT

    # ---- 2 · Detections ----------------------------------------------- #
    ws = _sheet(wb, "2 · Detections")
    _write_grid(ws,
                ["TS (UTC)", "Detector", "Rule", "Score", "Severity", "SrcIP", "DstIP",
                 "Port", "Channel", "Agent", "MITRE", "True Positive"],
                [[a["ts_iso"], a["detector"], a["rule_id"], a["score"], a["severity"],
                  a["src_ip"], a["dst_ip"], a["dst_port"], a["channel"], a["agent_id"],
                  a["mitre_technique"], a["true_positive"]] for a in alerts],
                [22, 10, 34, 8, 10, 16, 16, 8, 10, 10, 14, 12])

    # ---- 3 · IOCs ------------------------------------------------------ #
    ws = _sheet(wb, "3 · IOCs")
    iocs = []
    for a in alerts:
        iocs.append([
            "IP: " + str(a["dst_ip"]), a["src_ip"], a["channel"], "",
            a["mitre_technique"], a["ts_iso"]])
    for a in alerts:
        if a.get("agent_id") is not None:
            iocs.append(["C2 agent id", f"agent-{a['agent_id']}", a["detector"], "",
                         "T1071.001", a["ts_iso"]])
            break
    _write_grid(ws, ["Type", "Value", "Source", "File Hash", "MITRE", "First Seen"],
                iocs, [16, 24, 14, 18, 14, 22])

    # ---- 4 · Compliance Matrix ---------------------------------------- #
    ws = _sheet(wb, "4 · Compliance Matrix")
    _write_grid(ws, ["Framework", "Control", "Topic", "Implemented By", "Status"],
                [[c["framework"], c["control"], c["topic"], c["artifact"], c["status"]]
                 for c in COMPLIANCE_MATRIX],
                [16, 14, 30, 46, 12])

    # ---- 5 · Evidence -------------------------------------------------- #
    ws = _sheet(wb, "5 · Evidence")
    ev_rows = []
    audit = run_result.get("evidence_entries") or []
    for ent in audit:
        ev_rows.append([ent.get("ts_iso"), ent.get("event"), ent.get("detail"),
                        ent.get("sha256", "-"), ent.get("control")])
    if not ev_rows:
        ev_rows = [["-", "no evidence captured", "", "", ""]]
    _write_grid(ws, ["TS (UTC)", "Event", "Detail", "SHA-256", "Control"], ev_rows,
                [22, 20, 34, 66, 22])

    # ---- charts --------------------------------------------------------- #
    ws = _sheet(wb, "Charts")
    chart = BarChart()
    chart.type = "bar"
    chart.title = "Detector hits (Zeek vs Suricata)"
    refs = Reference(ws, min_col=2, min_row=1, max_row=1)
    ws["A1"] = "Detector"
    ws["B1"] = "Hits"
    ws["A2"] = "Zeek"; ws["B2"] = metrics["zeek_detections"]
    ws["A3"] = "Suricata"; ws["B3"] = metrics["suricata_detections"]
    data = Reference(ws, min_col=2, min_row=1, max_row=3)
    cats = Reference(ws, min_col=1, min_row=2, max_row=3)
    chart.add_data(data, titles_from_data=True)
    chart.set_categories(cats)
    ws.add_chart(chart, "D2")

    out.parent.mkdir(parents=True, exist_ok=True)
    wb.save(out)
    return out