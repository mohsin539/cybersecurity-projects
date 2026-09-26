import csv
import hashlib
import html
import io
import os
import time
import uuid

import xlwt
from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from . import LAB_TAG, SITE, VERSION
from .engine import IDENTITIES, TECHNIQUES, TOPOLOGY
from .metrics import compute, coverage_matrix
from .rules import BUILTIN_RULES, expected_rule_ids

SEV_COLORS = {"critical": "C92A2A", "high": "E86A17", "medium": "E6B800", "low": "2E86DE"}
SEV_FILLS = {k: PatternFill("solid", fgColor=v) for k, v in SEV_COLORS.items()}
HEADER_FILL = PatternFill("solid", fgColor="16324F")
HEADER_FONT = Font(color="FFFFFF", bold=True)

COMPLIANCE_MAP = [
    ("ISO", "A.8.10", "Information deletion — one-command teardown of lab VMs", "engine.run_technique / lab teardown"),
    ("ISO", "A.8.16", "Monitoring activities — event log + network telemetry capture", "engine steps + detection pipeline"),
    ("ISO", "A.8.28", "Secure coding — parameterized SQL, escaped HTML", "store.py / report.py"),
    ("ISO", "A.9.1.2", "Access to networks — ATK01 allowed only in run window", "lab topology ACL"),
    ("ISO", "A.5.16/5.17", "Identity & access — MFA + least privilege on web console", "main.py auth"),
    ("NIST", "CSF ID.AM-06", "Inventory — lab asset + identity fabric", "engine.TOPOLOGY / IDENTITIES"),
    ("NIST", "CSF PR.AA-02", "Access — RBAC + session binding", "main.py auth"),
    ("NIST", "CSF DE.CM-07", "Monitoring — continuous telemetry capture", "telemetry collectors"),
    ("NIST", "CSF DE.AE-01", "Anomaly events — detection metrics vs ground truth", "metrics.compute"),
    ("NIST", "800-53 SC-7", "Boundary protection — no egress, host-only vNIC", "network segmentation"),
    ("NIST", "800-53 SI-4", "System monitoring — Zeek/Suricata + event logs", "NSM plane"),
    ("NIST", "800-53 AU-6", "Audit review — evidence ledger SHA-256", "report evidence"),
    ("OWASP", "A01", "Broken access control — RBAC + signed downloads", "main.py auth / report download"),
    ("OWASP", "A02", "Cryptographic failures — TLS, SHA-256 evidence", "report hashing"),
    ("OWASP", "A03", "Injection — parameterized SQL, escaped HTML output", "store / report"),
    ("OWASP", "A08", "Data integrity — report checksums", "report sha256"),
    ("OWASP", "A09", "Logging failures — audit ledger", "store.audit"),
    ("OWASP", "A10", "SSRF — no outbound fetch in web app", "no external URLs"),
]

COMPLIANCE_MISSING = "n/a"


def _hl(s):
    return html.escape(str(s), quote=True) if s is not None else ""


def _sha(data_bytes):
    return hashlib.sha256(data_bytes).hexdigest()


def build_meta(runs, detections):
    metrics = compute(runs, detections)
    cov = coverage_matrix(detections)
    return {
        "project": "LAMDEX",
        "version": VERSION,
        "site": SITE,
        "is_lab": LAB_TAG,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "runs": runs,
        "detections": detections,
        "metrics": metrics,
        "coverage": cov,
        "techniques": TECHNIQUES,
        "topology": TOPOLOGY,
        "identities": IDENTITIES,
        "rules": BUILTIN_RULES,
        "compliance": COMPLIANCE_MAP,
    }


def _xlsx_cell(ws, row, col, value, bold=False, fill=None, color=None):
    c = ws.cell(row=row, column=col, value=value)
    if bold:
        c.font = Font(bold=True)
    if fill:
        c.fill = fill
    if color == "white":
        c.font = Font(color="FFFFFF", bold=bold)
    return c


def _write_sheet_header(ws, headers):
    hashes = [0.12 + (len(h) * 0.028) for h in headers]
    for ci, h in enumerate(headers, start=1):
        _xlsx_cell(ws, 1, ci, h, bold=True, fill=HEADER_FILL, color="white")
        ws.column_dimensions[get_column_letter(ci)].width = hashes[ci - 1]
    ws.freeze_panes = "A2"


def export_xlsx(meta, out_path):
    wb = Workbook()
    ws = wb.active
    ws.title = "Run Summary"
    ws.append(["LAMDEX — Lateral Movement Detection Lab", "", "", "", ""])
    ws.append(["Version", meta["version"], "Site", meta["site"], "LAB tag", str(meta["is_lab"])])
    ws.append(["Generated", meta["generated_at"], "", "", "", ""])
    ws.append([])
    ws.append(["Runs", meta["metrics"]["totals"]["runs"], "Detections", meta["metrics"]["totals"]["detections"], "", ""])
    ws.append(["TP", meta["metrics"]["totals"]["tp"], "FP", meta["metrics"]["totals"]["fp"], "FN", meta["metrics"]["totals"]["fn"]])
    ws.append(["Precision", meta["metrics"]["totals"]["precision"], "Recall", meta["metrics"]["totals"]["recall"], "F1", meta["metrics"]["totals"]["f1"]])
    ws.append([])
    _write_sheet_header(ws, ["run_id", "technique", "source", "target", "records", "sha256"])
    for r in meta["runs"]:
        _xlsx_cell(ws, ws.max_row + 1, 1, r["run_id"])
        _xlsx_cell(ws, ws.max_row, 2, r["technique_id"] + " " + r["technique_name"])
        _xlsx_cell(ws, ws.max_row, 3, r["source"])
        _xlsx_cell(ws, ws.max_row, 4, r["target"])
        _xlsx_cell(ws, ws.max_row, 5, r["record_count"])
        _xlsx_cell(ws, ws.max_row, 6, r["sha256"])

    ws2 = wb.create_sheet("Detections")
    _write_sheet_header(ws2, ["detection_id", "run_id", "rule_id", "rule_name", "technique", "level", "confidence", "event_id", "data_source", "source", "target", "user", "ground_truth_match"])
    for d in meta["detections"]:
        row = [d["detection_id"], d["run_id"], d["rule_id"], d["rule_name"], d["technique_id"] or d["rule_technique"] or "-",
               d["level"], d["confidence"], d["event_id"] or "-", d["data_source"], d["src"], d["tgt"], d["usr"],
               str(bool(d["tp"]))]
        fill = SEV_FILLS.get(d["level"])
        _xlsx_cell(ws2, ws2.max_row + 1, 1, row[0])
        for ci, v in enumerate(row[1:], start=2):
            _xlsx_cell(ws2, ws2.max_row, ci, v)
        if fill:
            ws2.cell(row=ws2.max_row, column=6).fill = fill

    ws3 = wb.create_sheet("Techniques")
    _write_sheet_header(ws3, ["technique_id", "name", "tactic", "severity", "coverage", "expected_rules", "covered_rules", "status"])
    tech_by_id = {t["technique_id"]: t for t in meta["techniques"]}
    cov_by_id = {c["technique_id"]: c for c in meta["coverage"]}
    for t in meta["techniques"]:
        c = cov_by_id.get(t["technique_id"], {"expected": 0, "covered": 0})
        _xlsx_cell(ws3, ws3.max_row + 1, 1, t["technique_id"])
        _xlsx_cell(ws3, ws3.max_row, 2, t["name"])
        _xlsx_cell(ws3, ws3.max_row, 3, t["tactic"])
        _xlsx_cell(ws3, ws3.max_row, 4, t["severity"])
        _xlsx_cell(ws3, ws3.max_row, 5, "%s/%s" % (c["covered"], c["expected"]))
        _xlsx_cell(ws3, ws3.max_row, 6, c["expected"])
        _xlsx_cell(ws3, ws3.max_row, 7, c["covered"])
        _xlsx_cell(ws3, ws3.max_row, 8, "MVP" if t["coins"] == "mvp" else "Extended")

    ws4 = wb.create_sheet("Metrics")
    _write_sheet_header(ws4, ["technique_id", "expected", "coverage", "tp", "fp", "fn", "precision", "recall", "f1"])
    for m in meta["metrics"]["per_technique"]:
        _xlsx_cell(ws4, ws4.max_row + 1, 1, m["technique_id"])
        for ci, v in enumerate([m["expected"], m["covered"], m["tp"], m["fp"], m["fn"], m["precision"], m["recall"], m["f1"]], start=2):
            _xlsx_cell(ws4, ws4.max_row, ci, v)

    ws5 = wb.create_sheet("Compliance Matrix")
    _write_sheet_header(ws5, ["framework", "control", "description", "evidence"])
    for row in meta["compliance"]:
        _xlsx_cell(ws5, ws5.max_row + 1, 1, row[0])
        _xlsx_cell(ws5, ws5.max_row, 2, row[1])
        _xlsx_cell(ws5, ws5.max_row, 3, row[2])
        _xlsx_cell(ws5, ws5.max_row, 4, row[3])

    ws6 = wb.create_sheet("Evidence")
    _write_sheet_header(ws6, ["run_id", "tech", "artifact", "sha256"])
    for r in meta["runs"]:
        _xlsx_cell(ws6, ws6.max_row + 1, 1, r["run_id"])
        _xlsx_cell(ws6, ws6.max_row, 2, r["technique_id"])
        _xlsx_cell(ws6, ws6.max_row, 3, "runs/" + r["run_id"] + "/telemetry.json")
        _xlsx_cell(ws6, ws6.max_row, 4, r["sha256"])

    wb.save(out_path)
    return out_path


def export_xls(meta, out_path):
    wb = xlwt.Workbook()
    hdr = xlwt.easyxf("font: bold on, colour white; pattern: pattern solid, fore_colour dark_blue")
    sev_map = {"critical": xlwt.easyxf("pattern: pattern solid, fore_colour red"),
               "high": xlwt.easyxf("pattern: pattern solid, fore_colour orange"),
               "medium": xlwt.easyxf("pattern: pattern solid, fore_colour yellow"),
               "low": xlwt.easyxf("pattern: pattern solid, fore_colour light_blue")}

    def fill(ws, headers, rows, date_fmt=False, style_for=None):
        for ci, h in enumerate(headers):
            ws.write(0, ci, h, hdr)
        for ri, row in enumerate(rows, start=1):
            for ci, v in enumerate(row):
                st = style_for(ci, row) if style_for else xlwt.Style.default_style
                ws.write(ri, ci, v, st)

    ws = wb.add_sheet("Summary")
    fill(ws, ["key", "value"],
         [["Project", "LAMDEX"], ["Version", meta["version"]], ["Site", meta["site"]],
          ["Generated", meta["generated_at"]], ["Runs", meta["metrics"]["totals"]["runs"]],
          ["Detections", meta["metrics"]["totals"]["detections"]],
          ["Precision", meta["metrics"]["totals"]["precision"]],
          ["Recall", meta["metrics"]["totals"]["recall"]],
          ["F1", meta["metrics"]["totals"]["f1"]],
          ["TP", meta["metrics"]["totals"]["tp"]],
          ["FP", meta["metrics"]["totals"]["fp"]],
          ["FN", meta["metrics"]["totals"]["fn"]]])

    ws2 = wb.add_sheet("Detections")
    fill(ws2, ["id", "run", "rule", "tech", "level", "conf", "eid", "src", "tgt", "user"],
         [[d["detection_id"], d["run_id"], d["rule_id"], d["technique_id"] or "-", d["level"],
           d["confidence"], d["event_id"] or "-", d["src"], d["tgt"], d["usr"]]
          for d in meta["detections"]],
         style_for=lambda ci, row: sev_map.get(row[4], xlwt.Style.default_style) if ci == 4 else xlwt.Style.default_style)

    ws3 = wb.add_sheet("Metrics")
    fill(ws3, ["technique", "expected", "covered", "tp", "fp", "fn", "precision", "recall", "f1"],
         [[m["technique_id"], m["expected"], m["covered"], m["tp"], m["fp"], m["fn"],
           m["precision"], m["recall"], m["f1"]] for m in meta["metrics"]["per_technique"]])

    ws4 = wb.add_sheet("Compliance")
    fill(ws4, ["framework", "control", "description", "evidence"],
         [list(row[0:4]) for row in meta["compliance"]])

    wb.save(out_path)
    return out_path


def export_csv_bundle(meta, out_dir):
    paths = {}
    det_file = os.path.join(out_dir, "alerts.csv")
    with open(det_file, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["detection_id", "run_id", "rule_id", "rule_name", "technology", "level",
                    "confidence", "event_id", "data_source", "source_host", "target_host", "user",
                    "ground_truth_match", "timestamp"])
        for d in meta["detections"]:
            w.writerow([d["detection_id"], d["run_id"], d["rule_id"], d["rule_name"],
                        d["technique_id"] or d["rule_technique"] or "-", d["level"],
                        d["confidence"], d["event_id"] or "-", d["data_source"], d["src"], d["tgt"],
                        d["usr"], d["tp"], d["ts"]])
    paths["alerts.csv"] = det_file

    tc_file = os.path.join(out_dir, "techniques.csv")
    with open(tc_file, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["technique_id", "name", "severity", "coverage", "expected_rules", "covered_rules", "coverage_ratio"])
        for c in meta["coverage"]:
            w.writerow([c["technique_id"], c["name"], c["severity"],
                        "%.0f%%" % (c["ratio"] * 100), c["expected"], c["covered"], round(c["ratio"], 2)])
    paths["techniques.csv"] = tc_file

    m_file = os.path.join(out_dir, "metrics.csv")
    with open(m_file, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["technique_id", "expected", "coverage", "tp", "fp", "fn", "precision", "recall", "f1"])
        for m in meta["metrics"]["per_technique"]:
            w.writerow([m["technique_id"], m["expected"], m["covered"], m["tp"], m["fp"],
                        m["fn"], m["precision"], m["recall"], m["f1"]])
    paths["metrics.csv"] = m_file

    co_file = os.path.join(out_dir, "compliance.csv")
    with open(co_file, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["framework", "control", "description", "evidence"])
        for row in meta["compliance"]:
            w.writerow(list(row))
    paths["compliance.csv"] = co_file

    ev_file = os.path.join(out_dir, "evidence.csv")
    with open(ev_file, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["run_id", "technique_id", "artifact", "sha256", "is_lab"])
        for r in meta["runs"]:
            w.writerow([r["run_id"], r["technique_id"], "telemetry", r["sha256"], "true"])
    paths["evidence.csv"] = ev_file
    return paths


def _sev_badge(level):
    colors = {"critical": "#C92A2A", "high": "#E86A17", "medium": "#E6B800", "low": "#2E86DE"}
    return '<span class="badge" style="background:%s;color:#fff">%s</span>' % (colors.get(level, "#444"), _hl(level))


def export_html(meta, out_path):
    det_rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s &rarr; %s</td></tr>"
        % (_hl(d["detection_id"]), _hl(d["run_id"]), _hl(d["rule_id"]), _hl(d["technique_id"] or d["rule_technique"] or "-"),
           _sev_badge(d["level"]), d["confidence"], _hl(d["event_id"] or "-"), _hl(d["data_source"]), _hl(d["src"]), _hl(d["tgt"]))
        for d in meta["detections"])
    tech_rows = "".join(
        "<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><span>%s</span></td></tr>"
        % (_hl(c["technique_id"]), _hl(c["name"]), _sev_badge(c["severity"]),
           _hl(str(c["expected"])), _hl(str(c["covered"])), _hl(str(c["covered"]) + "/" + str(c["expected"])))
        for c in meta["coverage"])
    comp_rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
        % (_hl(row[0]), _hl(row[1]), _hl(row[2]), _hl(row[3])) for row in meta["compliance"])
    t = meta["metrics"]["totals"]
    css = (
        "body{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1421;color:#dbe4f0;margin:0;padding:24px} "
        "h1{color:#7dd3fc} h2{color:#c4b5fd;border-bottom:1px solid #2c3e50;padding-bottom:6px} "
        ".wrap{max-width:1180px;margin:0 auto}.cards{display:flex;gap:14px;flex-wrap:wrap;margin:18px 0} "
        ".card{background:#16233b;border:1px solid #263a55;border-radius:12px;padding:14px 20px;min-width:150px} "
        ".card b{display:block;font-size:26px;color:#22d3a8}.card span{color:#8aa2c0;font-size:12px} "
        "table{border-collapse:collapse;width:100percent;margin:10px 0;font-size:13px} "
        "th{background:#16324f;color:#fff;text-align:left;padding:8px} "
        "td{border-bottom:1px solid #22344d;padding:7px 8px} "
        "code{background:#1d2c44;padding:2px 6px;border-radius:4px;color:#fbbf24} "
        ".badge{padding:2px 9px;border-radius:10px;font-size:11px;font-weight:600;text-transform:uppercase} "
        ".tag{color:#64748b;font-size:12px}")
    doc = (
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta http-equiv=\"Content-Security-Policy\" "
        "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        "<title>LAMDEX Evidence Report</title><style>%s</style></head><body><div class=\"wrap\">"
        "<h1>&#128270; LAMDEX Evidence Report</h1>"
        "<p class=\"tag\">Version __VERSION__ &middot; Site __SITE__ &middot; LAB:true &middot; Generated __GENERATED__</p>"
        "<div class=\"cards\">"
        "<div class=\"card\"><b>__RUNS__</b><span>Runs</span></div>"
        "<div class=\"card\"><b>__DETECTIONS__</b><span>Detections</span></div>"
        "<div class=\"card\"><b>__PRECISION__</b><span>Precision</span></div>"
        "<div class=\"card\"><b>__RECALL__</b><span>Recall</span></div>"
        "<div class=\"card\"><b>__F1__</b><span>F1</span></div>"
        "<div class=\"card\"><b>__COVERED__</b><span>Techniques Covered</span></div>"
        "</div><h2>Detections (__NDET__)</h2>"
        "<table><tr><th>ID</th><th>Run</th><th>Rule</th><th>Technique</th><th>Level</th><th>Conf</th>"
        "<th>Event</th><th>Source</th><th>Vector</th></tr>__DET_ROWS__</table>"
        "<h2>Technique Coverage</h2>"
        "<table><tr><th>Technique</th><th>Name</th><th>Severity</th><th>Expected</th><th>Covered</th>"
        "<th>Status</th></tr>__TECH_ROWS__</table>"
        "<h2>Compliance Mapping</h2>"
        "<table><tr><th>Framework</th><th>Control</th><th>Description</th><th>Evidence</th></tr>__COMP_ROWS__</table>"
        "</div></body></html>")
    doc = doc.replace("__VERSION__", _hl(meta["version"])) \
        .replace("__SITE__", _hl(meta["site"])) \
        .replace("__GENERATED__", _hl(meta["generated_at"])) \
        .replace("__RUNS__", _hl(str(t["runs"]))) \
        .replace("__DETECTIONS__", _hl(str(t["detections"]))) \
        .replace("__PRECISION__", _hl(str(t["precision"]))) \
        .replace("__RECALL__", _hl(str(t["recall"]))) \
        .replace("__F1__", _hl(str(t["f1"]))) \
        .replace("__COVERED__", _hl(str(t["techniques_covered"]))) \
        .replace("__NDET__", _hl(str(len(meta["detections"])))) \
        .replace("__DET_ROWS__", det_rows) \
        .replace("__TECH_ROWS__", tech_rows) \
        .replace("__COMP_ROWS__", comp_rows)
    doc = doc.replace("width:100percent", "width:100%")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(doc)
    return out_path


def write_bundle(storage, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    runs = storage.list_runs()
    detections = storage.list_detections()
    meta = build_meta(runs, detections)
    stamp = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
    written = []
    xlsx_path = os.path.join(out_dir, "lamdex_report_%s.xlsx" % stamp)
    export_xlsx(meta, xlsx_path)
    xls_path = os.path.join(out_dir, "lamdex_report_%s.xls" % stamp)
    export_xls(meta, xls_path)
    csv_paths = export_csv_bundle(meta, out_dir)
    html_path = os.path.join(out_dir, "lamdex_report_%s.html" % stamp)
    export_html(meta, html_path)
    for label, path in [("workbook-xlsx", xlsx_path), ("workbook-xls", xls_path), ("dashboard-html", html_path)]:
        size = os.path.getsize(path)
        rid = uuid.uuid4().hex[:12]
        with open(path, "rb") as f:
            digest = _sha(f.read())
        storage.add_report(rid, label, os.path.splitext(path)[1].lstrip("."), path, digest, size)
        written.append({"report_id": rid, "kind": label, "path": path, "sha256": digest, "size": size})
    for name, path in csv_paths.items():
        size = os.path.getsize(path)
        rid = uuid.uuid4().hex[:12]
        with open(path, "rb") as f:
            digest = _sha(f.read())
        storage.add_report(rid, "csv-" + name.split(".")[0], "csv", path, digest, size)
        written.append({"report_id": rid, "kind": "csv-" + name, "path": path, "sha256": digest, "size": size})
    storage.audit("analyst", "report.bundle", "generated %d report artifacts" % len(written))
    return written


def data_meta():
    return {"techniques": len(TECHNIQUES), "rules": len(BUILTIN_RULES),
            "hosts": len(TOPOLOGY), "identities": len(IDENTITIES),
            "compliance_rows": len(COMPLIANCE_MAP)}