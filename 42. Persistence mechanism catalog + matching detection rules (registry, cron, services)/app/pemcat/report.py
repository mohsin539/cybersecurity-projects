import csv
import html
import io
import time

try:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    OPENPYXL_OK = True
except ImportError:
    OPENPYXL_OK = False

SEVERITY_COLORS = {
    "critical": "9C0006",
    "high": "C00000",
    "medium": "ED7D31",
    "low": "FFC000",
}
HEADER_FILL = "1F3864"
KPI_FILLS = ["2E75B6", "C00000", "548235", "BF8F00"]

COMPLIANCE_MAP = [
    ("OWASP A01", "Broken Access Control", "RBAC, signed expiring report URLs, deny-by-default"),
    ("OWASP A02", "Cryptographic Failures", "TLS, at-rest encryption, SHA-256 fingerprints"),
    ("OWASP A03", "Injection", "Parameterized SQL, DSL validation, output-encoded HTML reports"),
    ("OWASP A07", "Identity & Auth Failures", "MFA-capable login gate, minimal surface"),
    ("OWASP A08", "Software & Data Integrity", "Report SHA-256 checksums, signed rule store"),
    ("OWASP A09", "Logging & Monitoring", "Append-only audit ledger, activity KPIs"),
    ("NIST ID.AM-06", "Configuration/Asset Inventory", "Persistence catalog as inventory control"),
    ("NIST DE.CM-07", "Continuous Monitoring", "Periodic persistence enumeration + matching"),
    ("NIST DE.AE-01", "Anomaly & Event Detection", "Detection rule engine scoring + confidence"),
    ("NIST PR.DS-01", "Data Protection at Rest", "Local DB + report integrity hashes"),
    ("ISO 8.15", "Access Control to IT Security Controls", "Rule enable/disable + status workflow"),
    ("ISO 6.8", "Info Security Event Reporting", "Match events exported for SIEM/SOAR"),
]


def _ts():
    return time.strftime("%Y%m%d_%H%M%S")


def _openpyxl_guard():
    if not OPENPYXL_OK:
        raise RuntimeError("openpyxl is required for .xlsx export")


def report_xlsx(path, data):
    _openpyxl_guard()
    wb = Workbook()
    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill("solid", fgColor=HEADER_FILL)
    wrap = Alignment(wrap_text=True, vertical="top")

    ws = wb.active
    ws.title = "Overview"
    ws["A1"] = "PEM-CAT Persistence Catalog Report"
    ws["A1"].font = Font(bold=True, size=16, color=HEADER_FILL)
    ws["A2"] = "Generated: {0}  |  Host: {1}  |  App: v{2}".format(
        data["generated"], data["host"], data["app_version"]
    )
    ws["A4"] = "KPI"
    ws["B4"] = "Value"
    for cell in ("A4", "B4"):
        ws[cell].font = header_font
        ws[cell].fill = header_fill
    kpis = [
        ("Total artifacts cataloged", data["stats"]["total"]),
        ("Baselined (trusted)", data["stats"]["baselined"]),
        ("Open detections", data["open_matches"]),
        ("Active rules", data["active_rules"]),
    ]
    for row, (label, value) in enumerate(kpis, 5):
        ws.cell(row=row, column=1, value=label)
        ws.cell(row=row, column=2, value=value)
        ws.cell(row=row, column=1).fill = PatternFill("solid", fgColor=KPI_FILLS[row - 5])
        ws.cell(row=row, column=1).font = Font(bold=True, color="FFFFFF")

    rows_by_type = data["stats"].get("by_type", {})
    ws.cell(row=10, column=1, value="Artifact distribution").font = Font(bold=True)
    ws.cell(row=10, column=1, value=None)
    ws.cell(row=10, column=1, value="Artifact distribution")
    ws["A10"].font = Font(bold=True, color=HEADER_FILL)
    ws["A11"] = "Type"
    ws["B11"] = "Count"
    ws["A11"].font = header_font
    ws["B11"].font = header_font
    ws["A11"].fill = header_fill
    ws["B11"].fill = header_fill
    _row = 12
    for atype, count in sorted(rows_by_type.items()):
        ws.cell(row=_row, column=1, value=atype)
        ws.cell(row=_row, column=2, value=count)
        _row += 1

    _row += 1
    ws.cell(row=_row, column=1, value="Security framework compliance mapping").font = Font(bold=True, color=HEADER_FILL)
    _row += 1
    for col, title in enumerate(("Control", "Risk", "Implementation"), 1):
        ws.cell(row=_row, column=col, value=title).font = header_font
        ws.cell(row=_row, column=col).fill = header_fill
    _row += 1
    for control, risk, impl in COMPLIANCE_MAP:
        ws.cell(row=_row, column=1, value=control)
        ws.cell(row=_row, column=2, value=risk)
        ws.cell(row=_row, column=3, value=impl)
        _row += 1
    ws.column_dimensions["A"].width = 34
    ws.column_dimensions["B"].width = 46
    ws.column_dimensions["C"].width = 60

    art_ws = wb.create_sheet("Artifacts")
    art_cols = ["artifact_id", "host_id", "artifact_type", "mechanism", "image_path",
                "command_line", "is_baselined", "seen_count", "first_seen", "last_seen",
                "fingerprint_sha256"]
    _write_sheet(art_ws, art_cols, data["records"], header_font, header_fill, wrap,
                 {"is_baselined": lambda v: "Yes" if v else "No"})

    mat_ws = wb.create_sheet("Matches")
    mat_cols = ["evt_id", "rule_id", "rule_name", "technique", "severity", "confidence",
                "score", "status", "detected_at", "host_id", "artifact_type", "mechanism"]
    _write_sheet(mat_ws, mat_cols, data["matches"], header_font, header_fill, wrap,
                 severity_fill=True, sev_key="severity")

    host_ws = wb.create_sheet("Hosts")
    _write_sheet(host_ws, ["host_id", "artifact_count", "open_matches", "baselined"],
                 data["hosts"], header_font, header_fill, wrap)

    rule_ws = wb.create_sheet("Rules")
    _write_sheet(rule_ws, ["rule_id", "name", "technique", "severity", "status", "owner"],
                 data["rules"], header_font, header_fill, wrap, severity_fill=True, sev_key="severity")

    audit_ws = wb.create_sheet("Audit")
    _write_sheet(audit_ws, ["id", "ts", "actor", "action", "object_id", "detail"],
                 data["audit"], header_font, header_fill, wrap)

    wb.save(path)
    return path


def _write_sheet(ws, columns, rows, header_font, header_fill, wrap, transforms=None,
                 severity_fill=False, sev_key=None):
    transforms = transforms or {}
    for col, title in enumerate(columns, 1):
        cell = ws.cell(row=1, column=col, value=title)
        cell.font = header_font
        cell.fill = header_fill
    for r, row in enumerate(rows, 2):
        for c, col in enumerate(columns, 1):
            value = row.get(col)
            if col in transforms:
                value = transforms[col](value)
            cell = ws.cell(row=r, column=c, value=value)
            cell.alignment = wrap
            if severity_fill and col == sev_key and value:
                color = SEVERITY_COLORS.get(str(value).lower())
                if color:
                    cell.fill = PatternFill("solid", fgColor=color)
                    cell.font = Font(color="FFFFFF", bold=True)
    ws.auto_filter.ref = "A1:{0}{1}".format(
        get_column_letter(len(columns)), len(rows) + 1
    )
    ws.freeze_panes = "A2"
    for c, col in enumerate(columns, 1):
        width = max(min(max(len(str(col)), 12), 40), 8)
        ws.column_dimensions[get_column_letter(c)].width = width


def report_csv(folder_path, data):
    files = []
    definitions = [
        ("artifacts", ["artifact_id", "host_id", "artifact_type", "mechanism", "image_path",
                       "command_line", "is_baselined", "seen_count", "first_seen",
                       "fingerprint_sha256"], data["records"]),
        ("matches", ["evt_id", "rule_id", "rule_name", "technique", "severity",
                     "confidence", "score", "status", "detected_at", "host_id", "mechanism"],
         data["matches"]),
        ("hosts", ["host_id", "artifact_count", "open_matches", "baselined"], data["hosts"]),
        ("rules", ["rule_id", "name", "technique", "severity", "status", "owner"], data["rules"]),
        ("audit", ["id", "ts", "actor", "action", "object_id", "detail"], data["audit"]),
    ]
    for name, columns, rows in definitions:
        path = "{0}/pemcat_report_{1}_{2}.csv".format(folder_path, name, _ts())
        with io.open(path, "w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.DictWriter(fh, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
        files.append(path)
    return files


def report_html(path, data):
    esc = html.escape
    cards = [
        ("Total Artifacts", data["stats"]["total"], "2E75B6"),
        ("Open Detections", data["open_matches"], "C00000"),
        ("Baselined", data["stats"]["baselined"], "548235"),
        ("Active Rules", data["active_rules"], "BF8F00"),
    ]
    kpi_html = ""
    for label, value, color in cards:
        kpi_html += (
            '<div class="kpi" style="border-top:4px solid #{0}">'
            '<div class="kpi-value">{1}</div><div class="kpi-label">{2}</div></div>'
        ).format(color, value, esc(label))

    by_type = data["stats"].get("by_type", {})

    seg_rows = ""
    for atype, count in sorted(by_type.items()):
        pct = 100 * count / max(data["stats"]["total"], 1)
        seg_rows += '<div class="seg"><span>{0}</span><div class="bar"><i style="width:{1:.0f}%"></i></div><b>{2}</b></div>'.format(
            esc(atype), pct, count)
    if not seg_rows:
        seg_rows = "<p>No catalog entries yet. Run a Scan.</p>"

    art_rows = ""
    for rec in data["records"][:500]:
        art_rows += "<tr><td>{0}</td><td>{1}</td><td>{2}</td><td title=\"{3}\">{4}</td><td title=\"{5}\">{6}</td><td>{7}</td></tr>".format(
            rec.get("artifact_id"), esc(rec.get("host_id")), esc(rec.get("artifact_type")),
            esc(rec.get("mechanism") or ""), esc(shorten(rec.get("mechanism"), 48)),
            esc(rec.get("image_path") or ""), esc(shorten(rec.get("image_path"), 46)),
            "Yes" if rec.get("is_baselined") else "No"
        )

    mat_rows = ""
    for m in data["matches"][:500]:
        mat_rows += "<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td><span class=\"sev sev-{4}\">{5}</span></td><td>{6}</td><td>{7}</td><td>{8}</td></tr>".format(
            m.get("evt_id"), esc(m.get("rule_id")), esc(m.get("rule_name")),
            esc(m.get("technique") or ""), esc(m.get("severity") or "").lower(),
            esc(m.get("severity") or ""), m.get("confidence"), m.get("score"),
            esc(m.get("status") or "")
        )

    host_rows = ""
    for h in data["hosts"]:
        host_rows += "<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td></tr>".format(
            esc(h["host_id"]), h["artifact_count"], h["open_matches"], h["baselined"]
        )

    audit_rows = ""
    for a in data["audit"][:200]:
        audit_rows += "<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td>{4}</td></tr>".format(
            a["id"], esc(a["ts"]), esc(a["actor"]), esc(a["action"]), esc(a["object_id"] or "")
        )

    doc = _HTML_TEMPLATE.format(
        generated=esc(data["generated"]),
        host=esc(data["host"]),
        version=esc(data["app_version"]),
        kpi=kpi_html,
        segments=seg_rows,
        artifacts=art_rows,
        matches=mat_rows,
        hosts=host_rows,
        audit=audit_rows,
    )
    with io.open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return path


def shorten(value, length):
    value = str(value or "")
    return value if len(value) <= length else value[: length - 1] + "…"


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>PEM-CAT Report - {generated}</title>
<style>
  :root {{ --ink:#1a1f36; --muted:#5b6281; --paper:#f4f6fb; --card:#ffffff; }}
  * {{ box-sizing:border-box; font-family:'Segoe UI', Arial, sans-serif; }}
  body {{ margin:0; background:var(--paper); color:var(--ink); }}
  header {{ background:linear-gradient(120deg,#1f3864,#2E75B6); color:#fff; padding:26px 28px; }}
  header h1 {{ margin:0; font-size:24px; }}
  header p {{ margin:4px 0 0; opacity:.85; font-size:13px; }}
  main {{ padding:22px 28px; }}
  .kpis {{ display:flex; gap:16px; margin:18px 0 26px; flex-wrap:wrap; }}
  .kpi {{ background:var(--card); border-radius:10px; padding:16px 22px; min-width:160px;
         box-shadow:0 2px 8px rgba(26,31,54,.08); }}
  .kpi-value {{ font-size:30px; font-weight:800; }}
  .kpi-label {{ color:var(--muted); font-size:13px; margin-top:2px; }}
  .panel {{ background:var(--card); border-radius:12px; padding:18px 20px; margin-bottom:24px;
           box-shadow:0 2px 8px rgba(26,31,54,.08); }}
  .panel h2 {{ margin:0 0 14px; font-size:16px; color:var(--ink);
               border-bottom:2px solid #e3e8f4; padding-bottom:8px; }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th {{ background:#eef1f9; text-align:left; padding:8px; color:#33415c; }}
  td {{ padding:7px 8px; border-bottom:1px solid #e3e8f4; }}
  .sev {{ padding:2px 8px; border-radius:20px; color:#fff; font-size:11px; font-weight:700; }}
  .sev-critical {{ background:#9C0006; }} .sev-high {{ background:#C00000; }}
  .sev-medium {{ background:#ED7D31; }} .sev-low {{ background:#BF8F00; }}
  .seg {{ display:flex; align-items:center; gap:12px; margin:8px 0; }}
  .seg span {{ width:140px; font-size:13px; }}
  .bar {{ flex:1; background:#e3e8f4; border-radius:20px; height:14px; overflow:hidden; }}
  .bar i {{ display:block; height:100%; background:linear-gradient(90deg,#2E75B6,#548235); }}
  .seg b {{ width:50px; text-align:right; }}
  .match-yes {{ color:#C00000; font-weight:700; }}
</style>
</head>
<body>
<header>
  <h1>🛡️ PEM-CAT — Persistence Catalog &amp; Detection Report</h1>
  <p>Generated {generated} · Host {host} · App v{version}</p>
</header>
<main>
  <div class="kpis">{kpi}</div>
  <div class="panel">
    <h2>📊 Catalog distribution</h2>
    {segments}
  </div>
  <div class="panel">
    <h2>🗃️ Persistence artifacts (top {artifact_limit})</h2>
    <table>
      <tr><th>ID</th><th>Host</th><th>Type</th><th>Mechanism</th><th>Image</th><th>Baselined</th></tr>
      {artifacts}
    </table>
  </div>
  <div class="panel">
    <h2>🚨 Detection matches</h2>
    <table>
      <tr><th>Evt</th><th>Rule</th><th>Name</th><th>ATT&amp;CK</th><th>Severity</th><th>Conf</th><th>Score</th><th>Status</th></tr>
      {matches}
    </table>
  </div>
  <div class="panel">
    <h2>🖥️ Hosts</h2>
    <table>
      <tr><th>Host</th><th>Artifacts</th><th>Open matches</th><th>Baselined</th></tr>
      {hosts}
    </table>
  </div>
  <div class="panel">
    <h2>📜 Audit trail</h2>
    <table>
      <tr><th>ID</th><th>Timestamp</th><th>Actor</th><th>Action</th><th>Object</th></tr>
      {audit}
    </table>
  </div>
</main>
</body>
</html>
""".replace("{artifact_limit}", "500")


def build_report_data(storage, app_version, host):
    stats = storage.stats()
    records = storage.list_records(limit=None)
    matches = storage.list_matches()
    rules = storage.rules()
    audit = storage.list_audit()
    hosts = []
    for host_id in storage.hosts():
        host_records = storage.list_records(host_id=host_id)
        count = len(host_records)
        open_matches = sum(
            1 for m in matches if m.get("host_id") == host_id and m.get("status") == "open"
        )
        baselined = sum(1 for r in host_records if r.get("is_baselined"))
        hosts.append({"host_id": host_id, "artifact_count": count,
                      "open_matches": open_matches, "baselined": baselined})
    data = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "host": host,
        "app_version": app_version,
        "stats": stats,
        "records": records,
        "matches": matches,
        "rules": rules,
        "audit": audit,
        "hosts": hosts,
        "open_matches": sum(1 for m in matches if m.get("status") == "open"),
        "active_rules": sum(1 for r in rules if r.get("status") == "active"),
    }
    return data