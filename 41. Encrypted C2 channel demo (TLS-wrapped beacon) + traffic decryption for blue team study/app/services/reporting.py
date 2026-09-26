import csv
import datetime

from app.config import REPORTS_DIR, TEMPLATES_DIR
from app.db import execute, now_iso, query_all, query_one
from app.services.detection import list_alerts, list_rules, stats

COMPLIANCE_MATRIX = {
    "owasp": [
        ["A01", "Broken Access Control", "RBAC on panel, per-zone ACLs, least privilege"],
        ["A02", "Cryptographic Failures", "TLS 1.3, AES-256-GCM, no custom crypto"],
        ["A03", "Injection", "Parameterized SQL, encoded output"],
        ["A04", "Insecure Design", "Threat model + red/blue zone isolation"],
        ["A05", "Security Misconfiguration", "Secure TLS config templates, lab profile"],
        ["A06", "Vulnerable Components", "Pinned versions, SBOM, update cadence"],
        ["A07", "Identification Failures", "mTLS, UUID tokens, admin token"],
        ["A08", "Software/Data Integrity", "Signed builds, integrity checksums"],
        ["A09", "Logging/Monitoring", "Audit log, SSLKEYLOG, alerting"],
        ["A10", "SSRF", "Egress allowlist, network segmentation"],
    ],
    "nist": [
        ["GV", "Govern", "SA-3, PL-2 risk register"],
        ["ID", "Identify", "CM-8, RS-2 asset inventory"],
        ["PR", "Protect", "SC-8, SC-13 transport, IA-2/4 identification"],
        ["DE", "Detect", "AU-6, SI-4 correlation + alerting"],
        ["RS", "Respond", "IR-4, IR-6 incident playbook"],
        ["RC", "Recover", "IR-4, CP-4 evidence restore"],
    ],
    "iso": [
        ["A.5.14", "Info transfer", "TLS-wrapped transport"],
        ["A.8.24", "Use of cryptography", "AES-256-GCM, X25519, key custodians"],
        ["A.8.9", "Configuration management", "Config-as-code lab templates"],
        ["A.8.12", "Vulnerability management", "Scans + SBOM cadence"],
        ["A.8.15", "Logging", "Structured logs to SIEM"],
        ["A.8.16", "Monitoring", "Alert pipeline"],
        ["A.8.26", "App security", "OWASP-informed review"],
    ],
}


def _scope_data(scope: str = "all") -> dict:
    if scope == "all":
        sessions = query_all("SELECT * FROM sessions ORDER BY first_seen DESC")
    else:
        sessions = query_all("SELECT * FROM sessions WHERE uuid=? ORDER BY first_seen DESC", (scope,))
    uuids = [s["uuid"] for s in sessions]
    ph = ",".join("?" * len(uuids)) if uuids else "''"
    traffic = query_all(f"SELECT * FROM traffic WHERE session_uuid IN ({ph}) ORDER BY id", uuids) if uuids else []
    tasks = query_all(f"SELECT * FROM tasks WHERE session_uuid IN ({ph}) ORDER BY id", uuids) if uuids else []
    keys = query_all(f"SELECT * FROM keys WHERE session_uuid IN ({ph}) ORDER BY id", uuids) if uuids else []
    alerts = (
        list_alerts(limit=500)
        if scope == "all"
        else query_all("SELECT * FROM alerts WHERE session_uuid=? ORDER BY id DESC", (scope,))
    )
    audit = query_all("SELECT * FROM audit_log ORDER BY id DESC LIMIT 200")
    return {
        "sessions": sessions,
        "traffic": traffic,
        "tasks": tasks,
        "keys": keys,
        "alerts": alerts,
        "audit": audit,
        "rules": list_rules(),
        "stats": stats(),
    }


def build_bundle(formats: list, scope: str = "all") -> dict:
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    data = _scope_data(scope)
    produced = []
    for fmt in formats:
        if fmt == "xlsx":
            path = REPORTS_DIR / f"report_{ts}.xlsx"
            _write_xlsx(path, data)
        elif fmt == "csv":
            path = REPORTS_DIR / f"report_{ts}.csv"
            _write_csv(path, data)
        elif fmt == "html":
            path = REPORTS_DIR / f"report_{ts}.html"
            _write_html(path, data)
        else:
            continue
        produced.append({"format": fmt, "file_name": path.name, "size": path.stat().st_size, "path": str(path)})
        execute(
            "INSERT INTO report_bundles (created_at, scope, formats, file_name, file_size, path) VALUES (?,?,?,?,?,?)",
            (now_iso(), scope, fmt, path.name, path.stat().st_size, str(path)),
        )
    return {"generated_at": ts, "files": produced}


def list_reports() -> list:
    return query_all("SELECT * FROM report_bundles ORDER BY id DESC LIMIT 50")


def _write_xlsx(path, data):
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill
    from openpyxl.utils import get_column_letter

    wb = Workbook()
    header_fill = PatternFill("solid", fgColor="1E3A8A")
    header_font = Font(color="FFFFFF", bold=True)
    zone_fills = {"sessions": "FFE4E6", "traffic": "FEF9C3", "tasks": "DBEAFE", "alerts": "DCFCE7"}

    def sheet(name, rows, cols, fill_hex):
        ws = wb.create_sheet(title=name[:31])
        ws.append(cols)
        for c in range(1, len(cols) + 1):
            cell = ws.cell(row=1, column=c)
            cell.fill = header_fill
            cell.font = header_font
        fill = PatternFill("solid", fgColor=fill_hex)
        for r in rows:
            vals = [r.get(k, "") if isinstance(r, dict) else r for k in cols]
            ws.append(vals)
            for c in range(1, len(cols) + 1):
                ws.cell(row=ws.max_row, column=c).fill = fill
        ws.auto_filter.ref = ws.dimensions
        for c in range(1, len(cols) + 1):
            ws.column_dimensions[get_column_letter(c)].width = 26
        return ws

    sheet("Sessions", data["sessions"], ["uuid", "agent_name", "ip", "os", "status", "first_seen", "last_seen", "risk_score", "ja3", "sni", "tls_version", "cipher"], zone_fills["sessions"])
    sheet("Traffic", data["traffic"], ["id", "session_uuid", "ts", "event", "src_ip", "dst_ip", "dst_port", "record_len", "decrypted", "plaintext"], zone_fills["traffic"])
    sheet("Tasks", data["tasks"], ["task_id", "session_uuid", "command", "status", "created_at", "result_data", "result_size"], zone_fills["tasks"])
    sheet("Alerts", data["alerts"], ["id", "ts", "rule_id", "rule_name", "session_uuid", "severity", "score", "detail", "status", "mitre_id"], zone_fills["alerts"])
    sheet("KeyCustodian", data["keys"], ["id", "session_uuid", "key_type", "label", "created_at", "status"], "EDE9FE")
    sheet("AuditLog", data["audit"], ["id", "ts", "actor", "action", "zone", "detail", "ip"], "F3F4F6")
    ws = wb.create_sheet(title="Compliance")
    ws.append(["Framework", "ID", "Area", "Architecture Response"])
    row_idx = 2
    for fw, rows in COMPLIANCE_MATRIX.items():
        for (rid, area, mapping) in rows:
            ws.cell(row=row_idx, column=1, value=fw)
            ws.cell(row=row_idx, column=2, value=rid)
            ws.cell(row=row_idx, column=3, value=area)
            ws.cell(row=row_idx, column=4, value=mapping)
            row_idx += 1
    wb.remove(wb.active)
    wb.save(path)


def _write_csv(path, data):
    def dump(rows, cols):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(cols)
            for r in rows:
                w.writerow([r.get(k, "") for k in cols])

    dump(data["traffic"], ["id", "session_uuid", "ts", "event", "src_ip", "dst_ip", "src_port", "dst_port", "record_len", "meta", "decrypted", "plaintext"])
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([])
        w.writerow(["SESSIONS"])
        w.writerow(["uuid", "agent_name", "status", "risk_score", "ja3", "sni", "first_seen", "last_seen"])
        for s in data["sessions"]:
            w.writerow([s.get("uuid"), s.get("agent_name"), s.get("status"), s.get("risk_score"), s.get("ja3"), s.get("sni"), s.get("first_seen"), s.get("last_seen")])
        w.writerow([])
        w.writerow(["ALERTS"])
        w.writerow(["id", "ts", "rule_id", "rule_name", "session_uuid", "severity", "score", "status", "mitre_id"])
        for a in data["alerts"]:
            w.writerow([a.get("id"), a.get("ts"), a.get("rule_id"), a.get("rule_name"), a.get("session_uuid"), a.get("severity"), a.get("score"), a.get("status"), a.get("mitre_id")])


def _write_html(path, data):
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html", "j2"]),
    )
    tpl = env.get_template("report.html.j2")
    html = tpl.render(data=data, compliance=COMPLIANCE_MATRIX, generated=now_iso())
    path.write_text(html, encoding="utf-8")