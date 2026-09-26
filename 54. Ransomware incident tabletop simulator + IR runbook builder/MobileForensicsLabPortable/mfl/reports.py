"""Report generator — produces downloadable, tamper-evident exports.

Formats:
  - HTML  (printable executive/technical report, self-contained)
  - JSON  (full case dump, machine-readable)
  - CSV   (per-entity tables)
  - XML   (audit pack interchange)

Every report ships with a SHA-256 manifest so recipients can verify integrity
(ISO A.8.24 / NIST SI-7 / OWASP A08).
"""

import csv
import hashlib
import io
import json
import xml.etree.ElementTree as ET
from datetime import datetime

from flask import current_app

from .db import query, query_one
from .compliance import posture


def _case_bundle(case_id):
    case = query_one("SELECT * FROM cases WHERE id=?", (case_id,))
    if not case:
        return None
    evidence = query(
        "SELECT * FROM evidence WHERE case_id=? ORDER BY id ASC", (case_id,)
    )
    artifacts = query(
        "SELECT a.* FROM artifacts a JOIN evidence e ON a.evidence_id=e.id "
        "JOIN cases c ON e.case_id=c.id WHERE c.id=? ORDER BY a.id ASC", (case_id,)
    )
    custody = query(
        "SELECT cu.*, e.device_model FROM custody_events cu "
        "JOIN evidence e ON cu.evidence_id=e.id JOIN cases c ON e.case_id=c.id "
        "WHERE c.id=? ORDER BY cu.occurred_at ASC", (case_id,)
    )
    return {"case": case, "evidence": evidence, "artifacts": artifacts, "custody": custody}


def html_report(app, case_id):
    bundle = _case_bundle(case_id)
    if not bundle:
        return None
    case, evidence, artifacts, custody = (
        bundle["case"], bundle["evidence"], bundle["artifacts"], bundle["custody"])
    org = query_one("SELECT value FROM settings WHERE key='org_name'")
    org = org["value"] if org else "Mobile Forensics Lab"
    pos = posture(app)

    rows = []
    for a in artifacts:
        ev = next((e for e in evidence if e["id"] == a["evidence_id"]), None)
        rows.append((ev["device_model"] if ev else "-",
                     a["category"], a["name"], a["value"], a["severity"],
                     a["timestamp"] or "-", a["artifact_hash"][:16]))

    rows_html = "".join(
        "<tr><td>%s</td><td><span class='tag'>%s</span></td><td>%s</td>"
        "<td><code>%s</code></td><td><span class='sev sev-%s'>%s</span></td>"
        "<td>%s</td><td><code>%s</code></td></tr>"
        % (_esc(r[0]), _esc(r[1]), _esc(r[2]), _esc(r[3]), r[4], _esc(r[4]), _esc(r[5]), _esc(r[6]))
        for r in rows
    ) or "<tr><td colspan='7'>No artifacts recorded.</td></tr>"

    ev_rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><code>%s</code></td>"
        "<td><span class='state'>%s</span></td></tr>"
        % (_esc(e["device_model"]), _esc(e["os_type"]), _esc(e["acquisition_method"]),
           _esc(e["acquired_by"]), _esc((e["sha256"] or "-")[:20]), _esc(e["status"]))
        for e in evidence
    ) or "<tr><td colspan='6'>No evidence on record.</td></tr>"

    co_rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s → %s</td><td>%s</td><td>%s</td></tr>"
        % (_esc(ev["device_model"]), _esc(cu["event_type"]),
           _esc(cu["from_location"] or "-"), _esc(cu["to_location"] or "-"),
           _esc(cu["to_user"] or "-"), _esc(cu["occurred_at"]))
        for cu, ev in ((cu, next((e for e in evidence if e["id"] == cu["evidence_id"]), None)) for cu in custody)
        if ev
    ) or "<tr><td colspan='5'>No custody events.</td></tr>"

    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    bundle_json = _canonical_json({"case": dict(bundle["case"]),
                                   "evidence": [dict(r) for r in bundle["evidence"]],
                                   "artifacts": [dict(r) for r in bundle["artifacts"]],
                                   "custody": [dict(r) for r in bundle["custody"]]})
    manifest = hashlib.sha256((bundle_json + str(case["id"])).encode()).hexdigest()

    html = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Forensic Report — {_esc(case['case_ref'])}</title>
<style>
  body{{font-family:Segoe UI,Arial,sans-serif;color:#1a2430;margin:32px}}
  h1{{color:#5a2d82}} h2{{color:#00407a;border-bottom:2px solid #d5d9e8;padding-bottom:4px;margin-top:36px}}
  table{{border-collapse:collapse;width:100%;margin:10px 0 26px}}
  th,td{{border:1px solid #c9d0de;padding:7px 10px;font-size:13px;text-align:left}}
  th{{background:#263445;color:#fff}} tr:nth-child(even){{background:#f3f5fa}}
  code{{font-family:Consolas,monospace;color:#7a0b0b}}
  .tag{{background:#e9d8fd;color:#4b0082;border-radius:9px;padding:1px 8px;font-size:11px}}
  .sev{{border-radius:9px;padding:1px 8px;font-size:11px;font-weight:700}}
  .sev-blocker,.sev-critical{{background:#7a0b0b;color:#fff}}
  .sev-high{{background:#d9534f;color:#fff}} .sev-medium{{background:#f0ad4e}}
  .sev-low{{background:#5bc0de}} .sev-info{{background:#d9d9d9}}
  .state{{background:#5cb85c;color:#fff;border-radius:9px;padding:1px 8px;font-size:11px}}
  .exechead{{background:#eef2fb;border-left:6px solid #5a2d82;padding:14px 18px;border-radius:6px}}
  .muted{{color:#7a8595}} .grid{{display:flex;gap:20px}} .card{{flex:1;border:1px solid #d5d9e8;border-radius:8px;padding:14px}}
  .score{{font-size:44px;font-weight:800;color:#00407a}} footer{{margin-top:40px;color:#7a8595;font-size:11px}}
</style></head><body>
<div class="exechead"><b>{_esc(org)}</b> · Digital Forensic Laboratory
<div class="muted">Case {_esc(case['case_ref'])} — {_esc(case['title'])} · Generated {_esc(ts)}</div></div>
<div class="grid">
 <div class="card"><div class="score">{len(evidence)}</div><div class="muted">Evidence items</div></div>
 <div class="card"><div class="score">{len(artifacts)}</div><div class="muted">Artifacts</div></div>
 <div class="card"><div class="score">{len(custody)}</div><div class="muted">Custody events</div></div>
 <div class="card"><div class="score">{pos['score']}%</div><div class="muted">Compliance posture</div></div>
</div>

<h2>1. Case Dossier</h2>
<table>
 <tr><th>Ref</th><td>{_esc(case['case_ref'])}</td><th>Status</th><td>{_esc(case['status'])}</td></tr>
 <tr><th>Severity</th><td>{_esc(case['severity'])}</td><th>Lead examiner</th><td>{_esc(case['lead_examiner'])}</td></tr>
 <tr><th>Opened</th><td>{_esc(case['created_at'])}</td><th>Description</th><td>{_esc(case['description'])}</td></tr>
</table>

<h2>2. Evidence Intake</h2>
<table><tr><th>Device</th><th>OS</th><th>Acquisition</th><th>By</th><th>SHA-256 (head)</th><th>Status</th></tr>{ev_rows}</table>

<h2>3. Artifact Analysis</h2>
<table><tr><th>Device</th><th>Category</th><th>Artifact</th><th>Value</th><th>Severity</th><th>Timestamp</th><th>Hash</th></tr>{rows_html}</table>

<h2>4. Chain of Custody</h2>
<table><tr><th>Device</th><th>Event</th><th>Location</th><th>Custodian</th><th>Occurred</th></tr>{co_rows}</table>

<h2>5. Compliance Mapping (excerpt)</h2>
<table><tr><th>Framework</th><th>Control</th><th>Capability</th><th>Evidence</th></tr>
{f''.join("<tr><td>{_esc(r['framework'])}</td><td><code>{_esc(r['ref'])}</code></td><td>{_esc(r['capability'])}</td><td>{'✅' if r['evidence'] else '⬜'}</td></tr>" for r in pos['rows'])}
</table>

<h2>6. Integrity Manifest</h2>
<p class="muted">SHA-256 of canonical case payload:</p>
<p><code>{manifest}</code></p>
<footer>MobileForensicsLabPortable — auditable case export. Verify with any SHA-256 tool.
Control basis: ISO 27001:2022 · NIST CSF 2.0 / 800-53r5 · OWASP Top 10 (2021).</footer>
</body></html>"""
    return html.encode("utf-8"), manifest


def json_report(case_id):
    bundle = _case_bundle(case_id)
    if not bundle:
        return None
    payload = {"case": dict(bundle["case"]),
               "evidence": [dict(r) for r in bundle["evidence"]],
               "artifacts": [dict(r) for r in bundle["artifacts"]],
               "custody": [dict(r) for r in bundle["custody"]]}
    payload["export_ts"] = datetime.utcnow().isoformat() + "Z"
    return _canonical_json(payload).encode("utf-8")


def csv_report(case_id, entity, app=None):
    bundle = _case_bundle(case_id)
    if not bundle:
        return None
    buf = io.StringIO()
    writer = csv.writer(buf)
    if entity == "evidence":
        writer.writerow(["id","device_model","manufacturer","os_type","imei","acquisition_method",
                         "acquired_by","acquired_at","status","sha256"])
        for e in bundle["evidence"]:
            writer.writerow([e["id"], e["device_model"], e["manufacturer"], e["os_type"], e["imei"],
                             e["acquisition_method"], e["acquired_by"], e["acquired_at"], e["status"], e["sha256"]])
    elif entity == "artifacts":
        writer.writerow(["id","evidence_id","category","name","value","severity","timestamp","artifact_hash"])
        for a in bundle["artifacts"]:
            writer.writerow([a["id"], a["evidence_id"], a["category"], a["name"], a["value"],
                             a["severity"], a["timestamp"] or "", a["artifact_hash"]])
    else:
        writer.writerow(["id","evidence_id","event_type","from_user","to_user","from_location","to_location","occurred_at"])
        for c in bundle["custody"]:
            writer.writerow([c["id"], c["evidence_id"], c["event_type"], c["from_user"], c["to_user"],
                             c["from_location"], c["to_location"], c["occurred_at"]])
    return buf.getvalue().encode("utf-8")


def audit_xml(app, limit=5000):
    root = ET.Element("audit_pack")
    root.set("generated", datetime.utcnow().isoformat() + "Z")
    root.set("framework", "ISO 27001:2022 / NIST SP 800-53 AU-2 / OWASP A09")
    rows = query("SELECT * FROM audit_events ORDER BY id ASC LIMIT ?", (limit,))
    for r in rows:
        el = ET.SubElement(root, "event")
        for k in ("id", "ts", "actor_id", "actor_role", "action", "subject_type",
                  "subject_id", "context", "severity", "prev_hash", "hash"):
            ET.SubElement(el, k).text = str(r[k])
    xml = ET.tostring(root, encoding="unicode", xml_declaration=False)
    body = '<?xml version="1.0" encoding="UTF-8"?>\n' + xml
    return body.encode("utf-8")


def _esc(text):
    from markupsafe import escape
    return escape(text)


def _canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)