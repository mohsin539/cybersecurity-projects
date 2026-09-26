"""Human-readable compliance report generation (HTML + JSON)."""
from __future__ import annotations

import html
import json
import time

from . import __version__
from .model import now_iso

SEV_COLORS = {"low": "#3b82f6", "medium": "#f59e0b", "high": "#f97316", "critical": "#ef4444"}
VERDICT_EMOJI = {"PASS": "\u2705", "FAIL": "\u274c", "NA": "\u23f8\ufe0f"}


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def _status(d: dict) -> str:
    if d.get("status"):
        return d["status"]
    sc = d.get("scan")
    return sc.get("status", "PENDING") if sc else "PENDING"


def _status_badge(status: str) -> str:
    color = {"COMPLIANT": "#16a34a", "NON_COMPLIANT": "#dc2626", "PENDING": "#d97706", "ERROR": "#64748b"}.get(status, "#64748b")
    return f'<span style="background:{color};color:#fff;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:700">{_esc(status)}</span>'


def generate_html_report(state: dict, device_id: str = "") -> str:
    devices = state.get("devices", [])
    if device_id:
        devices = [d for d in devices if d["id"] == device_id]
    policy = state.get("policy", {})
    meta = state.get("meta", {})

    total = len(devices)
    compliant = sum(1 for d in devices if _status(d) == "COMPLIANT")
    non_comp = sum(1 for d in devices if _status(d) == "NON_COMPLIANT")
    pending = sum(1 for d in devices if _status(d) == "PENDING")

    rows = []
    for d in devices:
        scan = d.get("scan")
        status = _status(d)
        score = f"{scan['score']:.1f}%" if scan else "&ndash;"
        fails = scan["fail_count"] if scan else "&ndash;"
        last = scan["at"] if scan else "&ndash;"
        rows.append(
            f"<tr><td>{_esc(d['name'])}</td><td>{_esc(d['platform'].upper())}</td>"
            f"<td>{_esc(d['model'])}</td><td>{_esc(d.get('department',''))}</td>"
            f"<td>{_status_badge(status)}</td><td>{score}</td><td>{fails}</td><td>{_esc(last)}</td></tr>"
        )

    detail = ""
    if device_id and devices:
        d = devices[0]
        scan = d.get("scan")
        if scan:
            trs = []
            for r in scan["results"]:
                actual = _esc(r.get("actual"))
                expected = _esc(r.get("expected"))
                rem = _esc(r.get("remediation"))
                trs.append(
                    f"<tr><td>{_esc(r['label'])}<div style='color:#94a3b8;font-size:11px'>{_esc(r['rule_id'])} &middot; {r['severity'].upper()}</div></td>"
                    f"<td>{_esc(r.get('group'))}</td>"
                    f"<td>{VERDICT_EMOJI.get(r['verdict'],'')} {r['verdict']}</td>"
                    f"<td>{actual or '&ndash;'}</td><td>{expected or '&ndash;'}</td><td style='color:#94a3b8;font-size:12px'>{rem or '&ndash;'}</td></tr>"
                )
            detail = (
                f"<h2>Device Report &mdash; {_esc(d['name'])}</h2>"
                f"<p>{_status_badge(scan['status'])} &nbsp; Compliance score: <b>{scan['score']:.1f}%</b> &nbsp; "
                f"Pass: {scan['pass_count']} / Fail: {scan['fail_count']} / N/A: {scan['na_count']}</p>"
                f"<table><thead><tr><th>Rule</th><th>Group</th><th>Verdict</th><th>Actual</th><th>Expected</th><th>Remediation</th></tr></thead>"
                f"<tbody>{''.join(trs)}</tbody></table>"
            )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>MDM-Lite Compliance Report</title>
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: #0b1120; color: #e2e8f0; }}
  .wrap {{ max-width: 1080px; margin: 0 auto; padding: 32px 20px; }}
  header {{ border-bottom: 1px solid #1e293b; padding-bottom: 16px; margin-bottom: 24px;
           background: linear-gradient(90deg,#1d4ed8,#7c3aed); -webkit-background-clip: text; background-clip:text; color: transparent; }}
  header h1 {{ margin: 0; font-size: 26px; }}
  .sub {{ color: #94a3b8; font-size: 13px; }}
  .cards {{ display: flex; gap: 14px; flex-wrap: wrap; margin: 20px 0; }}
  .card {{ background:#111c33; border:1px solid #1e293b; border-radius: 14px; padding: 16px 20px; min-width: 150px; box-shadow: 0 4px 18px rgba(0,0,0,.35); }}
  .card .n {{ font-size: 28px; font-weight: 800; }}
  .card .l {{ color: #94a3b8; font-size: 12px; text-transform: uppercase; letter-spacing: .05em; }}
  .gn {{ color:#22c55e; }} .rn {{ color:#ef4444; }} .yn {{ color:#f59e0b; }} .bn {{ color:#3b82f6; }}
  table {{ width: 100%; border-collapse: collapse; background:#0f172a; border-radius: 12px; overflow: hidden; }}
  th, td {{ text-align: left; padding: 10px 12px; font-size: 13px; border-bottom: 1px solid #1e293b; }}
  th {{ background: #16233e; color: #cbd5e1; text-transform: uppercase; font-size: 11px; letter-spacing:.05em; }}
  tr:hover td {{ background: #131f38; }}
  footer {{ margin-top: 28px; color: #475569; font-size: 11px; }}
</style>
</head>
<body><div class="wrap">
<header>
  <h1>&#128241; MDM-Lite Device Compliance Report</h1>
  <div class="sub">Generated {_esc(now_iso())} &middot; App v{__version__} &middot; Policy {_esc(policy.get('name',''))} v{_esc(policy.get('version',''))} &middot; {_esc(meta.get('instanceId',''))}</div>
</header>
<div class="cards">
  <div class="card"><div class="n bn">{total}</div><div class="l">Enrolled devices</div></div>
  <div class="card"><div class="n gn">{compliant}</div><div class="l">Compliant</div></div>
  <div class="card"><div class="n rn">{non_comp}</div><div class="l">Non-compliant</div></div>
  <div class="card"><div class="n yn">{pending}</div><div class="l">Pending scan</div></div>
</div>
<table><thead><tr><th>Device</th><th>Platform</th><th>Model</th><th>Department</th><th>Status</th><th>Score</th><th>Failures</th><th>Last scan</th></tr></thead>
<tbody>{''.join(rows) if rows else '<tr><td colspan=8 style=text-align:center;color:#64748b>No enrolled devices.</td></tr>'}</tbody></table>
{detail}
<footer>Generated locally by the MDM-Lite Compliance Checker. No telemetry leaves this machine.</footer>
</div></body></html>"""


def generate_json_report(state: dict, device_id: str = "") -> dict:
    devices = state.get("devices", [])
    if device_id:
        devices = [d for d in devices if d["id"] == device_id]
    counts = {"total": len(devices),
              "compliant": sum(1 for d in devices if _status(d) == "COMPLIANT"),
              "nonCompliant": sum(1 for d in devices if _status(d) == "NON_COMPLIANT"),
              "pending": sum(1 for d in devices if _status(d) == "PENDING")}
    return {
        "generatedAt": now_iso(),
        "appVersion": __version__,
        "policy": {"name": state["policy"]["name"], "version": state["policy"]["version"]},
        "summary": counts,
        "devices": devices,
    }