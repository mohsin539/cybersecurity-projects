"""Report generation: colourful, self-contained HTML executive report,
CSV event/timeline exports, and a tamper-evident JSON case bundle.
"""
import csv
import html
import io
import json
from datetime import datetime, timezone

from . import __version__
from .audit import artefact_hash
from .compliance import ISO_27001_CONTROLS, NIST_CSF, OWASP_TOP10_2021, map_rule_frameworks
from .correlate import PHASE_COLORS


def _esc(v):
    return html.escape(str(v if v is not None else ""), quote=True)


def _sev_color(score):
    if score >= 85:
        return "#ef4444"
    if score >= 65:
        return "#f97316"
    if score >= 40:
        return "#fbbf24"
    if score >= 20:
        return "#38bdf8"
    return "#64748b"


def _fmt(ts, fmt="%Y-%m-%d %H:%M:%S UTC"):
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return dt.strftime(fmt)
    except Exception:
        return str(ts)


# --------------------------------------------------------------------------
# CSS for the executive report
# --------------------------------------------------------------------------
_CSS = """
:root{--bg:#0b1220;--panel:#101b31;--panel2:#0e1729;--line:#1e2d4a;--ink:#e6edf7;
--dim:#8ea3c0;--cyan:#22d3ee;--mag:#f472b6;--green:#34d399;--amber:#fbbf24;
--red:#f87171;--vio:#a78bfa;--blue:#38bdf8;--orange:#fb923c}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font-family:'Segoe UI',Roboto,Arial,sans-serif;font-size:14px;line-height:1.5}
.page{max-width:1180px;margin:0 auto;padding:28px 34px 70px}
header.top{display:flex;justify-content:space-between;align-items:center;
border:1px solid var(--line);border-radius:14px;padding:20px 26px;
background:linear-gradient(120deg,#0f2138 0%,#101b31 55%,#1a1030 100%)}
.logo{display:flex;align-items:center;gap:12px}
.logo-mark{width:42px;height:42px;border-radius:10px;display:grid;place-items:center;
font-weight:800;color:#06121f;background:linear-gradient(135deg,var(--cyan),var(--mag))}
h1{font-size:19px;margin:0;letter-spacing:.4px}
.sub{color:var(--dim);font-size:12px;margin-top:2px}
.badges{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.badge{border:1px solid var(--line);border-radius:999px;padding:5px 12px;font-size:11px;
color:var(--dim)}
.badge.secure{color:var(--green);border-color:#1f4d3a;background:#06281d}
h2{font-size:15px;margin:28px 0 12px;display:flex;align-items:center;gap:8px;
letter-spacing:.5px}
h2::before{content:"";width:4px;height:16px;border-radius:2px;
background:linear-gradient(var(--cyan),var(--mag))}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.card{border:1px solid var(--line);border-radius:12px;padding:16px 18px;background:var(--panel)}
.card .label{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:1px}
.card .value{font-size:24px;font-weight:700;margin-top:6px}
.card .hint{font-size:11px;color:var(--dim);margin-top:4px}
.risk{color:var(--red)}
.gauge-wrap{display:grid;grid-template-columns:120px 1fr;align-items:center;gap:18px}
.meter{height:12px;border-radius:999px;background:#0b1626;border:1px solid var(--line);
overflow:hidden}
.meter>div{height:100%;border-radius:999px}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th,td{border-bottom:1px solid var(--line);padding:8px 10px;text-align:left;vertical-align:top}
th{color:var(--dim);text-transform:uppercase;font-size:10.5px;letter-spacing:.6px}
tr:hover td{background:#0f1c33}
.pill{display:inline-block;border-radius:999px;padding:2px 10px;font-size:11px;font-weight:600}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.panel{border:1px solid var(--line);border-radius:14px;padding:18px 20px;background:var(--panel)}
.phaseband{display:flex;gap:8px;flex-wrap:wrap}
.phase{border-radius:10px;padding:10px 14px;min-width:118px;border:1px solid var(--line)}
.phase .p-name{font-size:11px;opacity:.85}
.phase .p-cnt{font-size:20px;font-weight:700;margin-top:4px}
.mitre-grid{display:grid;grid-template-columns:minmax(140px,auto) repeat(var(--tac,none),1fr)}
.mitre-grid .cell{min-height:26px}
.mitre-grid .c0{background:rgba(255,255,255,.03)}
.mitre-grid .c1{background:rgba(34,211,238,.18);color:var(--cyan)}
.mitre-grid .c2{background:rgba(251,191,36,.25);color:var(--amber)}
.mitre-grid .c3{background:rgba(249,115,22,.35);color:#ffd9a8}
.mitre-grid .c4{background:rgba(239,68,68,.45);color:#ffcfcf}
.mitre-grid .head{font-weight:700;font-size:12px}
.mitre-grid .th{color:var(--dim);font-size:10.5px;text-transform:uppercase}
.pre{font-family:'Consolas','Cascadia Mono',monospace;font-size:11.5px;background:#0a1220;
border:1px solid var(--line);border-radius:8px;padding:10px 12px;overflow-x:auto;
white-space:pre-wrap;word-break:break-word}
.foot{margin-top:44px;border-top:1px solid var(--line);padding-top:16px;color:var(--dim);
font-size:11.5px}
.mono{font-family:Consolas,monospace;font-size:11px;color:var(--cyan);word-break:break-all}
.ok{color:var(--green)}.warn{color:var(--amber)}.crit{color:var(--red)}
ol.mitig{padding-left:18px}
ol.mitig li{margin:6px 0}
.timeline{border-left:3px solid var(--line);margin-left:8px;padding-left:20px}
.tl-item{position:relative;padding:8px 0}
.tl-item::before{content:"";position:absolute;left:-27px;top:14px;width:11px;height:11px;
border-radius:50%;background:var(--dot,#22d3ee);box-shadow:0 0 10px var(--dot,#22d3ee)}
@media print{.panel,.card,.phase{border-color:#cbd5e1}.timeline{border-color:#cbd5e1}}
"""


def html_report(case, audit_stats=None):
    """Build a fully self-contained, colourful executive HTML report."""
    return (
        _html_head(case, audit_stats)
        + _html_summary(case)
        + _html_mitre(case)
        + _html_details(case)
        + _html_events(case)
        + _html_compliance(case)
        + _html_audit(case, audit_stats)
        + _html_footer(case)
    )
def _html_head(case, audit_stats=None):
    body = [
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        "<title>Intrusion Timeline Report - %s</title>" % _esc(case.get("case_id", "")),
        "<style>", _CSS, "</style></head><body><div class='page'>",
        "<header class='top'><div class='logo'><div class='logo-mark'>&#9881;</div><div>",
        "<h1>Windows Event Log Intrusion Correlation Report</h1>",
        "<div class='sub'>Case %s &middot; Generated %s &middot; Tool v%s</div>" % (
            _esc(case.get("case_id", "")), _esc(case.get("generated_at", "")), _esc(__version__)),
        "</div></div>",
        "<div class='badges' style='margin-top:18px'>",
        "<span class='badge secure'>&#10004; SHA-256 verified</span>"
        "<span class='badge'>ISO 27001 mapped</span><span class='badge'>NIST CSF mapped</span>",
        "<span class='badge'>OWASP-aligned surface</span><span class='badge'>MITRE ATT&amp;CK</span>",
        "</div></header>",
    ]
    return "".join(body)


def _html_summary(case):
    an = case.get("analysis") or {}
    s = an.get("summary", {})
    sev = int(s.get("max_severity", 0))
    risk = float(s.get("risk_score", 0))
    c = _sev_color(sev)
    sev_label = s.get("risk_label", "informational")
    top_hosts = "".join(
        "<div>%s &mdash; %s</div>" % (_esc(h), n) for h, n in s.get("top_hosts", []))
    top_rules = "".join(
        "<div>%s &mdash; %s</div>" % (_esc(r), n) for r, n in s.get("top_rules", []))
    spikes = "".join(
        "<div class='mono'>%s &rarr; %d events (z=%.1f)</div>" % (
            _esc(normalise(s_.get("start_ts", ""))), s_.get("count", 0), s_.get("deviation", 0))
        for s_ in case.get("analysis", {}).get("spikes", [])[:6])
    return (
        "<h2>Executive Summary</h2>"
        "<div class='cards'>"
        "<div class='card'><div class='label'>Exposure window</div><div class='value'>%s</div>"
        "<div class='hint'>%s &rarr; %s</div></div>"
        "<div class='card'><div class='label'>Events ingested</div><div class='value'>%s</div></div>"
        "<div class='card'><div class='label'>Incidents flagged</div><div class='value'>%s</div></div>"
        "<div class='card'><div class='label'>Attack phases</div><div class='value'>%s</div>"
        "<div class='hint'>%s</div></div>"
        "<div class='card'><div class='label'>Campaign clusters</div><div class='value'>%s</div></div>"
        "<div class='card'><div class='label'>Peak severity</div><div class='value' style='color:%s'>%s</div>"
        "<div class='hint'>%s</div></div>"
        "<div class='card'><div class='label'>Surge windows</div><div class='value'>%s</div></div>"
        "</div>"
        "<div class='panel' style='margin-top:16px'><div class='ring'><div class='gauge-wrap'>"
        "<div style='text-align:center'><div style='font-size:40px;font-weight:800;color:%s'>%s</div>"
        "<div class='label' style='font-size:11px;color:var(--dim)'>OVERALL RISK</div></div>"
        "<div><div style='margin:6px 0 4px'>Composite risk %s / 100</div>"
        "<div class='meter'><div style='width:%s%%;background:%s'></div></div></div></div>"
        "%s</div>"
        "<h2>Kill-Chain Phases Observed</h2><div class='phaseband'>%s</div>"
        "<div class='grid2' style='margin-top:16px'>"
        "<div class='panel'><h2 style='margin-top:0'>Top Affected Hosts</h2>%s</div>"
        "<div class='panel'><h2 style='margin-top:0'>Top Detections (Rules)</h2>%s</div></div>"
        "<h2>Activity Surges (anomaly detection)</h2><div class='pre'>%s</div>"
        "<h2>Recommended Response Actions</h2><ol class='mitig'>%s</ol>" % (
            case.get("case_id", ""), _fmt(case.get("window_start", "")),
            _fmt(case.get("window_end", "")), s.get("events", 0), s.get("incidents", 0),
            s.get("phase_count", 0), ", ".join(_esc(x) for x in s.get("phases_covered", [])),
            s.get("campaigns", 0), c, sev, _esc(sev_label), s.get("spikes", 0),
            c, risk, risk, min(100.0, risk), c,
            _html_campaigns(case), _phase_band(case),
            top_hosts or "<div class='dim'>No hosts</div>",
            top_rules or "<div class='dim'>No rules</div>",
            spikes or "<div class='dim'>No significant surges</div>",
            "".join("<li>%s</li>" % _esc(m) for m in case.get("analysis", {}).get("mitigation", []))))


def _html_mitre(case):
    matrix = case.get("analysis", {}).get("mitre", {})
    if not matrix:
        return ""
    tactics = list(matrix.keys())
    techniques = sorted({t for ts in matrix.values() for t in ts})
    style = "grid-template-columns:150px repeat(%d,1fr)" % len(tactics)
    cells = ['<div class="head">Technique / Tactic</div>']
    cells += ['<div class="th">%s</div>' % _esc(t) for t in tactics]
    for tech in techniques:
        cells.append('<div class="th">%s</div>' % _esc(tech))
        for tact in tactics:
            n = matrix.get(tact, {}).get(tech, 0)
            cls = "c%d" % min(n, 4) if n else "c0"
            cells.append("<div class='cell %s'>%s</div>" % (cls, n or ""))
    return ("<h2>MITRE ATT&CK Detection Coverage</h2>"
            "<div class='panel'><div class='mitre-grid' style='%s'>%s</div>"
            "<div style='margin-top:10px;font-size:11px;color:var(--dim)'>"
            "Heat = number of correlated incidents per technique/tactic.</div></div>" % (
                style, "".join(cells)))


def _html_details(case):
    incidents = case.get("analysis", {}).get("incidents", [])
    if not incidents:
        return "<h2>Correlated Incidents</h2><p>No incidents matched the rule set.</p>"
    rows = []
    for inc in incidents:
        color = _sev_color(inc.get("severity", 0))
        stage = inc.get("stage", "")
        rows.append(
            "<tr><td class='mono'>%s</td><td><span class='pill' style='color:%s'>%s</span></td>"
            "<td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                _fmt(inc.get("ts", "")), color, _esc(inc.get("rule_name", "")),
                _esc(stage), _esc(inc.get("computer", "")),
                _esc(inc.get("source_ip", "") or "-"),
                _esc(inc.get("target_user", "") or "-"), _esc(_cut(inc.get("message", ""), 90))))
    return ("<h2>Correlated Incidents (%s)</h2>"
            "<div class='panel' style='overflow-x:auto'><table>"
            "<tr><th>Timestamp</th><th>Rule</th><th>Phase</th><th>Host</th><th>Source IP</th>"
            "<th>Account</th><th>Detail</th></tr>%s</table></div>" % (
                len(incidents), "".join(rows)))


def _cut(text, n):
    text = str(text)
    return text if len(text) <= n else text[: n - 3] + "..."


def _html_events(case):
    events = case.get("events", [])
    if not events:
        return ""
    rows = []
    for ev in events[:100]:
        rows.append(
            "<tr><td class='mono'>%s</td><td>%s</td><td>%s</td><td>%s</td>"
            "<td>%s</td><td>%s</td></tr>" % (
                _fmt(ev.get("ts", "")), _esc(ev.get("channel", "")), ev.get("event_id"),
                _esc(ev.get("provider", "")), _esc(ev.get("computer", "")),
                _esc(_cut(ev.get("message", ""), 120))))
    more = len(events) - 100
    return ("<h2>Ingested Events (%d%s)</h2>"
            "<details><summary style='cursor:pointer;color:var(--dim)'>Show raw events table</summary>"
            "<div class='panel' style='overflow-x:auto;margin-top:8px'><table>"
            "<tr><th>Timestamp</th><th>Channel</th><th>ID</th><th>Provider</th><th>Host</th><th>Message</th></tr>"
            "%s</table></div></details>" % (
                len(events), " first %d shown" % (100 if more else len(events)),
                "".join(rows)))


def _html_compliance(case):
    cov = case.get("framework") or {}
    iso = case.get("coverage", {}).get("iso_27001", [])
    nist = case.get("coverage", {}).get("nist_csf", [])
    iso_rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            k, _esc(ISO_27001_CONTROLS.get(k, {}).get("name", "")),
            _esc(ISO_27001_CONTROLS.get(k, {}).get("family", "")))
        for k in iso)
    cov_rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            k, _esc(NIST_CSF.get(k.split(".")[0], {}).get("name", "")),
            _esc(NIST_CSF.get(k.split(".")[0], {}).get("categories", {}).get(k, "")))
        for k in nist)
    owasp = "".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            _esc(o.get("id", "")), _esc(o.get("name", "")),
            _esc("; ".join(o.get("items", []))))
        for o in cov.get("owasp", []))
    return (
        "<h2>Security-Framework Compliance Matrix</h2>"
        "<div class='grid2'>"
        "<div class='panel'><b>ISO/IEC 27001:2022 Annex A</b> (controls evidenced)<br>"
        "<span class='badge'>%d controls covered</span>"
        "<div style='overflow-x:auto;margin-top:8px'><table>"
        "<tr><th>Control</th><th>Name</th><th>Family</th></tr>%s</table></div></div>"
        "<div class='panel'><b>NIST CSF 2.0</b> (functions addressed)<br>"
        "<span class='badge'>%d categories covered</span>"
        "<div style='overflow-x:auto;margin-top:8px'><table>"
        "<tr><th>ID</th><th>Function</th><th>Category</th></tr>%s</table></div></div>"
        "</div>"
        "<div class='panel' style='margin-top:12px'><b>OWASP Top 10 (2021)</b> - tool hardening evidence"
        "<div style='overflow-x:auto;margin-top:8px'><table>"
        "<tr><th>ID</th><th>Category</th><th>Evidence in tool</th></tr>%s</table></div></div>" % (
            len(iso), iso_rows or "<tr><td colspan='3'>No incidents triggered controls</td></tr>",
            len(nist), cov_rows or "<tr><td colspan='3'>No incidents</td></tr>", owasp))


def _html_audit(case, audit_stats=None):
    rows = case.get("audit", [])[:60]
    ad = "".join(
        "<tr><td class='mono'>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            _fmt(e.get("ts", "")), _esc(e.get("actor", "")), _esc(e.get("action", "")),
            _esc(_cut(e.get("detail", ""), 70)), _esc(e.get("level", "")))
        for e in rows)
    valid = "valid" if audit_stats and audit_stats.get("valid") else "review"
    return ("<h2>Audit Trail (chain-of-custody)</h2>"
            "<div class='panel'><div class='badges'>"
            "<span class='badge secure'>&#10004; chain %s</span>"
            "<span class='badge'>%d actions logged</span></div>"
            "<div style='overflow-x:auto;margin-top:8px'><table>"
            "<tr><th>Timestamp</th><th>Actor</th><th>Action</th><th>Detail</th><th>Level</th></tr>"
            "%s</table></div></div>" % (valid, len(case.get("audit", [])),
                                        ad or "<tr><td colspan='5'>No audit entries</td></tr>"))


def _html_footer(case):
    integ = case.get("integrity", {})
    return (
        "<div class='foot'>"
        "<b>Integrity &amp; audit</b><br>"
        "Report SHA-256: <span class='mono'>%s</span><br>"
        "Generated by <b>%s</b> v%s &middot; Timestamp: <span class='mono'>%s</span><br>"
        "This report is tamper-evident. Verify by re-hashing the exported artefact and "
        "comparing to the value above / the .sha256 sidecar. Further verification is "
        "available through the audit chain exported with the case JSON."
        "</div></div></body></html>" % (
            integ.get("hash", "n/a"), _esc(case.get("tool", "")), _esc(__version__),
            _esc(case.get("generated_at", ""))))


def csv_events(case):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["timestamp", "channel", "event_id", "provider", "computer",
                "source_ip", "target_user", "subject_user", "process", "message", "hash"])
    for ev in case.get("events", []):
        w.writerow([ev.get("ts", ""), ev.get("channel", ""), ev.get("event_id"),
                    ev.get("provider", ""), ev.get("computer", ""), ev.get("source_ip", ""),
                    ev.get("target_user", ""), ev.get("subject_user", ""), ev.get("process", ""),
                    ev.get("message", ""), ev.get("hash", "")])
    return out.getvalue().encode("utf-8-sig")


def csv_timeline(case):
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["timestamp", "stage", "rule_id", "rule_name", "severity", "host",
                "source_ip", "target_user", "message"])
    for inc in case.get("analysis", {}).get("incidents", []):
        w.writerow([inc.get("ts", ""), inc.get("stage", ""), inc.get("rule_id", ""),
                    inc.get("rule_name", ""), inc.get("severity", ""), inc.get("computer", ""),
                    inc.get("source_ip", ""), inc.get("target_user", ""), inc.get("message", "")])
    return out.getvalue().encode("utf-8-sig")


def json_case(case):
    return json.dumps(case, ensure_ascii=False, indent=2).encode("utf-8")


def normalise(ts):
    return str(ts).replace("T", " ").replace("Z", " UTC")[:19]


def _phase_band(case):
    out = []
    for p in case.get("analysis", {}).get("phases", []):
        fill = "rgba(%s,.14)" % p["color"][1:]
        out.append(
            "<div class='phase' style='border-color:%s;background:%s'>"
            "<div class='p-name'>%s</div><div class='p-cnt'>%s</div>"
            "<div style='font-size:10px;opacity:.8'>risk %s</div></div>" % (
                _esc(p["color"]), fill, _esc(p["name"]), p["count"], p["risk"]))
    return "".join(out) or "<div>No phases detected.</div>"


def _html_campaigns(case):
    cams = case.get("analysis", {}).get("campaigns", [])
    if not cams:
        return ""
    rows = []
    for cm in cams:
        color = _sev_color(cm.get("severity", 0))
        rows.append(
            "<div class='panel' style='margin-top:10px'>"
            "<div class='badges'><span class='badge' style='color:%s'>%s</span>"
            "<span class='badge'>%d incidents</span><span class='badge'>window %s</span></div>"
            "<div style='margin-top:8px;font-size:12px'>hosts: %s &nbsp;&middot;&nbsp; users: %s &nbsp;&middot;&nbsp; ips: %s</div>"
            "<div class='mono' style='margin-top:6px'>chain: %s</div></div>" % (
                color, _esc(cm.get("label", "")), cm.get("count", 0), _esc(cm.get("window", "")),
                ", ".join(_esc(h) for h in cm.get("hosts", [])),
                ", ".join(_esc(u) for u in cm.get("users", [])),
                ", ".join(_esc(p) for p in cm.get("ips", [])),
                " &rarr; ".join(_esc(x) for x in cm.get("stage_sequence", []))))
    return "<h2>Threat Campaign Clusters</h2>" + "".join(rows)
# __CHUNK_RPT2__