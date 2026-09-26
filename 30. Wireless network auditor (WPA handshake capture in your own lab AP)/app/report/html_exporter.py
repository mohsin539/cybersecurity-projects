"""HTML report exporter - self-contained, colorful, XSS-safe, no external assets.
"""
import html
import os
from datetime import datetime, timezone

SEV_COLORS = {
    "Critical": ("#f85149", "#3d1513"),
    "High": ("#f0883e", "#3a2410"),
    "Medium": ("#93d50a", "#1e2a0b"),
    "Low": ("#f0b429", "#2c2308"),
    "Info": ("#8b949e", "#161b22"),
}

_SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]


def _esc(v):
    return html.escape(str(v), quote=True)


def _sev_color(sev):
    return SEV_COLORS.get(sev, SEV_COLORS["Info"])


def render(data) -> str:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    sev_totals = data.severity_totals()

    def sev_bar():
        total = max(1, sum(sev_totals.values()))
        bars = []
        for sev in _SEV_ORDER:
            cnt = sev_totals.get(sev, 0)
            fg, bg = _sev_color(sev)
            pct = 100 * cnt / total
            bars.append(
                f'<div class="sev" style="background:{bg};border:1px solid {fg}55;">'
                f'<span style="color:{fg};font-weight:700">{sev.title()}</span>'
                f'<b style="color:{fg}">{cnt}</b>'
                f'<div class="sevbar"><div style="width:{pct:.0f}%;background:{fg}"></div></div>'
                f"</div>"
            )
        return "".join(bars)

    ap_rows = "".join(
        f"<tr><td>{_esc(a['ssid'])}</td><td>{_esc(a['bssid'])}</td>"
        f"<td>{_esc(a['channel'])}</td><td>{_esc(a['cipher'])}</td></tr>"
        for a in data.aps
    )
    client_rows = "".join(
        f"<tr><td>{_esc(c['mac'])}</td><td>{_esc(c['bssid'])}</td></tr>"
        for c in data.clients[:50]
    )
    hs_rows = "".join(
        f"<tr>{'<td style=\"background:#1f6feb33\">&nbsp;</td>' if s['complete'] else '<td></td>'} "
        f"<td>{_esc(s['client'])}</td><td>{_esc(s['bssid'])}</td>"
        f"<td>{_esc(s['msgs'])}</td><td>{_esc(s['started'])}</td></tr>"
        for s in data.sessions
    )
    finding_rows = "".join(
        '<tr>'
        f'<td><span class="pill" style="background:{_sev_color(f["severity"])[1]};'
        f'color:{_sev_color(f["severity"])[0]}">{_esc(f["severity"])}</span></td>'
        f"<td>{_esc(f['title'])}</td><td>{_esc(f['bssid'])}</td>"
        f"<td>{_esc(f['detail'])}</td><td>{_esc(f['ts'])}</td></tr>"
        for f in data.findings
    )
    audit_rows = "".join(
        f"<tr><td>{_esc(a['ts'])}</td><td>{_esc(a['action'])}</td><td>{_esc(a['detail'])}</td></tr>"
        for a in data.audit
    )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Wireless Network Auditor - Report</title>
<style>
:root{{--bg:#0d1117;--panel:#161b22;--border:#30363d;--text:#e6edf3;--muted:#8b949e;
--cyan:#39d5ff;--green:#3fb950;--amber:#f0b429;--red:#f85149;--purple:#bc8cff;--blue:#58a6ff;}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;padding:24px}}
.wrap{{max-width:980px;margin:0 auto}}
h1{{font-size:26px;background:linear-gradient(90deg,var(--cyan),var(--blue));-webkit-background-clip:text;background-clip:text;color:transparent}}
h2{{font-size:18px;margin:26px 0 10px;color:var(--cyan);border-bottom:1px solid var(--border);padding-bottom:6px}}
p,td,th{{font-size:13px}}
.mut{{color:var(--muted)}}
table{{width:100%;border-collapse:collapse;background:var(--panel);border-radius:10px;overflow:hidden;margin:10px 0}}
th{{text-align:left;padding:9px 11px;background:#1c2333;color:var(--muted);font-size:11px;text-transform:uppercase}}
td{{padding:8px 11px;border-top:1px solid var(--border)}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:16px 0}}
.kpi{{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:14px}}
.kpi b{{font-size:26px;display:block;background:linear-gradient(90deg,var(--green),var(--teal,var(--cyan)));-webkit-background-clip:text;background-clip:text;color:transparent}}
.kpi span{{color:var(--muted);font-size:12px}}
.sev{{border-radius:10px;padding:10px 12px;margin:8px 0;display:flex;align-items:center;gap:12px}}
.sev span{{width:90px}} .sev b{{min-width:28px}}
.sevbar{{flex:1;height:8px;background:#0d1117;border-radius:5px;overflow:hidden}}
.sevbar>div{{height:100%;border-radius:5px}}
.pill{{padding:2px 10px;border-radius:20px;font-size:11px;font-weight:700}}
code{{background:#0b0f14;border:1px solid var(--border);padding:1px 6px;border-radius:5px;color:var(--purple)}}
.foot{{margin-top:36px;padding-top:14px;border-top:1px solid var(--border);color:var(--muted);font-size:11px}}
.chain{{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:12px;font-family:monospace;font-size:11px;color:var(--green);word-break:break-all}}
</style></head><body><div class="wrap">
<h1>📡 Wireless Network Auditor — Audit Report</h1>
<p class="mut">Generated {_esc(now)} · App {_esc(data.app_version)} · backend {_esc(data.backend)} · Scope: lab AP only</p>

<h2>Executive Summary</h2>
<div class="kpis">
<div class="kpi"><b>{data.stats['aps']}</b><span>Lab APs</span></div>
<div class="kpi"><b>{data.stats['clients']}</b><span>Clients seen</span></div>
<div class="kpi"><b>{data.stats['sessions']}</b><span>EAPOL sessions</span></div>
<div class="kpi"><b>{data.stats['complete']}</b><span>Complete 4-way</span></div>
<div class="kpi"><b>{data.stats['findings']}</b><span>Findings</span></div>
</div>
{sev_bar()}

<h2>Access Points</h2>
<table><tr><th>SSID</th><th>BSSID</th><th>Channel</th><th>Cipher</th></tr>{ap_rows}</table>

<h2>Clients</h2>
<table><tr><th>MAC</th><th>Associated BSSID</th></tr>{client_rows}</table>

<h2>WPA Handshake Sessions (EAPOL)</h2>
<table><tr><th>Complete</th><th>Client</th><th>AP BSSID</th><th>Msgs</th><th>Started</th></tr>{hs_rows}</table>

<h2>Findings</h2>
<table><tr><th>Severity</th><th>Title</th><th>BSSID</th><th>Detail</th><th>Time</th></tr>{finding_rows}</table>

<h2>Audit Trail</h2>
<table><tr><th>Time</th><th>Action</th><th>Detail</th></tr>{audit_rows}</table>

<h2>Evidence Integrity</h2>
<p>Tamper-evident hash chain — {data.chain.get('length',0)} records</p>
<div class="chain">head: {_esc(data.chain.get('head',''))}</div>

<div class="foot">Authorized lab use only · OWASP Top 10 · ISO 27001:2022 · NIST CSF 2.0 aligned ·
Report digest captured at {_esc(now)}</div>
</div></body></html>"""


def export(data, path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render(data))
    return path