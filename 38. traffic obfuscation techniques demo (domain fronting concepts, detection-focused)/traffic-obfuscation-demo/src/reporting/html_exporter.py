"""HTML exporter - self-contained, branded, printable report page."""

from __future__ import annotations

import html
from pathlib import Path

from src.reporting.bundle import ReportBundle

CSS = """
:root{--ink:#251b37;--accent:#6c5ce7;--accent2:#a29bfe;--gold:#fdcb6e;
--cyan:#74b9ff;--green:#00b894;--red:#e17055;--panel:#ffffff;--bg:#f4f7fb;
--muted:#6c7a89;--line:#e8eef6;}
*{box-sizing:border-box}
body{margin:0;font-family:'Segoe UI',system-ui,sans-serif;background:
linear-gradient(160deg,#f4f7fb 0%,#eef1fb 40%,#fbf6ef 100%);color:var(--ink)}
.wrap{max-width:1180px;margin:0 auto;padding:32px 20px 80px}
.hero{background:linear-gradient(120deg,#251b37,#4b3f9e 55%,#6c5ce7);
color:#fff;border-radius:22px;padding:34px 40px;box-shadow:0 18px 45px rgba(37,27,55,.28);
position:relative;overflow:hidden}
.hero:after{content:'';position:absolute;right:-70px;top:-70px;width:240px;height:240px;
border-radius:50%;background:radial-gradient(circle,rgba(253,203,110,.55),transparent 70%)}
.hero h1{margin:0;font-size:30px;letter-spacing:.4px}
.hero p{margin:8px 0 0;opacity:.85;font-size:14px}
.badges{display:flex;gap:8px;margin-top:18px;flex-wrap:wrap}
.badge{background:rgba(255,255,255,.14);border:1px solid rgba(255,255,255,.35);
padding:5px 12px;border-radius:999px;font-size:12px;font-weight:600}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-top:22px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:18px 20px;
box-shadow:0 6px 18px rgba(37,27,55,.06)}
.card h3{margin:0 0 4px;font-size:13px;text-transform:uppercase;letter-spacing:1px;color:var(--muted)}
.card .big{font-size:30px;font-weight:800;color:var(--accent)}
.card .sub{font-size:12px;color:var(--muted)}
h2{margin:34px 0 14px;font-size:19px;color:var(--ink);border-bottom:3px solid var(--line);
padding-bottom:8px}
table{width:100%;border-collapse:collapse;background:var(--panel);border-radius:12px;
overflow:hidden;box-shadow:0 6px 18px rgba(37,27,55,.06)}
th{background:var(--accent);color:#fff;text-align:left;padding:10px 12px;font-size:12.5px}
td{padding:9px 12px;border-top:1px solid var(--line);font-size:13px;vertical-align:top}
tr:nth-child(even) td{background:#fafbff}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;color:#fff;font-size:11.5px;
font-weight:700}
.pill.critical{background:var(--red)} .pill.high{background:#e17055}
.pill.medium{background:#f39c12} .pill.low{background:var(--cyan)}
.pill.info{background:#b2bec3}
.pill.benign{background:var(--green)} .pill.suspicious{background:#e17055}
.pill.fronted{background:var(--red)}
.scorebar{height:8px;border-radius:6px;background:#edf0f6;overflow:hidden;min-width:60px}
.scorebar i{display:block;height:100%;border-radius:6px}
.fw{cursor:default}
.fw .chip{display:inline-block;background:var(--accent2);color:#fff;border-radius:6px;
padding:2px 8px;font-size:11px;margin:2px;font-weight:700}
.io{font-size:11px;color:var(--muted)}
footer{margin-top:40px;color:var(--muted);font-size:12px;text-align:center}
"""


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def _verdict_hash(label: str) -> str:
    return {"benign": "green", "suspicious": "orange", "fronted": "red"}.get(label, "muted")


def export_html(bundle: ReportBundle, out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # stat cards
    fronted = [v for v in bundle.verdicts if v.label.value == "fronted"]
    susp = [v for v in bundle.verdicts if v.label.value == "suspicious"]
    high = [f for f in bundle.findings if f.severity.value in ("high", "critical")]

    cards = [
        ("Flows analysed", str(len(bundle.verdicts)), "sessions / TLS records"),
        ("Fronted detected", str(len(fronted)), "verdict = fronted"),
        ("Suspicious flows", str(len(susp)), "verdict = suspicious"),
        ("High/Critical findings", str(len(high)), "needs review"),
    ]

    # verdicts table
    verdict_rows = ""
    for v in bundle.verdicts:
        fw = {f.record_id: f for f in bundle.findings}
        refs = sorted({r for f in bundle.findings if f.record_id == v.record_id for r in f.refs})
        verdict_rows += (
            f"<tr><td>{_esc(v.record_id)}</td>"
            f"<td>{_esc(v.scenario)}</td>"
            f"<td><code>{_esc(v.sni)}</code></td>"
            f"<td><code>{_esc(v.host_header)}</code></td>"
            f"<td>{_esc(v.dest_ip)}</td>"
            f"<td>{_esc(v.cdn_owner) or '—'}</td>"
            f"<td><div class='scorebar'><i style='width:{v.score}%;background:{ {0:'#00b894',1:'#f39c12',2:'#e17055'}.get(v.score//40, '#6c5ce7') }'></i></div></td>"
            f"<td><span class='pill {_verdict_hash(v.label.value)}'>{v.label.value}</span></td>"
            f"<td>{_esc(', '.join(refs) or '—')}</td></tr>"
        )

    # findings table
    finding_rows = ""
    for f in bundle.findings:
        finding_rows += (
            f"<tr><td>{_esc(f.record_id.split('-')[0])}</td>"
            f"<td>{_esc(f.finding_id)}</td>"
            f"<td><span class='pill {f.severity.value}'>{f.severity.value}</span></td>"
            f"<td>{_esc(f.title)}</td>"
            f"<td class='io'>{_esc(f.evidence)}</td>"
            f"<td><div class='fw'>{''.join(f'<span class=\'chip\'>{_esc(r)}</span>' for r in f.refs)}</div></td>"
            f"</tr>"
        )

    # framework table
    fw_rows = ""
    for fw, st in bundle.framework_stats.items():
        ratio = int(100 * st["relevant"] / max(1, st["total"]))
        fw_rows += (
            f"<tr><td><strong>{_esc(fw)}</strong></td>"
            f"<td>{st['total']}</td><td>{st['relevant']}</td>"
            f"<td><span class='pill benign'>{st['adopt']}</span></td>"
            f"<td><span class='pill medium'>{st['review']}</span></td>"
            f"<td><span class='pill low'>{st['monitoring']}</span></td>"
            f"<td><div class='scorebar'><i style='width:{ratio}%;background:#6c5ce7'></i></div></td>"
            f"</tr>"
        )

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_esc(bundle.project)} — Detection Report</title>
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
  <div class="hero">
    <h1>🛰 Traffic Obfuscation Techniques — Detection Report</h1>
    <p>Domain Fronting Concepts &nbsp;·&nbsp; Network-Focused Analysis &nbsp;·&nbsp;
       Version {_esc(bundle.version)} &nbsp;·&nbsp; Generated {_esc(bundle.generated_at)}</p>
    <div class="badges">
      <span class="badge">OWASP Top 10 (2021)</span>
      <span class="badge">NIST CSF 2.0</span>
      <span class="badge">ISO/IEC 27001:2022</span>
      <span class="badge">JA4-a-like Fingerprinting</span>
      <span class="badge">SNI / Host Mismatch</span>
    </div>
  </div>

  <div class="grid">
    {''.join(f"<div class='card'><h3>{_esc(t)}</h3><div class='big'>{_esc(v)}</div><div class='sub'>{_esc(s)}</div></div>" for t, v, s in cards)}
  </div>

  <h2>1 · Flow Verdicts (scoring 0–100)</h2>
  <table>
    <thead><tr>
      <th>Record</th><th>Scenario</th><th>SNI (front)</th><th>Host (origin)</th>
      <th>Dest IP</th><th>CDN</th><th>Score</th><th>Verdict</th><th>Framework refs</th>
    </tr></thead>
    <tbody>{verdict_rows}</tbody>
  </table>

  <h2>2 · Detection Findings</h2>
  <table>
    <thead><tr>
      <th>Flow</th><th>Finding</th><th>Severity</th><th>Title</th><th>Evidence</th><th>Mapped controls</th>
    </tr></thead>
    <tbody>{finding_rows}</tbody>
  </table>

  <h2>3 · Compliance Coverage (controls mapped)</h2>
  <table>
    <thead><tr>
      <th>Framework</th><th>Total</th><th>Relevant</th><th>Adopt</th><th>Review</th>
      <th>Monitoring</th><th>Coverage</th>
    </tr></thead>
    <tbody>{fw_rows}</tbody>
  </table>

  <footer>© 2026 Traffic Obfuscation Techniques Demo · educational lab only ·
  findings are heuristic indicators, not attribution.</footer>
</div>
</body>
</html>
"""
    out_path.write_text(page, encoding="utf-8")
    return out_path