"""Dark-mode .HTML dashboard export (architecture section 6).

Self-contained HTML (inline CSS + canvas chart, zero network calls) so the
report renders offline and prints cleanly to PDF via the browser.
"""

from __future__ import annotations

import html
import time as _time
from string import Template
from pathlib import Path

_TEMPLATE = Template("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>C2 Detection Lab - Report ${run_id}</title>
<style>
  :root{--bg0:#070b16;--bg1:#0d1330;--ser:#0ff;--zk:#7c4dff;--sc:#ff6b2c;
        --gui:#ff2d78;--rpt:#22d3a8;--cmp:#ffd93b;--txt:#dfe7ff;--mut:#8fa3c8;}
  *{box-sizing:border-box;margin:0;padding:0;}
  body{font-family:'Segoe UI',system-ui,Roboto,sans-serif;color:var(--txt);
    background:linear-gradient(160deg,var(--bg0),var(--bg1));padding:26px;min-height:100vh;}
  .wrap{max-width:1080px;margin:0 auto;}
  h1{font-size:1.5rem;background:linear-gradient(90deg,#7df9ff,#b794ff,#ff7eb0);
    -webkit-background-clip:text;background-clip:text;color:transparent;margin-bottom:6px;}
  .sub{color:var(--mut);font-size:.85rem;margin-bottom:18px;}
  .kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px;}
  .kpi{background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);
    border-radius:12px;padding:14px;text-align:center;}
  .kpi b{display:block;font-size:1.5rem;color:var(--rpt);}
  .kpi span{font-size:.72rem;color:var(--mut);letter-spacing:.4px;text-transform:uppercase;}
  h2{font-size:1rem;margin:24px 0 10px;color:var(--ser);border-bottom:1px solid rgba(0,255,255,.3);padding-bottom:6px;}
  table{width:100%;border-collapse:collapse;font-size:.8rem;}
  th,td{padding:8px 10px;text-align:left;border-bottom:1px solid rgba(255,255,255,.09);}
  th{background:rgba(255,255,255,.06);color:#fff;}
  .sev-high,.sev-critical{color:#ffab7d;}
  .sev-med{color:#ffe27a;}
  .pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:.68rem;font-weight:700;
    background:rgba(124,77,255,.18);color:#c9a4ff;}
  .ok{color:var(--rpt);}
  .foot{margin-top:30px;text-align:center;color:var(--mut);font-size:.72rem;}
</style>
</head>
<body><div class="wrap">

<h1>&#128752; C2 Detection Lab &mdash; Evidence Report</h1>
<div class="sub">Run <b>${run_id}</b> &middot; generated ${generated} UTC &middot;
channel ${channel} &middot; ${agents} agent(s)</div>

<div class="kpis">
  <div class="kpi"><b>${precision}</b><span>Precision</span></div>
  <div class="kpi"><b>${recall}</b><span>Recall</span></div>
  <div class="kpi"><b>${f1}</b><span>F1-Score</span></div>
  <div class="kpi"><b>${alerts}</b><span>Alerts</span></div>
  <div class="kpi"><b>${c2_events}</b><span>C2 Events</span></div>
  <div class="kpi"><b>${benign_events}</b><span>Benign Events</span></div>
</div>

<h2>Detector Breakdown (Zeek vs Suricata)</h2>
<canvas id="chart" width="900" height="220"></canvas>

<h2>Detections (${det_count})</h2>
<table><tr><th>TS (UTC)</th><th>Detector</th><th>Severity</th><th>Score</th>
<th>Src</th><th>Dst</th><th>Rule</th><th>MITRE</th></tr>
${rows}
</table>

<h2>Compliance Scorecard</h2>
<table><tr><th>Framework</th><th>Control</th><th>Topic</th><th>Status</th></tr>
${compliance_rows}
</table>

<div class="foot">C2 Detection Lab &middot; Zeek + Suricata signatures that catch it &middot;
ISO 27001 &middot; NIST CSF 2.0 &middot; NIST 800-53 &middot; OWASP Top 10</div>

<script>
const ctx=document.getElementById('chart').getContext('2d');
const zeek=${zeek_hits}, suri=${suri_hits};
const w=ctx.canvas.width,h=ctx.canvas.height,pad=60,max=Math.max(zeek,suri,1);
ctx.fillStyle='#0d1330';ctx.fillRect(0,0,w,h);
const bw=(w-2*pad-80)/2,bh=140;
const bars=[[zeek,'#7c4dff'],[suri,'#ff6b2c']],labels=['Zeek','Suricata'];
for(let i=0;i<2;i++){
  const x=pad+i*(bw+80),hgt=Math.round(bh*bars[i][0]/max);
  ctx.fillStyle=bars[i][1];
  ctx.fillRect(x,h-40-hgt,bw,hgt);
  ctx.fillStyle='#dfe7ff';ctx.font='14px Segoe UI';
  ctx.fillText(labels[i],x, h-hgt-46);
  ctx.fillText(bars[i][0],x,h-24);
}
</script>
</div></body></html>
""")


def _sev(c: str) -> str:
    cls = "sev-high" if c in ("high", "critical") else "sev-med"
    return f'<span class="{cls}">{html.escape(c)}</span>'


def write_html(run_result: dict, path: str | Path) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    m = run_result["metrics"]
    alerts = run_result["alerts"]

    if not alerts:
        alerts = [{"ts_iso": "-", "detector": "none", "severity": "-", "score": "-",
                   "src_ip": "-", "dst_ip": "-", "rule_id": "-", "mitre_technique": "-"}]

    rows = "\n".join(
        f"<tr><td>{html.escape(str(a['ts_iso']))}</td>"
        f"<td>{html.escape(a['detector'])}</td>"
        f"<td>{_sev(str(a['severity']))}</td>"
        f"<td>{a['score']}</td>"
        f"<td>{html.escape(str(a['src_ip']))}</td>"
        f"<td>{html.escape(str(a['dst_ip']))}</td>"
        f"<td>{html.escape(str(a['rule_id']))}</td>"
        f"<td><span class='pill'>{html.escape(str(a['mitre_technique']))}</span></td></tr>"
        for a in alerts)

    from core.compliance import COMPLIANCE_MATRIX
    comp = "\n".join(
        f"<tr><td>{html.escape(c['framework'])}</td><td>{html.escape(c['control'])}</td>"
        f"<td>{html.escape(c['topic'])}</td>"
        f"<td class='ok'>{html.escape(c['status'])}</td></tr>"
        for c in COMPLIANCE_MATRIX)

    out.write_text(_TEMPLATE.substitute(
        run_id=html.escape(run_result["run_id"]),
        generated=_time.strftime("%Y-%m-%d %H:%M:%S", _time.gmtime()),
        channel=run_result["config"]["channel"],
        agents=run_result["config"]["agent_count"],
        precision=m["precision"], recall=m["recall"], f1=m["f1"],
        alerts=m["alerts"], c2_events=m["c2_events"], benign_events=m["benign_events"],
        det_count=len(run_result["alerts"]),
        zeek_hits=m["zeek_detections"], suri_hits=m["suricata_detections"],
        rows=rows, compliance_rows=comp,
    ), encoding="utf-8")
    return out