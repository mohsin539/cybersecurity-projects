from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ..models import SEVERITY_ORDER, Severity, TimelineEvent

SEVERITY_COLORS = {
    "info": "#60a5fa",
    "low": "#34d399",
    "medium": "#fbbf24",
    "high": "#fb923c",
    "critical": "#f43f5e",
}

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>__TITLE__</title>
<style>
  :root {
    --bg: #070b18;
    --panel: #0f1730;
    --panel-2: #141d3a;
    --line: #22305c;
    --text: #e6ecff;
    --muted: #8ea0cc;
    --accent: #22d3ee;
    --accent-2: #a855f7;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: "Segoe UI", Roboto, Inter, system-ui, sans-serif;
    background:
      radial-gradient(1200px 600px at 10% -10%, rgba(34,211,238,.16), transparent 60%),
      radial-gradient(1000px 600px at 100% 0%, rgba(168,85,247,.16), transparent 55%),
      var(--bg);
    color: var(--text);
    padding: 28px 24px 80px;
  }
  header.hero {
    border-radius: 20px;
    padding: 26px 30px;
    background: linear-gradient(120deg, rgba(34,211,238,.18), rgba(168,85,247,.20));
    border: 1px solid var(--line);
    box-shadow: 0 20px 60px rgba(0,0,0,.45);
  }
  .hero h1 {
    margin: 0 0 6px;
    font-size: 30px;
    letter-spacing: .4px;
    background: linear-gradient(90deg, #22d3ee, #a855f7, #f472b6);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
  }
  .hero p { margin: 4px 0; color: var(--muted); font-size: 14px; }
  .pill {
    display: inline-block; padding: 4px 12px; border-radius: 999px;
    font-size: 12px; font-weight: 600; margin-right: 8px;
    border: 1px solid var(--line); background: rgba(255,255,255,.04);
  }
  .grid { display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); margin: 22px 0; }
  .card {
    background: linear-gradient(160deg, var(--panel-2), var(--panel));
    border: 1px solid var(--line); border-radius: 16px; padding: 18px;
    box-shadow: 0 12px 30px rgba(0,0,0,.35);
  }
  .card .k { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .12em; }
  .card .v { font-size: 28px; font-weight: 700; margin-top: 6px; }
  .bars { display: grid; gap: 10px; margin-top: 8px; }
  .bar-row { display: grid; grid-template-columns: 90px 1fr 60px; align-items: center; gap: 12px; font-size: 13px; }
  .bar-track { height: 12px; border-radius: 999px; background: rgba(255,255,255,.06); overflow: hidden; }
  .bar-fill { height: 100%; border-radius: 999px; }
  .controls { display: flex; gap: 12px; flex-wrap: wrap; align-items: center; margin: 20px 0 12px; }
  input[type=search], select {
    background: var(--panel-2); border: 1px solid var(--line); color: var(--text);
    padding: 10px 14px; border-radius: 10px; font-size: 14px; outline: none;
  }
  input[type=search]:focus, select:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(34,211,238,.15); }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  thead th {
    position: sticky; top: 0; text-align: left; padding: 12px 10px;
    background: #0b1226; color: var(--muted); text-transform: uppercase;
    font-size: 11px; letter-spacing: .1em; border-bottom: 1px solid var(--line); z-index: 2;
  }
  tbody td { padding: 10px; border-bottom: 1px solid rgba(34,48,92,.55); vertical-align: top; }
  tbody tr:hover { background: rgba(34,211,238,.06); }
  .badge { padding: 3px 9px; border-radius: 999px; font-size: 11px; font-weight: 700; color: #05070f; }
  .mono { font-family: "Cascadia Code", Consolas, monospace; font-size: 12px; color: var(--muted); }
  .desc { max-width: 620px; word-break: break-word; }
  .wrap { background: linear-gradient(160deg, var(--panel-2), var(--panel)); border: 1px solid var(--line); border-radius: 16px; overflow: hidden; margin-top: 8px; }
  footer { margin-top: 26px; color: var(--muted); font-size: 12px; text-align: center; }
</style>
</head>
<body>
<header class="hero">
  <h1>__TITLE__</h1>
  <p>Portable DFIR timeline report &middot; generated __GENERATED__</p>
  <p>
    <span class="pill">Case: __CASE_ID__</span>
    <span class="pill">Events: __TOTAL__</span>
    <span class="pill">Chain: __CHAIN__</span>
    <span class="pill">Engine: TimelineBuilder __VERSION__</span>
  </p>
</header>

<section class="grid">
  __CARDS__
</section>

<section class="card">
  <div class="k">Severity distribution</div>
  <div class="bars">__SEVERITY_BARS__</div>
</section>

<section class="controls">
  <input id="q" type="search" placeholder="Search description, path, user, host..." />
  <select id="sev">
    <option value="">All severities</option>
    __SEV_OPTIONS__
  </select>
  <span class="pill" id="count"></span>
</section>

<div class="wrap">
<table id="t">
  <thead>
    <tr><th>Timestamp (UTC)</th><th>Kind</th><th>Severity</th><th>Source</th><th>Host</th><th>User</th><th>Path / Artifact</th><th>Description</th></tr>
  </thead>
  <tbody>
__ROWS__
  </tbody>
</table>
</div>

<footer>TimelineBuilder __VERSION__ &middot; integrity-verified evidence &middot; read-only collection</footer>

<script>
const rows = [...document.querySelectorAll('#t tbody tr')];
const q = document.getElementById('q');
const sev = document.getElementById('sev');
const count = document.getElementById('count');
function apply() {
  const term = q.value.toLowerCase();
  const s = sev.value;
  let visible = 0;
  for (const r of rows) {
    const okText = !term || r.dataset.search.includes(term);
    const okSev = !s || r.dataset.severity === s;
    const show = okText && okSev;
    r.style.display = show ? '' : 'none';
    if (show) visible++;
  }
  count.textContent = visible + ' / ' + rows.length + ' events';
}
q.addEventListener('input', apply);
sev.addEventListener('change', apply);
apply();
</script>
</body>
</html>
"""


def _severity_bars(counts: Counter) -> str:
    total = sum(counts.values()) or 1
    rows = []
    for severity in ("critical", "high", "medium", "low", "info"):
        count = counts.get(severity, 0)
        pct = round(100 * count / total, 1)
        color = SEVERITY_COLORS[severity]
        rows.append(
            f'<div class="bar-row"><span>{severity.title()}</span>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{pct}%;background:linear-gradient(90deg,{color},{color}aa)"></div></div>'
            f"<span>{count}</span></div>"
        )
    return "\n".join(rows)


def _rows(events: list[TimelineEvent]) -> str:
    chunks = []
    for event in events:
        sev = event.severity.value
        color = SEVERITY_COLORS.get(sev, "#60a5fa")
        ts = event.normalized_timestamp().strftime("%Y-%m-%d %H:%M:%S")
        search = " ".join(
            [event.description, event.source_path, event.user, event.host, sev, event.source_type.value]
        ).lower()
        chunks.append(
            "<tr data-severity=\"{sev}\" data-search=\"{search}\">"
            "<td class=\"mono\">{ts}</td>"
            "<td class=\"mono\">{kind}</td>"
            "<td><span class=\"badge\" style=\"background:{color}\">{sev}</span></td>"
            "<td>{src}</td><td>{host}</td><td>{user}</td>"
            "<td class=\"mono\">{path}</td><td class=\"desc\">{desc}</td></tr>".format(
                sev=html.escape(sev),
                search=html.escape(search, quote=True),
                ts=ts,
                kind=html.escape(event.time_kind.value),
                color=color,
                src=html.escape(event.source_type.value),
                host=html.escape(event.host or "-"),
                user=html.escape(event.user or "-"),
                path=html.escape(event.source_path),
                desc=html.escape(event.description),
            )
        )
    return "\n".join(chunks)


def export_html(
    events: Iterable[TimelineEvent],
    destination: str | Path,
    case_id: str = "",
    chain_status: str = "n/a",
    title: str = "Unified Forensic Timeline",
    version: str = "1.0.0",
    metadata: dict[str, Any] | None = None,
) -> Path:
    events = list(events)
    counts = Counter(event.severity.value for event in events)
    sources = Counter(event.source_type.value for event in events)
    hosts = {e.host for e in events if e.host}
    span_start = events[0].normalized_timestamp().isoformat() if events else "-"
    span_end = events[-1].normalized_timestamp().isoformat() if events else "-"
    high_plus = sum(c for s, c in counts.items() if SEVERITY_ORDER[Severity(s)] >= SEVERITY_ORDER[Severity.HIGH])

    cards = [
        ("Total events", f"{len(events):,}"),
        ("High / Critical", f"{high_plus:,}"),
        ("Distinct hosts", f"{len(hosts):,}"),
        ("Filesystem events", f"{sources.get('filesystem', 0):,}"),
        ("Log events", f"{sources.get('log', 0):,}"),
        ("Window start", span_start[:19].replace("T", " ")),
        ("Window end", span_end[:19].replace("T", " ")),
    ]
    cards_html = "\n".join(
        f'<div class="card"><div class="k">{html.escape(k)}</div><div class="v">{html.escape(str(v))}</div></div>'
        for k, v in cards
    )
    sev_options = "\n".join(
        f'<option value="{s}">{s.title()}</option>' for s in ("critical", "high", "medium", "low", "info")
    )

    document = (
        TEMPLATE.replace("__TITLE__", html.escape(title))
        .replace("__GENERATED__", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
        .replace("__CASE_ID__", html.escape(case_id or "-"))
        .replace("__TOTAL__", f"{len(events):,}")
        .replace("__CHAIN__", html.escape(chain_status))
        .replace("__VERSION__", html.escape(version))
        .replace("__CARDS__", cards_html)
        .replace("__SEVERITY_BARS__", _severity_bars(counts))
        .replace("__SEV_OPTIONS__", sev_options)
        .replace("__ROWS__", _rows(events))
    )
    dest = Path(destination)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(document, encoding="utf-8")
    _ = json.dumps(metadata or {}, default=str)
    return dest
