"""Self-contained HTML report writer.

Single-file, offline, CSP-locked, all values escaped. Inline SVG charts,
no external CDN or JS runtime dependencies.
"""
from __future__ import annotations

from src.security.sanitize import escape_html, js_string

_BADGE_COLOR = {"PASS": "#059669", "FAIL": "#b91c1c", "CAUTION": "#b45309", "INFO": "#0891b2"}
_VERDICT_COLOR = {"candidate wins": "var(--good)", "baseline wins": "var(--bad)",
                  "no practical difference": "var(--muted)", "inconclusive": "var(--muted)"}


def _svg_line(buckets: dict, width: int = 1000, height: int = 260) -> str:
    cand = buckets.get("candidate") or []
    base = buckets.get("baseline") or []
    series = []
    if cand:
        series.append(("candidate", cand, "#22d3ee"))
    if base:
        series.append(("baseline", base, "#fbbf24"))
    if not series:
        return "<p>no bucket data</p>"

    n = max(len(s[1]) for s in series)
    if n == 0:
        return "<p>no bucket data</p>"
    # downsample for very long runs (keep <= 2000 points)
    step = max(1, n // 2000)
    xs = list(range(0, n, step))
    ymax = max((max(s[1]) for s in series), default=1) or 1
    pad_l, pad_r, pad_t, pad_b = 46, 12, 16, 30

    def xpx(i: int) -> float:
        return pad_l + (i / (n - 1) if n > 1 else 0) * (width - pad_l - pad_r)

    def ypx(v: float) -> float:
        return pad_t + (1 - v / ymax) * (height - pad_t - pad_b)

    lines = []
    for label, arr, color in series:
        pts = " ".join(f"{xpx(i):.1f},{ypx(arr[i]):.1f}" for i in xs)
        lines.append(
            f'<g><polyline points="{pts}" fill="none" stroke="{color}" stroke-width="1.6" '
            f'opacity=".9"/></g>'
        )
    grid = ""
    for gval in range(0, 5):
        y = pad_t + (gval / 4) * (height - pad_t - pad_b)
        grid += f'<line x1="{pad_l}" y1="{y:.1f}" x2="{width - pad_r}" y2="{y:.1f}" stroke="#1e2a4e" stroke-dasharray="3 4"/><text x="{pad_l - 8}" y="{y + 4:.1f}" fill="#6b7fae" font-size="10" text-anchor="end">{int(ymax * (1 - gval / 4))}</text>'
    legend = "".join(
        f'<span style="color:{c}">\u25cf {escape_html(l)}</span>&nbsp;' for l, _, c in series
    )
    axis = (
        f'<line x1="{pad_l}" y1="{pad_t}" x2="{pad_l}" y2="{height - pad_b}" stroke="#2c4270"/>'
        f'<line x1="{pad_l}" y1="{height - pad_b}" x2="{width - pad_r}" y2="{height - pad_b}" stroke="#2c4270"/>'
    )
    svg = (
        f'<svg viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg" width="100%" height="auto">'
        f"{grid}{axis}{''.join(lines)}"
        f'<text x="{pad_l}" y="{height - 8}" fill="#6b7fae" font-size="11">second</text>'
        f"</svg>"
    )
    return f'<div style="margin:6px 0 2px">{legend}</div>{svg}'


def _summary_cards(model: dict) -> str:
    cards = []
    for r in model["summary_rows"]:
        val = r["candidate"]
        base = f"<div class='sub'>vs {escape_html(r.get('baseline','-'))}</div>" if "baseline" in r else ""
        cards.append(
            f"<div class='kpi'><div class='k-lbl'>{escape_html(r['metric'])}</div>"
            f"<div class='k-val'>{escape_html(val)}</div>{base}</div>"
        )
    return "".join(cards)


def _comparison_table(model: dict) -> str:
    if not model["comparison_rows"]:
        return "<p class='muted'>No comparison arm configured - run with a baseline.</p>"
    head = "<tr><th>Metric</th><th>Candidate</th><th>Baseline</th><th>\u0394(%)</th><th>M-W p(adj)</th><th>Hedges g</th><th>Effect</th><th>Verdict</th></tr>"
    body = []
    for r in model["comparison_rows"]:
        color = _VERDICT_COLOR.get(r["verdict"], "var(--muted)")
        body.append(
            f"<tr><td><b>{escape_html(r['metric'])}</b></td>"
            f"<td>{escape_html(r['candidate_mean'])}</td>"
            f"<td>{escape_html(r['baseline_mean'])}</td>"
            f"<td>{escape_html(r.get('relative_delta','-'))}</td>"
            f"<td>{escape_html(r['u_p'])}</td>"
            f"<td>{escape_html(r['hedges_g'])}</td>"
            f"<td>{escape_html(r['effect'])}</td>"
            f"<td><span class='tag' style='color:{color};border-color:{color}55'>{escape_html(r['verdict'])}</span></td></tr>"
        )
    return f"<table><thead>{head}</thead><tbody>{''.join(body)}</tbody></table>"


def _scenario_table(model: dict) -> str:
    rows = "".join(
        f"<tr><td class='key'>{escape_html(k)}</td><td>{escape_html(str(v))}</td></tr>"
        for k, v in model["scenario"].items()
    )
    return f"<table class='kv'>{rows}</table>"


def write_html(model: dict, path: str) -> str:
    badge = model["verdict_badge"]
    badge_color = _BADGE_COLOR.get(badge, "#0891b2")
    summary_rows = model["summary_rows"]
    buckets = model["buckets"]
    has_base = bool(buckets.get("baseline"))

    chart = _svg_line(buckets)
    scenario_html = _scenario_table(model)
    cards = _summary_cards(model)
    comp = _comparison_table(model)
    rep = _replica_table(model)

    doc = f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; img-src 'self' data:">
<title>Jitter &amp; Sleep Study Report - {escape_html(model['run_id'])}</title>
<style>
:root{{--bg:#0b1020;--panel:#111a33;--line:#223055;--text:#e6ecff;--muted:#8fa0c8;
--good:#059669;--bad:#b91c1c;--warn:#b45309;--cyan:#22d3ee;--amber:#fbbf24;--violet:#a78bfa}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:radial-gradient(900px 500px at 80% -10%,#1b2b5e 0%,transparent 60%),var(--bg);color:var(--text);
font-family:'Segoe UI',system-ui,sans-serif;line-height:1.6;padding:28px}}
.wrap{{max-width:1080px;margin:0 auto}}
h1{{font-size:26px;letter-spacing:-.3px;background:linear-gradient(90deg,var(--cyan),var(--amber));
-webkit-background-clip:text;background-clip:text;color:transparent}}
.meta{{color:var(--muted);font-size:13px;margin:6px 0 18px}}
.badge{{display:inline-block;font-weight:800;padding:6px 16px;border-radius:999px;
color:#04121a;margin:10px 2px 0}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:18px 0}}
.kpi{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px}}
.k-lbl{{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:1px}}
.k-val{{font-size:22px;font-weight:800;color:var(--cyan);margin-top:2px}}
.sub{{color:var(--muted);font-size:12px}}
.chart,.panel{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:18px;margin:14px 0}}
.panel h2{{font-size:17px;color:var(--violet);margin-bottom:8px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{text-align:left;padding:9px 10px;color:var(--muted);border-bottom:1px solid var(--line);text-transform:uppercase;font-size:11px;letter-spacing:1px}}
td{{padding:8px 10px;border-bottom:1px solid #182447;vertical-align:top}}
.key{{color:var(--amber);font-family:Consolas,monospace}}
.tag{{font-weight:700;border:1px solid;border-radius:6px;padding:2px 8px;font-size:11px}}
.muted{{color:var(--muted)}}
footer{{color:#5a6a92;font-size:12px;margin-top:22px;text-align:center}}
</style></head><body><div class="wrap">
<header>
  <h1>Agent Check-in Jitter &amp; Sleep Study Report</h1>
  <div class="meta">run <b>{escape_html(model['run_id'])}</b> &middot; {escape_html(model['generated_at'])} &middot; config sha <span class="key">{escape_html(model['config_hash'])}</span> &middot; engine {escape_html(model['engine'])}</div>
  <span class="badge" style="background:{badge_color}">{escape_html(badge)}</span>
  <span style="color:var(--muted);font-size:14px;margin-left:10px">{escape_html(model['verdict_text'])}</span>
</header>

<div class="kpis">{cards}</div>

<div class="chart"><h2>Arrivals per second</h2>{chart}</div>

<div class="panel"><h2>Scenario (validated)</h2>{scenario_html}</div>

<div class="panel"><h2>Statistical comparison vs {('no-jitter baseline' if has_base else 'no baseline (single arm)')}</h2>{comp}</div>

<div class="panel"><h2>Per-replica metrics</h2>{rep}</div>

<footer>Generated by AgentJitterStudy portable toolkit &middot; deterministic-seeded &middot; artifacts hashed in manifest</footer>
</div></body></html>
"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)
    return path


def _replica_table(model: dict) -> str:
    rows = model.get("replica_rows") or []
    if not rows:
        return "<p class='muted'>no data</p>"
    keys = list(rows[0].keys())
    head = "".join(f"<th>{escape_html(k)}</th>" for k in keys)
    body = "".join(
        "<tr>" + "".join(f"<td>{escape_html(str(r.get(k, '')))}</td>" for k in keys) + "</tr>"
        for r in rows
    )
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"