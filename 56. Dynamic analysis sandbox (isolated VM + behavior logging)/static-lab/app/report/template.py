"""Self-contained HTML template with embedded CSS (attractive, print-friendly, offline)."""

from __future__ import annotations

_CSS = """
:root{--bg:#0f1420;--panel:#161d2d;--line:#243049;--fg:#d7e0f2;--dim:#8fa0bd;
--accent:#38bdf8;--good:#2ea043;--warn:#e08a00;--bad:#d1242f;--chip:#31415e;}
*{box-sizing:border-box} body{margin:0;font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;
background:linear-gradient(160deg,#0f1420,#1a2132);color:var(--fg);padding:24px}
h1{background:linear-gradient(90deg,#38bdf8,#818cf8);-webkit-background-clip:text;color:transparent;margin:0 0 4px}
h2{margin:28px 0 10px;color:#b6c8ea;font-size:18px;letter-spacing:.4px;border-left:4px solid var(--accent);padding-left:10px}
.wrap{max-width:1180px;margin:0 auto}
.banner{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px;
background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:20px 24px;margin-bottom:20px}
.verdict{font-size:26px;font-weight:700}
.scorebar{width:340px;height:14px;background:#0a0e18;border-radius:8px;overflow:hidden;border:1px solid var(--line)}
.scorefill{height:100%;border-radius:8px;transition:width .6s}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin-top:14px}
.meta .kv{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:10px 12px}
.meta .k{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.6px}
.meta .v{font-size:14px;margin-top:4px;word-break:break-all}
table{width:100%;border-collapse:collapse;background:var(--panel);border-radius:10px;overflow:hidden;
border:1px solid var(--line);font-size:13px;margin:8px 0}
th{background:#1e2a44;color:#9db4dd;text-align:left;padding:8px 12px;font-size:11px;text-transform:uppercase;letter-spacing:.5px}
td{padding:7px 12px;border-top:1px solid #22304a;vertical-align:top}
tr:hover td{background:#1b2438}
.mono{font-family:Cascadia Mono,Consolas,monospace;font-size:12px;color:#a5f3fc}
.chip{background:var(--chip);color:#cfe3ff;border-radius:999px;padding:1px 8px;font-size:10px;margin-right:4px;display:inline-block}
.chip.warn{background:#4a3413;color:#f5c76b}
.chip.err{background:#4a1619;color:#ffb3b9}
.chip-ok{background:#12331d;color:#7ee2a8;border-radius:999px;padding:2px 10px}
.chip-err{background:#4a1619;color:#ffb3b9;border-radius:999px;padding:2px 10px}
.warn{color:var(--warn);font-weight:600}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px;font-size:13px}
.card-title{font-weight:700;margin-bottom:6px;color:#dfe8ff}
.small{font-size:11px;color:var(--dim);word-break:break-all}
a{color:var(--accent)}
.footer{margin-top:34px;color:var(--dim);font-size:11px;text-align:center;border-top:1px solid var(--line);padding-top:14px}
@media print{body{background:#fff;color:#111}.banner,.grid,.card,table{background:#fff;border-color:#ccc;color:#111}th{background:#eee;color:#333}}
"""


def render_html(
    verdict: str,
    verdict_color: str,
    score: int,
    analysis_id: str,
    file_path: str,
    file_name: str,
    file_size: int,
    magic_hint: str,
    hashes_rows: str,
    pe_rows: str,
    sections_rows: str,
    imports_rows: str,
    suspicious_rows: str,
    string_count: int,
    lookup_cards: str,
    audit_html: str,
    extra: str = "",
) -> str:
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>StaticLab Report - {file_name}</title>
<style>{_CSS}</style></head><body><div class="wrap">

<div class="banner">
  <div>
    <h1>StaticLab &middot; Static Analysis Report</h1>
    <div class="small">Analysis {analysis_id} &middot; pipeline: strings &middot; PE headers &middot; hash lookups</div>
  </div>
  <div style="display:flex;align-items:center;gap:16px">
    <div>
      <div class="small">VERDICT</div>
      <div class="verdict" style="color:{verdict_color}">{verdict}</div>
    </div>
    <div>
      <div class="small">THREAT SCORE</div>
      <div style="display:flex;align-items:center;gap:8px">
        <div class="scorebar"><div class="scorefill" style="width:{score}%;background:{verdict_color}"></div></div>
        <span style="font-weight:700">{score}/100</span>
      </div>
    </div>
  </div>
</div>

<div class="meta">
  <div class="kv"><div class="k">File</div><div class="v">{file_name}</div></div>
  <div class="kv"><div class="k">Path</div><div class="v">{file_path}</div></div>
  <div class="kv"><div class="k">Size</div><div class="v">{file_size:,} bytes</div></div>
  <div class="kv"><div class="k">Type</div><div class="v">{magic_hint}</div></div>
</div>

<h2>Cryptographic Hashes</h2>
<table><tr><th>Algorithm</th><th>Value</th></tr>{hashes_rows}</table>

<h2>PE Header Summary</h2>
<table><tr><th>Property</th><th>Value</th></tr>{pe_rows}</table>

<h2>Sections &amp; Entropy</h2>
<table><tr><th>Name</th><th>VA</th><th>Virt. Size</th><th>Raw Size</th><th>Entropy</th><th>SHA-256</th></tr>{sections_rows}</table>

<h2>Imports (top)</h2>
<table><tr><th>DLL</th><th>Functions</th></tr>{imports_rows}</table>

<h2>Interesting Strings <span class="chip">{string_count} total</span></h2>
<table><tr><th>Offset</th><th>Encoding</th><th>String</th><th>Flags</th></tr>{suspicious_rows}</table>

<h2>Threat-Intel Lookups</h2>
<div class="grid">{lookup_cards}</div>

<h2>Auditability</h2>
<table>{audit_html}</table>

{extra}

<div class="footer">StaticLab portable static-analysis sandbox &middot; generated locally &middot; report may contain unfiltered strings from a subject binary &middot; handle with care</div>
</div></body></html>
"""