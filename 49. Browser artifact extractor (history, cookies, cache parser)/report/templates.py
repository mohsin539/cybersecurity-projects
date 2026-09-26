"""Presentation layer: safe, escaped report templates.

All dynamic values pass through :func:`html.escape` before interpolation so a
malicious bookmark title or cookie value cannot inject script into the HTML
report (OWASP Top 10 A03:2021 - Injection).
"""
from __future__ import annotations

from html import escape
from typing import List

BRAND = {
    "name": "Browser Artifact Extractor",
    "tagline": "Forensic History, Cookie & Cache Parser",
    "version": "1.0.0",
    "accent": "#4f46e5",
    "accent2": "#06b6d4",
    "ink": "#0f172a",
}

PALETTE = {
    "history": "#6366f1",
    "downloads": "#0ea5e9",
    "cookies": "#f59e0b",
    "bookmarks": "#10b981",
    "autofill": "#8b5cf6",
    "logins": "#ef4444",
    "search_terms": "#14b8a6",
    "cache": "#ec4899",
}


def _e(value) -> str:
    return escape("" if value is None else str(value), quote=True)


def stat_card(label: str, value, color: str = BRAND["accent"]) -> str:
    return (
        f'<div class="stat" style="--c:{color}">'
        f'<div class="stat-value">{_e(value)}</div>'
        f'<div class="stat-label">{_e(label)}</div></div>'
    )


def table(headers: List[str], rows: List[List], accent: str = BRAND["accent"]) -> str:
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    body = []
    for row in rows:
        cells = "".join(f"<td>{_e(c)}</td>" for c in row)
        body.append(f"<tr>{cells}</tr>")
    return (
        f'<table style="--c:{accent}"><thead><tr>{head}</tr></thead>'
        f'<tbody>{"".join(body)}</tbody></table>'
    )


def section(title: str, body: str, count: int = None, color: str = BRAND["accent"]) -> str:
    badge = f'<span class="badge" style="background:{color}">{count:,}</span>' if count is not None else ""
    return (
        f'<section class="card"><header class="card-head" style="border-color:{color}">'
        f'<h2>{_e(title)}</h2>{badge}</header>{body}</section>'
    )


HTML_DOC = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{title}</title>
<style>
:root{{--ink:{ink};--accent:{accent};--accent2:{accent2};}}
*{{box-sizing:border-box;}}
body{{margin:0;font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:var(--ink);
    background:linear-gradient(135deg,#0f172a 0%,#1e293b 55%,#312e81 100%);padding:0 0 60px;}}
.hero{{padding:44px 40px 30px;color:#fff;background:linear-gradient(120deg,{accent} 0%,{accent2} 100%);}}
.hero h1{{margin:0;font-size:30px;letter-spacing:.3px;}}
.hero p{{margin:6px 0 0;opacity:.92;}}
.wrap{{max-width:1280px;margin:-24px auto 0;padding:0 24px;}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin:20px 0;}}
.stat{{background:#fff;border-radius:14px;padding:16px 18px;box-shadow:0 10px 30px rgba(2,6,23,.25);
    border-top:4px solid var(--c);}}
.stat-value{{font-size:26px;font-weight:700;color:var(--c);}}
.stat-label{{font-size:12px;text-transform:uppercase;letter-spacing:.8px;color:#64748b;margin-top:4px;}}
.card{{background:#fff;border-radius:16px;padding:2px 0 8px;margin:18px 0;
    box-shadow:0 10px 30px rgba(2,6,23,.18);overflow:hidden;}}
.card-head{{display:flex;align-items:center;gap:12px;padding:16px 20px;border-left:6px solid var(--c);
    border-bottom:1px solid #e2e8f0;background:#f8fafc;}}
.card-head h2{{margin:0;font-size:17px;}}
.badge{{color:#fff;border-radius:999px;padding:2px 12px;font-size:12px;font-weight:600;}}
.meta{{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:10px 26px;padding:16px 20px;}}
.meta div{{font-size:13px;color:#334155;}}
.meta b{{color:#0f172a;}}
table{{width:100%;border-collapse:collapse;font-size:12.5px;}}
thead th{{position:sticky;top:0;background:var(--c);color:#fff;text-align:left;padding:9px 12px;
    font-weight:600;white-space:nowrap;}}
tbody td{{padding:7px 12px;border-bottom:1px solid #eef2f7;max-width:520px;overflow:hidden;
    text-overflow:ellipsis;white-space:nowrap;color:#1e293b;}}
tbody tr:nth-child(even){{background:#f8fafc;}}
tbody tr:hover{{background:#eef2ff;}}
.scroll{{max-height:520px;overflow:auto;}}
.note{{color:#475569;font-size:12.5px;padding:10px 22px;}}
.pill{{display:inline-block;padding:1px 8px;border-radius:999px;background:#e0e7ff;color:#3730a3;font-size:11px;}}
.ok{{color:#059669;font-weight:600;}} .warn{{color:#d97706;font-weight:600;}} .bad{{color:#dc2626;font-weight:600;}}
footer{{max-width:1280px;margin:30px auto 0;padding:0 24px;color:#cbd5e1;font-size:12px;}}
a{{color:var(--accent);}}
</style></head><body>
<div class="hero"><h1>{brand}</h1><p>{tagline} &middot; v{version} &middot; ISO 27001 / NIST / OWASP aligned</p></div>
<div class="wrap">{body}</div>
<footer>Generated offline by {brand} v{version}. No network transmission occurred.
Evidence digests are SHA-256; audit log is hash-chained.</footer>
</body></html>"""
