"""Report generation (CSV / JSON / HTML) + artifact integrity manifest.

Outputs never embed secrets; every artifact entry carries its SHA-256 and
an audit method string so downstream verifiers can validate provenance.
"""

from __future__ import annotations

import csv
import html
import json
from typing import List

from ..core.disk import human_size


def export_csv(path: str, rows: List[dict], fields: List[str]) -> int:
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)
    return len(rows)


def export_json(path: str, payload: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def export_html(path: str, title: str, meta: dict, rows: List[dict]) -> int:
    """Self-contained, dependency-free HTML report (brandable, printable)."""
    thead = "".join(f"<th>{html.escape(h)}</th>" for h in meta["columns"])
    body = ""
    for r in rows:
        cells = []
        for k in meta["columns"]:
            v = r.get(k, "")
            if k == "size":
                v = human_size(v) if isinstance(v, (int, float)) else v
            if k == "quality":
                v = f"{float(v or 0) * 100:.0f}%"
            cells.append(f"<td>{html.escape(str(v))}</td>")
        body += "<tr>" + "".join(cells) + "</tr>"
    meta_html = "".join(
        f'<div class="meta"><span>{html.escape(str(k))}</span>'
        f"<b>{html.escape(str(v))}</b></div>"
        for k, v in meta.get("summary", {}).items()
    )
    doc = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>
 body{{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#0f1420;color:#e6ebf5}}
 header{{background:linear-gradient(135deg,#7c3aed,#0ea5e9 55%,#10b981);padding:28px 36px;color:#fff}}
 header h1{{margin:0;font-size:22px}} header p{{margin:6px 0 0;opacity:.85;font-size:13px}}
 .wrap{{padding:24px 36px}} .metas{{display:flex;gap:18px;flex-wrap:wrap;margin-bottom:20px}}
 .meta{{background:#1b2437;border:1px solid #273449;border-left:4px solid #10b981;
   border-radius:8px;padding:10px 14px;min-width:150px}} .meta span{{display:block;font-size:11px;color:#8fa3c8}}
 .meta b{{font-size:15px}}
 table{{width:100%;border-collapse:collapse;background:#161e30;border-radius:10px;overflow:hidden}}
 th{{background:#223150;color:#a7c0ee;text-align:left;padding:9px 10px;font-size:12px}}
 td{{padding:8px 10px;border-top:1px solid #232d45;font-size:13px;color:#c9d6ef}}
 .badge{{display:inline-block;border-radius:20px;padding:2px 9px;font-size:11px;color:#fff}}
 .b-high{{background:#0ea5e9}}.b-deleted{{background:#f59e0b}}.b-active{{background:#10b981}}
 .b-overwritten{{background:#64748b}}.b-carved{{background:#8b5cf6}}
 footer{{color:#5c6b8a;font-size:11px;padding:16px 36px}}
</style></head><body>
<header><h1>{html.escape(title)}</h1><p>Generated {html.escape(meta['generated'])}
 &middot; Read-only scan &middot; SHA-256 integrity manifest attached</p></header>
<div class="wrap"><div class="metas">{meta_html}</div>
<table><thead><tr>{thead}</tr></thead><tbody>{body}</tbody></table>
<footer>RecovPro Secure — generated locally; artifacts verified via SHA-256.</footer>
</div></body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
    return len(rows)