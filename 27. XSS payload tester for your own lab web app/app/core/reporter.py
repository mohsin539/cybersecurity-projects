"""XSS Payload Tester - report export (JSON + HTML with traceability records)."""
from __future__ import annotations

import html
import json
import os
from datetime import datetime
from typing import Dict, List

from .framemap import SEVERITY_WEIGHT
from .models import Finding


def export_json(findings: List[Finding], meta: Dict, path: str) -> str:
    payload = {
        "generated": datetime.utcnow().isoformat(),
        "meta": meta,
        "findings": [vars(f) for f in sorted(findings, key=lambda f: SEVERITY_WEIGHT.get(f.severity, 9))],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return path


def render_html(findings: List[Finding], meta: Dict) -> str:
    rows = []
    for f in sorted(findings, key=lambda f: SEVERITY_WEIGHT.get(f.severity, 9)):
        ev = "; ".join(f"{k}={v}" if isinstance(v, (str, int, float)) else f"{k}={json.dumps(v)}" for k, v in f.evidence.items())
        rows.append(
            "<tr>"
            f"<td>{html.escape(f.id)}</td>"
            f"<td><span class='sev sev-{f.severity.lower()}'>{html.escape(f.severity)}</span></td>"
            f"<td>{html.escape(f.title)}</td>"
            f"<td>{html.escape(f.verdict)}</td>"
            f"<td>{f.cvss_score:.1f}</td>"
            f"<td>{html.escape(f.owasp)}</td>"
            f"<td>{html.escape(','.join(f.cwes))}</td>"
            f"<td>{html.escape(','.join(f.nist_controls))}</td>"
            f"<td>{html.escape(','.join(f.iso_controls))}</td>"
            f"<td>{html.escape(f.url)}</td>"
            f"<td>{html.escape(f.param)}</td>"
            f"<td>{html.escape(f.vector_name)}</td>"
            f"<td>{html.escape(f.context)}</td>"
            f"<td>{html.escape(f.strategy)}</td>"
            f"<td>{f.confidence:.2f}</td>"
            f"<td>{html.escape(ev)}</td>"
            f"<td>{html.escape(f.payload)}</td>"
            f"<td>{html.escape(f.remediation[:140])}</td>"
            "</tr>"
        )
    meta_rows = "".join(
        f"<tr><th>{html.escape(str(k))}</th><td>{html.escape(str(v))}</td></tr>" for k, v in meta.items()
    )
    page = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>XssTester Report</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;margin:2em;color:#1a1a2e}}
h1{{font-size:1.4em}} table{{border-collapse:collapse;width:100%;font-size:0.78em}}
th,td{{border:1px solid #ccc;padding:4px 6px;text-align:left;vertical-align:top;word-break:break-word}}
tr:nth-child(even){{background:#f6f7fb}}
.sev{{font-weight:bold;padding:1px 6px;border-radius:3px;color:#fff}}
.sev-critical{{background:#b00020}}.sev-high{{background:#d93025}}
.sev-medium{{background:#e8710a}}.sev-low{{background:#f9ab00}}.sev-info{{background:#5f6368}}
.con{{background:#e8f0fe;padding:6px 10px;border:1px solid #ccd7f0}}
</style></head><body>
<h1>XssTester — XSS Payload Test Report</h1>
<p>Response-reflection triage evidence. Findings are heuristic — confirm each PoC in a browser before remediation.</p>
<div class="con"><table>{meta_rows}</table></div>
<h2>Findings ({len(findings)})</h2>
<table>
<tr><th>ID</th><th>Sev</th><th>Title</th><th>Verdict</th><th>CVSS</th><th>OWASP 2025</th><th>CWE</th>
<th>NIST 800-53</th><th>ISO 27001</th><th>URL</th><th>Param</th><th>Vector</th><th>Context</th>
<th>Strategy</th><th>Conf</th><th>Evidence</th><th>Payload</th><th>Remediation</th></tr>
{''.join(rows)}
</table>
</body></html>"""
    return page


def export_html(findings: List[Finding], meta: Dict, path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_html(findings, meta))
    return path


def ensure_outdir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path