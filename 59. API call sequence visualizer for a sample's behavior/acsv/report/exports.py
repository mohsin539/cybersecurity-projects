"""Report exporters (architecture §7.2): JSON, CSV, HTML, PDF, STIX 2.1.

- JSON/CSV: RFC 4180 / compact JSON.
- HTML: self-contained, CSP-restricted, auto-escaped viewer.
- PDF: handed to fpdf2 (embedded fonts, classification banner).
- STIX 2.1: minimal `observed-data` bundle export (ISO A.5.7 sharing).
"""

from __future__ import annotations

import csv
import html as html_mod
import io
import json
from datetime import datetime, timezone

try:
    from fpdf import FPDF
except ImportError:  # pragma: no cover - exe bundles fpdf2
    FPDF = None

from ..analysis.graph import build_graph

ETAG_MAP = {
    "File": "#8be9fd", "Registry": "#bd93f9", "Network": "#50fa7b",
    "Process": "#ffb86c", "Thread": "#ff79c6", "Crypto": "#f1fa8c",
    "Memory": "#ff5555", "IPC": "#ffb86b", "Exception": "#ff5555",
    "Other": "#6272a4",
}


def graph_payload(analysis: dict) -> dict:
    return build_graph(analysis.get("edges", []))


def render(doc: dict, fmt: str, session_id: str, svc) -> tuple[bytes, str]:
    if fmt == "json":
        return render_json(doc, session_id, svc), "application/json"
    if fmt == "csv":
        return render_csv(doc, session_id, svc), "text/csv; charset=utf-8"
    if fmt == "html":
        return render_html(doc, session_id, svc).encode("utf-8"), "text/html; charset=utf-8"
    if fmt == "pdf":
        return render_pdf(doc, session_id, svc), "application/pdf"
    if fmt == "stix":
        return render_stix(doc, session_id, svc), "application/json"
    raise ValueError(fmt)


# ---------------------------------------------------------------- JSON + CSV
def render_json(doc: dict, session_id: str, svc) -> bytes:
    out = {
        "_meta": {
            "schema": "acsv-report@1.0",
            "session_id": session_id,
            "report_sha256": doc["report_sha256"],
        },
        **doc,
    }
    return json.dumps(out, indent=2, default=str).encode("utf-8")


def render_csv(doc: dict, session_id: str, svc) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["seq", "ts_ns", "pid", "tid", "category", "api", "module",
                "ret", "status", "parent_seq", "args", "tags"])
    w.writerows(_event_rows(svc, session_id))
    return buf.getvalue().encode("utf-8")


def _event_rows(svc, session_id: str):
    rows = []
    for e in svc.store.iter_events(session_id, limit=200000):
        rows.append([
            e["seq"], e["ts_ns"], e["pid"], e["tid"], e["category"], e["api"],
            e.get("module", ""), e.get("ret", ""), e.get("status", ""),
            e.get("parent_seq", ""), json.dumps(e.get("args", {}), default=str),
            ",".join(e.get("tags", [])),
        ])
    return rows


# ---------------------------------------------------------------------- HTML
_HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>ACSV Report {id}</title>
<style>
:root{{--cy:#22d3ee;--vi:#a78bfa;--am:#fbbf24;--ro:#fb7185;--em:#34d399;--bg:#0b1120;}}
body{{background:var(--bg);color:#e2e8f0;font-family:Segoe UI,sans-serif;margin:24px 8%;}}
h1{{color:var(--cy);border-bottom:2px solid var(--vi);}}
h2{{color:var(--vi);}} h3{{color:var(--am);}}
.banner{{background:#1e293b;padding:14px 18px;border-left:6px solid var(--ro);
  margin-top:8px;}}
table{{border-collapse:collapse;width:100%;font-size:13px;}}
th{{background:#1e293b;color:var(--cy);text-align:left;padding:6px 8px;}}
td{{border-bottom:1px solid #334155;padding:5px 8px;}}
.kpi{{display:inline-block;min-width:150px;background:#0f172a;border:1px solid #334155;
  padding:12px;margin:6px;border-radius:10px;}}
.kpi b{{color:var(--am);font-size:20px;display:block;}}
.finding{{background:#111c33;border-left:4px solid var(--ro);padding:10px 12px;margin:8px 0;}}
.cat-File{{color:var(--cy);}} .cat-Registry{{color:var(--vi);}}
.cat-Network{{color:var(--em);}} .cat-Process{{color:var(--am);}}
.cat-Thread{{color:var(--ro);}}
code{{background:#0f172a;padding:1px 5px;border-radius:4px;}}
</style>
</head>
<body>
<div class="banner">INTERNAL SECURITY EVIDENCE | ACSV v1.0.0 | {subj}</div>
<h1>API Call Sequence Report</h1>
<p>Report <code>{id}</code> · generated {iso} · session <code>{session}</code></p>
<h2>Executive Summary</h2>
<div class="kpi"><b>{events}</b>events</div>
<div class="kpi"><b>{apis}</b>unique APIs</div>
<div class="kpi"><b>{findings}</b>findings</div>
<div class="kpi"><b>{crit}</b>critical</div>
<div class="kpi"><b>{high}</b>high</div>
<h2>Methodology</h2>
<p>{method}</p>
<h2>API Call Statistics</h2>
<table><tr><th>API</th><th>Calls</th></tr> {top_rows} </table>
<h2>Findings &amp; Anomalies</h2>
{find_rows}
<h2>Compliance Coverage</h2>
<table><tr><th>Framework</th><th>Total</th><th>Evidenced</th><th>Implemented</th><th>Coverage</th></tr> {cov_rows} </table>
<h2>Integrity &amp; Provenance</h2>
<p>Report SHA-256: <code>{report_sha}</code></p>
<p>Event-set hash: <code>{event_hash}</code></p>
<p>Policy snapshot: <code>{policy}</code></p>
</body>
</html>
"""


def render_html(doc: dict, session_id: str, svc) -> str:
    s = doc["summary"]
    top_rows = "\n".join(
        f"<tr><td><code>{html_mod.escape(name)}</code></td><td>{n}</td></tr>"
        for name, n in doc["statistics"].get("top_apis", [])[:25]
    )
    find_rows = "\n".join(
        f'<div class="finding"><b>{html_mod.escape(f.get("title", ""))}</b> '
        f'<span>({html_mod.escape(f.get("severity", ""))})</span><br>'
        f'{html_mod.escape(f.get("description", ""))}<br>'
        f'<small>tags: {html_mod.escape(", ".join(f.get("tags", [])))}</small></div>'
        for f in doc["statistics"].get("findings", [])
    )
    cov_rows = "\n".join(
        f"<tr><td>{html_mod.escape(fw)}</td><td>{m['summary']['total']}</td>"
        f"<td>{m['summary']['evidenced']}</td><td>{m['summary']['implemented']}</td>"
        f"<td>{round(m['summary']['implemented'] / max(m['summary']['total'], 1) * 100, 1)}%</td></tr>"
        for fw, m in doc["compliance"]["matrix"].items()
    )
    cov_rows += (
        f"<tr><td><b>Total</b></td><td>{doc['compliance']['cover']['total']}</td>"
        f"<td>{doc['compliance']['cover']['evidenced']}</td>"
        f"<td>{doc['compliance']['cover']['implemented']}</td>"
        f"<td>{doc['compliance']['cover']['coverage_pct']}%</td></tr>"
    )
    return _HTML_TEMPLATE.format(
        id=html_mod.escape(doc["report_id"]),
        subj=html_mod.escape(s["sample_name"] or "unknown-sample"),
        iso=doc["iso8601"],
        session=html_mod.escape(session_id),
        events=s["event_count"], apis=s["unique_apis"],
        findings=s["findings_total"], crit=s["findings_critical"], high=s["findings_high"],
        method=html_mod.escape(doc["methodology"]["capture"]),
        top_rows=top_rows, find_rows=find_rows, cov_rows=cov_rows,
        report_sha=doc["report_sha256"], event_hash=doc["integrity"]["event_set_hash"],
        policy=doc["integrity"]["policy_hash"],
    )


# ----------------------------------------------------------------------- PDF
class _Pdf(FPDF):
    def header(self):
        if self.page_no() > 1:
            self.set_font("Helvetica", "", 8)
            self.set_text_color(183, 194, 220)
            self.cell(0, 5, "ACSV Security Evidence - INTERNAL", align="L")
            self.ln(6)

    def footer(self):
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 160, 190)
        self.cell(0, 8, f"ACSV v1.0.0  |  page {self.page_no()}", align="C")


def write_para(pdf, text: str, size: int = 10) -> None:
    pdf.set_font("Helvetica", "", size)
    pdf.multi_cell(pdf.epw, 6, text, new_x="LMARGIN", new_y="NEXT")


def render_pdf(doc: dict, session_id: str, svc) -> bytes:
    if FPDF is None:  # pragma: no cover
        raise RuntimeError("fpdf2 not available")
    pdf = _Pdf()
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(34, 211, 238)
    pdf.cell(pdf.epw, 10, "API Call Sequence Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(140, 150, 180)
    pdf.cell(pdf.epw, 6, f"INTERNAL SECURITY EVIDENCE - {doc['report_id']}",
             new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)
    s = doc["summary"]
    pdf.set_text_color(200, 210, 230)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(pdf.epw, 8, "Executive Summary", new_x="LMARGIN", new_y="NEXT")
    write_para(pdf,
        f"Sample: {s['sample_name']}\nSHA-256: {s['sample_sha256']}\n"
        f"Events: {s['event_count']}  |  Unique APIs: {s['unique_apis']}  |  "
        f"Findings: {s['findings_total']} (critical: {s['findings_critical']}, "
        f"high: {s['findings_high']})")
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(pdf.epw, 8, "Findings", new_x="LMARGIN", new_y="NEXT")
    for f in doc["statistics"].get("findings", []):
        write_para(pdf,
            f"[{f.get('severity', '').upper()}] {f.get('title', '')} - "
            f"{f.get('description', '')}  (tags: {', '.join(f.get('tags', []))})")
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(pdf.epw, 8, "Top APIs", new_x="LMARGIN", new_y="NEXT")
    for name, n in doc["statistics"].get("top_apis", [])[:15]:
        write_para(pdf, f"{name:40s} {n}")
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(pdf.epw, 8, "Compliance Coverage", new_x="LMARGIN", new_y="NEXT")
    write_para(pdf,
        f"Total controls: {doc['compliance']['cover']['total']}  |  "
        f"Evidenced: {doc['compliance']['cover']['evidenced']}  |  "
        f"Coverage: {doc['compliance']['cover']['coverage_pct']}%")
    pdf.ln(3)
    pdf.set_font("Helvetica", "", 8)
    pdf.multi_cell(pdf.epw, 5,
        f"Report SHA-256: {doc['report_sha256']}\n"
        f"Event-set hash: {doc['integrity']['event_set_hash']}\n"
        f"Policy snapshot: {doc['integrity']['policy_hash']}\n"
        f"Generated: {doc['iso8601']}", new_x="LMARGIN", new_y="NEXT")
    return bytes(pdf.output())


# ---------------------------------------------------------------------- STIX
def render_stix(doc: dict, session_id: str, svc) -> bytes:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    objs = []
    for e in svc.store.iter_events(session_id, limit=5000):
        objs.append({
            "type": "observed-data",
            "id": f"observed-data--{_uuid_from(e['seq'])}",
            "created": now,
            "modified": now,
            "first_observed": now,
            "last_observed": now,
            "number_observed": 1,
            "object_refs": [],
            "custom": {"api": e["api"], "category": e["category"],
                       "seq": e["seq"], "ret": e.get("ret", "")},
        })
    bundle = {
        "type": "bundle",
        "id": f"bundle--{_uuid_from(0)}",
        "spec_version": "2.1",
        "objects": objs,
    }
    return json.dumps(bundle, indent=2).encode("utf-8")


def _uuid_from(seed: int) -> str:
    import uuid
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"acsv://seq/{seed}"))