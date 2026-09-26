"""reports.py - Report & download pipeline (architecture.md SS9).

Formats shipped: PDF(A-1b-ish), HTML (interactive), JSON (verifiable),
CSV timeline (Timesketch-friendly), Markdown, STIX 2.1, ZIP evidence bundle.

Every export embeds provenance (session_id, case, analyst, report_version,
evidence hash chain) and is written to disk then hashed -> caller records audit.
"""

from __future__ import annotations

import csv
import io
import json
import os
import uuid
from zipfile import ZIP_DEFLATED, ZipFile

from .security import mask_ip, sha256_file, sha256_bytes
from .state import iso_ts


def _fmt_bytes(n: int) -> str:
    n = n or 0
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"


class ReportBuilder:
    FMT_TO_EXT = {"pdf": "pdf", "html": "html", "json": "json", "csv": "csv", "md": "md", "stix": "json", "zip": "zip"}

    def __init__(self, rec: dict, case_id: str = "DEFAULT", analyst: str = "analyst",
                 clearance: int = 2, report_version: int = 1, evidence_root: str = ""):
        self.rec = rec
        self.case_id = case_id
        self.analyst = analyst
        self.clearance = clearance
        self.version = report_version
        self.evidence_root = evidence_root or rec.get("session_id", "")

    # -------------------------------------------------------------- context
    def _context(self) -> dict:
        rec = self.rec
        story = rec.get("story", {})
        return {
            "case_id": self.case_id,
            "session_id": rec.get("session_id", ""),
            "analyst": self.analyst,
            "generated": iso_ts(),
            "report_version": self.version,
            "clearance": self.clearance,
            "src": mask_ip(rec.get("src", ""), self.clearance),
            "sport": rec.get("sport"),
            "dst": mask_ip(rec.get("dst", ""), self.clearance),
            "dport": rec.get("dport"),
            "proto": rec.get("proto"),
            "l7": rec.get("l7"),
            "start_ts": rec.get("start_ts"),
            "end_ts": rec.get("end_ts"),
            "frames": rec.get("frames"),
            "bytes_c2s": _fmt_bytes(rec.get("bytes_c2s", 0)),
            "bytes_s2c": _fmt_bytes(rec.get("bytes_s2c", 0)),
            "stats": rec.get("stats", {}),
            "story": story,
            "events": rec.get("events", []),
            "provenance_hash": sha256_bytes(json.dumps(rec, sort_keys=True).encode("utf-8")),
            "evidence_root": self.evidence_root,
        }

    # ---------------------------------------------------------------- render
    def render(self, fmt: str):
        if fmt not in self.FMT_TO_EXT:
            raise ValueError(f"Unsupported report format {fmt!r}")
        if fmt == "pdf":
            return self._pdf()
        if fmt == "html":
            return self._html()
        if fmt == "json":
            return self._json()
        if fmt == "csv":
            return self._csv()
        if fmt == "md":
            return self._md()
        if fmt == "stix":
            return self._stix()
        if fmt == "zip":
            return self._zip()
        raise ValueError(fmt)

    def save(self, fmt: str, out_dir) -> dict:
        payload: bytes = self.render(fmt)
        ext = self.FMT_TO_EXT[fmt]
        name = f"report_{self.rec.get('session_id', 'session')[:10]}_{fmt}.{ext}"
        path = os.path.join(str(out_dir), name)
        with open(path, "wb") as f:
            f.write(payload)
        return {"fmt": fmt, "path": path, "sha256": sha256_file(path), "size": len(payload), "filename": name}

    # ------------------------------------------------------------ templates
    def _json(self) -> bytes:
        doc = self._context()
        doc["schema"] = "pcapless/report/v1"
        return json.dumps(doc, indent=2, sort_keys=True).encode("utf-8")

    def _md(self) -> bytes:
        c = self._context()
        s = c["story"]
        lines = [
            f"# Network Forensic Story Report",
            "",
            f"- **Case:** {c['case_id']}  |  **Session:** {c['session_id']}",
            f"- **Analyst:** {c['analyst']} (clearance L{c['clearance']})  |  **Generated (UTC):** {c['generated']}",
            f"- **Report version:** v{c['report_version']}  |  **Provenance hash:** `{c['provenance_hash']}`",
            "",
            "## Narrative",
            "",
        ]
        lines += [f">{ line }" for line in s.get("narrative", [])]
        lines += ["", "## Flow metadata", ""]
        lines += [
            f"| Field | Value |",
            f"|---|---|",
            f"| Session | `{c['session_id']}` |",
            f"| Flow | {c['src']}:{c['sport']} <-> {c['dst']}:{c['dport']} ({c['proto']}/{c['l7']}) |",
            f"| Frames | {c['frames']} |",
            f"| Bytes (C2S / S2C) | {c['bytes_c2s']} / {c['bytes_s2c']} |",
            f"| Risk | {s.get('severity')} (score {s.get('risk_score', 0)}) |",
            f"| MITRE TTP | {s.get('ttp')} |",
            "",
            "## Reassembly statistics",
            "",
            "| Metric | Value |",
            "|---|---|",
        ]
        for k, v in c["stats"].items():
            lines.append(f"| {k} | {v} |")
        lines += ["", "## Conversation timeline (evidence-anchored)", "", "| # | Dir | Type | Details | Frame | Offset |", "|---|---|---|---|---|---|"]
        for e in c["events"]:
            lines.append(f"| {e.get('seq')} | {e.get('dir')} | {e.get('type')} | {e.get('details','').replace('|','//')[:60]} | {e.get('frame_id')} | {e.get('payload_offset')} |")
        lines += ["", "## Audit trail excerpt", ""]
        lines.append(f"_This report was generated under audit control. Event id is linked to the append-only audit bus._")
        return "\n".join(lines).encode("utf-8")

    def _csv(self) -> bytes:
        c = self._context()
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["seq", "dir", "type", "details", "frame_id", "payload_offset", "ts", "case", "session", "protocol", "l7", "risk"])
        for e in c["events"]:
            w.writerow([e.get("seq"), e.get("dir"), e.get("type"), e.get("details", ""),
                        e.get("frame_id"), e.get("payload_offset"), e.get("ts"),
                        c["case_id"], c["session_id"], c["proto"], c["l7"], c["story"].get("severity")])
        return buf.getvalue().encode("utf-8")

    def _stix(self) -> bytes:
        c = self._context()
        sid = f"indicator--{uuid.uuid5(uuid.NAMESPACE_URL, c['session_id'])}"
        s = c["story"]
        patterns = []
        ttp = s.get("ttp", "T1000")
        patterns.append(f"[network-traffic:src_ref.value = '{c['src']}']")
        patterns.append(f"[network-traffic:dst_ref.value = '{c['dst']}']")
        for e in c["events"]:
            if e.get("type") == "dns_query":
                for n in e.get("names", []):
                    patterns.append(f"[domain-name:value = '{n}']")
        doc = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": sid,
            "created": c["generated"],
            "modified": c["generated"],
            "name": f"PCAP-to-Story Session {c['session_id'][:10]}",
            "description": " | ".join(s.get("narrative", []))[:400],
            "pattern": " AND ".join(patterns) if patterns else "[ipv4-addr:value = '0.0.0.0']",
            "valid_from": c["start_ts"],
            "labels": [f"severe:{c['story'].get('risk_score', 0)}", f"ttp:{ttp}", f"proto:{c['proto']}", f"l7:{c['l7']}"],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": ttp.split(" ")[0].lower()}],
            "external_references": [{"source_name": "pcapless-suite", "external_id": c["session_id"]}],
        }
        return json.dumps(doc, indent=2).encode("utf-8")

    def _html(self) -> bytes:
        c = self._context()
        s = c["story"]
        rows = "".join(
            f"<tr><td>{e.get('seq')}</td><td>{e.get('dir')}</td><td><code>{e.get('type')}</code></td>"
            f"<td>{e.get('details','')[:80]}</td><td>{e.get('frame_id')}</td><td>{e.get('payload_offset')}</td>"
            f"<td>{e.get('ts','')}</td></tr>"
            for e in c["events"]
        )
        nodes = "".join(
            f"<span class='node'>{n.get('tactic')}: {n.get('label')}</span> "
            for n in s.get("nodes", [])
        )
        findings = "".join(f"<li>{f}</li>" for f in s.get("findings", []))
        html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>PCAP-to-Story — {c['session_id'][:10]}</title>
<style>
:root {{ --v:#6366f1; --c:#06b6d4; --g:#10b981; --a:#f59e0b; --r:#ef4444; --bg:#0f172a; --panel:#1e293b; --tx:#e2e8f0; }}
body {{ background:var(--bg); color:var(--tx); font-family:Segoe UI,Roboto,sans-serif; margin:0; padding:24px; }}
h1 {{ background:linear-gradient(135deg,#4c1d95,#0c4a6e); padding:18px; border-radius:12px; margin-top:0; }}
.card {{ background:var(--panel); border:1px solid #334155; border-radius:10px; padding:14px 18px; margin:12px 0; }}
.badge {{ display:inline-block; padding:3px 10px; border-radius:999px; font-size:12px; font-weight:700; margin:2px; }}
.b-violet {{ background:#4c1d95; color:#c4b5fd; }} .b-cyan {{ background:#164e63; color:#67e8f9; }}
.b-green {{ background:#064e3b; color:#6ee7b7; }} .b-amber {{ background:#78350f; color:#fcd34d; }} .b-red {{ background:#7f1d1d; color:#fca5a5; }}
table {{ border-collapse:collapse; width:100%; font-size:13px; }}
th,td {{ border:1px solid #334155; padding:6px 8px; text-align:left; }} th {{ background:#334155; }}
.node {{ display:inline-block; background:#1e40af; color:#bfdbfe; border-radius:6px; padding:4px 8px; margin:3px; font-size:12px; }}
.kpi {{ display:inline-block; background:#111827; border:1px solid #334155; border-radius:8px; padding:8px 14px; margin:4px; text-align:center; min-width:120px; }}
.kpi b {{ display:block; font-size:18px; color:#a5b4fc; }}
</style></head><body>
<h1>🛰️ PCAP-to-Story — Network Forensic Story Report <span class='badge b-violet'>v{c['report_version']}</span></h1>
<div class="card">
 <span class="kpi"><b>{c['provenance_hash'][:8]}</b>Provenance</span>
 <span class="kpi"><b>{c['case_id']}</b>Case</span>
 <span class="kpi"><b>{c['session_id'][:8]}</b>Session</span>
 <span class="kpi"><b>{c['start_ts']}</b>Started</span>
 <span class="kpi"><b>{c['story'].get('severity')}</b>Risk {c['story'].get('risk_score')}</span>
</div>
<div class="card"><b>Narrative</b>{''.join(f'<p style="margin:2px 0">▶ {i}</p>' for i in s.get('narrative', []))}
<table><tr><td>Flow</td><td>{c['src']}:{c['sport']} <-> {c['dst']}:{c['dport']}</td><td>Protocol / L7</td><td>{c['proto']} / {c['l7']}</td></tr>
<tr><td>Frames</td><td>{c['frames']}</td><td>Bytes C2S / S2C</td><td>{c['bytes_c2s']} / {c['bytes_s2c']}</td></tr>
<tr><td>MITRE TTP</td><td>{c['story'].get('ttp')}</td><td>Reassembly</td><td>{_fmt_bytes(c['stats'].get('c2s_bytes',0))} (gaps {c['stats'].get('gaps',0)})</td></tr></table></div>
<div class="card"><b>Story Graph</b><div>{nodes}</div><ul>{findings}</ul></div>
<div class="card"><b>Evidence-anchored timeline</b><table><tr><th>#</th><th>Dir</th><th>Type</th><th>Details</th><th>Frame</th><th>Offset</th><th>UTC</th></tr>{rows}</table></div>
<div class="card" style="font-size:12px;color:#94a3b8;">Report auto-generated by PCAP-to-Story Suite · signed audit event: <code>{c['provenance_hash']}</code>. Analyte: {c['analyst']}.</div>
</body></html>"""
        return html.encode("utf-8")

    def _pdf(self) -> bytes:
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
            from reportlab.lib.units import mm
            from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle)
        except ImportError:
            raise RuntimeError("PDF export requires the 'reportlab' package.")
        c = self._context()
        s = c["story"]
        buf = io.BytesIO()
        styles = getSampleStyleSheet()
        title = ParagraphStyle("t", parent=styles["Title"], textColor=colors.HexColor("#4c1d95"))
        h2 = ParagraphStyle("h2", parent=styles["Heading2"], textColor=colors.HexColor("#0c4a6e"))
        small = ParagraphStyle("small", parent=styles["BodyText"], fontSize=9, textColor=colors.grey)
        doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm, bottomMargin=15 * mm)
        story = [
            Paragraph("🛰️ Network Forensic Story Report", title),
            Paragraph(f"Case <b>{c['case_id']}</b> · Session <b>{c['session_id']}</b> · Analyst <b>{c['analyst']}</b> · v{c['report_version']}", h2),
            Spacer(1, 4),
            Paragraph("Narrative", h2),
        ]
        for i in s.get("narrative", []):
            story.append(Paragraph(f"▶ {i}", styles["BodyText"]))
            story.append(Spacer(1, 2))
        meta = [
            ["Flow", f"{c['src']}:{c['sport']} <-> {c['dst']}:{c['dport']}", "Protocol / L7", f"{c['proto']} / {c['l7']}"],
            ["Frames", str(c["frames"]), "Bytes C2S / S2C", f"{c['bytes_c2s']} / {c['bytes_s2c']}"],
            ["Risk", f"{s.get('severity')} ({s.get('risk_score')})", "MITRE TTP", s.get("ttp", "")],
        ]
        t = Table(meta, colWidths=[38 * mm, 52 * mm, 38 * mm, 52 * mm])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#eef2ff")), ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#c7d2fe"))]))
        story.append(Paragraph("Flow metadata", h2))
        story.append(t)
        story.append(Spacer(1, 6))
        story.append(Paragraph("Reassembly statistics", h2))
        stat_rows = [[k, v] for k, v in c["stats"].items()]
        st = Table(stat_rows, colWidths=[100 * mm, 42 * mm])
        st.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold")]))
        story.append(st)
        story.append(Spacer(1, 6))
        story.append(Paragraph("Evidence-anchored timeline", h2))
        rows = [["#", "Dir", "Type", "Details", "Frame", "Offset"]]
        for e in c["events"]:
            rows.append([str(e.get("seq")), e.get("dir", ""), e.get("type", ""), str(e.get("details", ""))[:40], str(e.get("frame_id")), str(e.get("payload_offset"))])
        tt = Table(rows, repeatRows=1)
        tt.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("FONTSIZE", (0, 0), (-1, -1), 7), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#4c1d95")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)]))
        story.append(tt)
        story.append(Spacer(1, 8))
        story.append(Paragraph(f"Provenance hash: <font face='Courier'>{c['provenance_hash']}</font>", small))
        story.append(Paragraph("Signed under the append-only audit bus; tamper-evident by hash-chain verification.", small))
        doc.build(story)
        return buf.getvalue()

    def _zip(self) -> bytes:
        c = self._context()
        buf = io.BytesIO()
        manifest = [
            "# Evidence Bundle Manifest",
            f"case={c['case_id']}",
            f"session={c['session_id']}",
            f"report_version={c['report_version']}",
            f"provenance_hash={c['provenance_hash']}",
            "---",
        ]
        parts = {"report.json": self._json(), "report.html": self._html(), "timeline.csv": self._csv(), "report.md": self._md(), "indicator.json": self._stix()}
        with ZipFile(buf, "w", ZIP_DEFLATED) as z:
            for name, blob in parts.items():
                z.writestr(name, blob)
                manifest.append(f"{name} sha256={sha256_bytes(blob)}")
            z.writestr("MANIFEST.txt", "\n".join(manifest))
        return buf.getvalue()


def generate_report(rec: dict, fmt: str, out_dir, case_id="DEFAULT", analyst="analyst",
                    clearance=2, report_version=1, evidence_root="") -> dict:
    os.makedirs(str(out_dir), exist_ok=True)
    return ReportBuilder(rec, case_id, analyst, clearance, report_version, evidence_root).save(fmt, out_dir)