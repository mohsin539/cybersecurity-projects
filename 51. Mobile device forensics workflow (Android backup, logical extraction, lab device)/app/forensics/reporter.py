import csv
import hashlib
import hmac
import io
import json
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

from . import config
from .audit import AuditJournal
from .evidence import now_iso

ACTOR = "examiner"


def build_report_data(case, inventory=None, keyword_hits=None, timeline=None) -> dict:
    journal = AuditJournal(config.default_vault() / "journal" / "audit.jsonl")
    audit_entries = [e for e in journal.read() if case.id in e.get("detail", "")]
    data = {
        "generated_at": now_iso(),
        "case": case.summary,
        "description": case.description,
        "examiner": case.examiner,
        "opened_at": case.opened_at,
        "exhibits": [e.to_dict() for e in case.evidence],
        "inventory": inventory,
        "keyword_hits": keyword_hits or [],
        "timeline": timeline or [],
        "audit": audit_entries,
        "framework_map": "ISO 27001:2022 | NIST SP 800-101/124 | OWASP Top 10 | SWGDE | ISO 27037",
    }
    return data


def _json_lines(data: dict) -> list[str]:
    yield "=" * 78
    yield "MOBILE DEVICE FORENSICS LAB — SDF-STYLE ARTIFACT REPORT"
    yield "=" * 78
    yield f"Case ID        : {data['case']['case_id']}"
    yield f"Title          : {data['case']['title']}"
    yield f"Description    : {data['description']}"
    yield f"Examiner       : {data['examiner']}"
    yield f"Opened         : {data['opened_at']}"
    yield f"Generated      : {data['generated_at']}"
    yield f"Compliance     : {data['framework_map']}"
    yield "-" * 78
    yield f"Exhibits       : {data['case']['exhibits']}"
    yield f"Total size     : {data['case']['total_bytes']} bytes"
    for z, st in data["case"]["zones"].items():
        yield f"Zone {z:<12}: {st}"
    yield "-" * 78
    yield "EVIDENCE"
    for e in data["exhibits"]:
        yield f"  [{e['exhibit_id']}] {e['description']}"
        yield f"      source={e['source']} sha256={e['sha256'] or 'pending'} size={e['size']} status={e['status']}"
    if data["inventory"]:
        yield "-" * 78
        yield f"INVENTORY ({data['inventory']['file_count']} files, {data['inventory']['total_size']} bytes)"
        cats = data["inventory"]["categories"]["by_kind"]
        yield f"  categories: " + ", ".join(f"{k}={v}" for k, v in cats.items())
        for d in data["inventory"]["sqlite_databases"]:
            yield f"  sqlite: {d['path']} -> {int(d['meta']['tables'])} tables"
    if data["keyword_hits"]:
        yield "-" * 78
        yield f"KEYWORD HITS ({len(data['keyword_hits'])})"
        for h in data["keyword_hits"]:
            yield f"  {h['path']} ({h['size']} bytes) contains '{h['needle']}'"
    if data["timeline"]:
        yield "-" * 78
        yield f"TIMELINE ({len(data['timeline'])})"
        for t in data["timeline"][:40]:
            yield f"  {t['ts']}  {t['path']}"
    yield "-" * 78
    yield "AUDIT TRAIL (hash-linked journal)"
    for e in data["audit"]:
        yield f"  #{e['n']} {e['ts']} [{e['zone']}] {e['action']} — {e['detail']}"
    yield "=" * 78
    yield "END OF REPORT"


def export_json(case, data: dict) -> Path:
    out = case.reports_dir / f"{case.id}_report.json"
    out.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return out


def export_csv(case, data: dict) -> Path:
    out = case.reports_dir / f"{case.id}_tables.csv"
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["SECTION", "field", "value", "note"])
        w.writerow(["case", "id", data["case"]["case_id"], ""])
        for e in data["exhibits"]:
            w.writerow(["evidence", e["uid"], e["sha256"], e["description"]])
        for h in data["keyword_hits"]:
            w.writerow(["keyword", h["path"], h["needle"], h["size"]])
        for t in data["timeline"]:
            w.writerow(["timeline", t["path"], t["ts"], t["size"]])
        for e in data["audit"]:
            w.writerow(["audit", e["ts"], e["action"], e["detail"]])
    return out


def export_xml(case, data: dict) -> Path:
    out = case.reports_dir / f"{case.id}_sdf.xml"
    lines = io.StringIO()
    lines.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    lines.write("<sdfReport version=\"1.0\" xmlns=\"urn:sdf:forensics:1\">\n")
    c = data["case"]
    case_id = xml_escape(c["case_id"])
    lines.write(f'  <case id="{case_id}">\n')
    lines.write(f"    <title>{xml_escape(c['title'])}</title>\n")
    lines.write(f"    <description>{xml_escape(data['description'])}</description>\n")
    lines.write(f"    <examiner>{xml_escape(data['examiner'])}</examiner>\n")
    lines.write(f"    <opened>{xml_escape(data['opened_at'])}</opened>\n")
    for z, st in c["zones"].items():
        lines.write(f"    <zone name=\"{xml_escape(z)}\" status=\"{xml_escape(st)}\"/>\n")
    lines.write("  </case>\n")
    lines.write("  <evidence>\n")
    for e in data["exhibits"]:
        lines.write(f"    <exhibit id=\"{xml_escape(e['exhibit_id'])}\" uid=\"{xml_escape(e['uid'])}\">\n")
        lines.write(f"      <description>{xml_escape(e['description'])}</description>\n")
        lines.write(f"      <sha256>{e['sha256']}</sha256>\n")
        lines.write(f"      <size>{e['size']}</size>\n")
        lines.write(f"      <status>{xml_escape(e['status'])}</status>\n")
        lines.write("    </exhibit>\n")
    lines.write("  </evidence>\n")
    lines.write("  <audit>\n")
    for e in data["audit"]:
        lines.write(
            f"    <entry n=\"{e['n']}\" ts=\"{xml_escape(e['ts'])}\" zone=\"{xml_escape(e['zone'])}\">"
            f"{xml_escape(e['action'])} :: {xml_escape(e['detail'])}</entry>\n"
        )
    lines.write("  </audit>\n")
    lines.write("</sdfReport>\n")
    out.write_text(lines.getvalue(), encoding="utf-8")
    return out


def export_html(case, data: dict) -> Path:
    out = case.reports_dir / f"{case.id}_view.html"
    badges = {
        "intake": "open", "acquisition": "pending", "extraction": "pending",
        "analysis": "pending", "reporting": "pending", "audit": "pending",
    }
    zone_cells = "".join(
        f'<span class="chip {status}">{z}</span>' for z, status in data["case"]["zones"].items()
    )
    exhibit_rows = "".join(
        f"<tr><td>{e['exhibit_id']}</td><td>{xml_escape(e['description'])}</td>"
        f"<td>{e['source']}</td><td>{e['size']}</td><td><code>{e['sha256'] or '-'}</code></td></tr>"
        for e in data["exhibits"]
    )
    audit_rows = "".join(
        f"<tr><td>{e['n']}</td><td>{xml_escape(e['ts'])}</td><td>{xml_escape(e['zone'])}</td>"
        f"<td>{xml_escape(e['action'])} :: {xml_escape(e['detail'])}</td></tr>"
        for e in data["audit"]
    )
    keyword_rows = "".join(
        f"<tr><td>{xml_escape(h['path'])}</td><td>{xml_escape(h['needle'])}</td><td>{h['size']}</td></tr>"
        for h in data["keyword_hits"]
    )
    c = data["case"]
    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{c['case_id']} — Forensic Report</title>
<style>
 body{{font-family:Segoe UI,sans-serif;background:#0d1b2a;color:#e0e1dd;margin:24px}}
 h1{{color:#ffb703}} h2{{color:#4ea8de;border-bottom:1px solid #1b263b;padding-bottom:4px}}
 .card{{background:#1b263b;border-radius:10px;padding:16px;margin:12px 0;border:1px solid #2b3a55}}
 .chip{{display:inline-block;padding:3px 10px;border-radius:20px;margin:3px;font-size:12px}}
 .open,.acquiring{{background:#f57c00;color:#fff}} .pending{{background:#415a77;color:#fff}}
 .done,.complete{{background:#2dcb8b;color:#0d1b2a}}
 table{{border-collapse:collapse;width:100%;font-size:13px;background:#12233b;border-radius:8px;overflow:hidden}}
 th,td{{border:1px solid #2b3a55;padding:6px 9px;text-align:left}}
 th{{background:#1f3a5f;color:#ffb703}} code{{color:#7fd851}}
 footer{{color:#778da9;font-size:12px;margin-top:24px}}
</style></head><body>
<h1>📱 {c['case_id']} — Forensic Artifact Report</h1>
<div class="card"><b>Title:</b> {xml_escape(c['title'])} · <b>Exhibits:</b> {c['exhibits']} · <b>Bytes:</b> {c['total_bytes']}<br>
<b>Examiner:</b> {xml_escape(data['examiner'])} · <b>Generated:</b> {xml_escape(data['generated_at'])}<br>
<b>Compliance:</b> {xml_escape(data['framework_map'])}<br>{zone_cells}</div>
<h2>Evidence Exhibits</h2>
<div class="card"><table><tr><th>Exhibit</th><th>Description</th><th>Source</th><th>Size</th><th>SHA-256</th></tr>{exhibit_rows}</table></div>
<h2>Analysis</h2>
<div class="card"><table><tr><th>Path</th><th>Keyword</th><th>Size</th></tr>{keyword_rows}</table></div>
<h2>Audit Trail</h2>
<div class="card"><table><tr><th>#</th><th>Time</th><th>Zone</th><th>Action</th></tr>{audit_rows}</table></div>
<footer>Generated by Mobile Forensics Lab Portable · Tamper-evident WORM journaling · Offline safe</footer>
</body></html>"""
    out.write_text(html, encoding="utf-8")
    return out


def _docx_paragraph(text: str) -> str:
    return f'<w:p><w:r><w:t xml:space="preserve">{xml_escape(text)}</w:t></w:r></w:p>'


def export_docx(case, data: dict) -> Path:
    out = case.reports_dir / f"{case.id}_report.docx"
    body = "\n".join(_docx_paragraph(line) for line in _json_lines(data))
    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body>{body}</w:body></w:document>"
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        "</Types>"
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
        "</Relationships>"
    )
    import zipfile

    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", rels)
        z.writestr("word/document.xml", document_xml)
    return out


def _pdf_escape(text: str) -> str:
    return text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def export_pdf(case, data: dict) -> Path:
    out = case.reports_dir / f"{case.id}_report.pdf"
    lines = _json_lines(data)
    content = io.BytesIO()
    content.write(b"BT\n/F1 8.5 Tf\n50 800 Td\n")
    for line in lines:
        safe = _pdf_escape(line.encode("latin-1", "replace").decode("latin-1"))
        content.write(f"({safe}) Tj\n0 -12 Td\n".encode("latin-1"))
    content.write(b"ET\n")
    stream = content.getvalue()
    objs = []
    objs.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objs.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objs.append(
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
        b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>"
    )
    objs.append(f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"\nendstream")
    objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")
    buf = io.BytesIO()
    buf.write(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(buf.tell())
        buf.write(f"{i} 0 obj\n".encode())
        buf.write(body)
        buf.write(b"\nendobj\n")
    xref_pos = buf.tell()
    buf.write(b"xref\n0 " + str(len(objs) + 1).encode() + b"\n")
    buf.write(b"0000000000 65535 f \n")
    for off in offsets:
        buf.write(f"{off:010d} 00000 n \n".encode())
    buf.write(
        f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode()
    )
    out.write_bytes(buf.getvalue())
    return out


def sign_file(vault, path: Path) -> str:
    key = config.signing_key(vault)
    h = hmac.new(key, path.read_bytes(), hashlib.sha256)
    return h.hexdigest()


def generate_all(case, data: dict, formats: list[str], vault: Path | None = None) -> list[dict]:
    vault = vault or config.default_vault()
    made = []
    writers = {
        "pdf": export_pdf,
        "docx": export_docx,
        "xml": export_xml,
        "json": export_json,
        "csv": export_csv,
        "html": export_html,
    }
    for fmt in formats:
        if fmt not in writers:
            continue
        p = writers[fmt](case, data)
        sig = sign_file(vault, p)
        rel = str(p.relative_to(case.root))
        case.add_report(f"{fmt.upper()} report", rel)
        case.reports[-1]["sha256"] = sig
        made.append({"format": fmt, "path": rel, "hmac_sha256": sig})
    case.save()
    return made