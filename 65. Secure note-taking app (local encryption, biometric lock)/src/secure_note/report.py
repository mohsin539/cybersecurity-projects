"""Report Generator & Download Center (architecture.md Â§11).

Local-only generation; every bundle is digitally signed (P-256 via ECDSA)
and timestamped. Outputs: PDF, CSV, JSON, and a signed ZIP attestation
package â€” written to the user-selected export directory.
"""

from __future__ import annotations

import csv
import io
import json
import os
import time
import uuid
import zipfile

from . import policy

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import (
        encode_dss_signature, Prehashed,
    )
    _CRYPTO_AVAIL = True
except Exception:  # pragma: no cover
    _CRYPTO_AVAIL = False


class ReportError(Exception):
    pass


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _json_script(doc) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False)


def _pdf_safe(s) -> str:
    """Collapse characters outside latin-1 so the built-in Helvetica font renders."""
    return "".join(ch if ord(ch) < 256 else "?" for ch in str(s))


def build_pdf(compliance_rows, summaries, audit_rows, evidence, out_path: str) -> str:
    """Render a compliance + posture PDF using the built-in Helvetica font."""
    try:
        from fpdf import FPDF
    except Exception as e:
        import traceback
        raise ReportError(f"fpdf2 import failed: {type(e).__name__}: {e}\n{traceback.format_exc()}")

    pdf = FPDF(format="A4")
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.add_page()

    # header block
    pdf.set_fill_color(24, 42, 77)
    pdf.rect(0, 0, 210, 26, "F")
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 17)
    pdf.set_y(9)
    pdf.cell(0, 9, "SecureNote Pro  -  Security Compliance Report", ln=1)
    pdf.set_font("Helvetica", "", 8)
    pdf.set_y(19)
    pdf.cell(0, 5, f"Generated locally: {_now()}   |   Engine: offline-only   |   No data leaves device",
             ln=1)
    pdf.set_text_color(0, 0, 0)
    pdf.ln(6)

    # summaries
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(24, 42, 77)
    pdf.cell(0, 8, "1. Framework Posture Summary", ln=1)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(0, 0, 0)
    for s in summaries:
        shade = (211, 236, 217) if s["score"] >= 90 else ((255, 244, 204) if s["score"] >= 60 else (255, 205, 210))
        pdf.set_fill_color(*shade)
        pdf.set_font("Helvetica", "B", 9)
        text = f"{s['framework']}   ->   {s['passed']}/{s['total']} controls passed   [{s['score']:.1f}%]"
        pdf.cell(0, 7, _pdf_safe(text), fill=1)
        pdf.set_font("Helvetica", "", 9)
        pdf.ln(7)
    pdf.ln(3)

    # compliance matrix
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(24, 42, 77)
    pdf.cell(0, 8, "2. Control Evidence Matrix", ln=1)
    pdf.set_text_color(0, 0, 0)
    col_w = (210 - 28) / 6.0
    headers = ["Control", "Title", "Status", "Rationale"]
    pdf.set_font("Helvetica", "B", 8)
    for i, h in enumerate(headers):
        pdf.cell([col_w * 1.1, col_w * 2.0, col_w * 0.8, col_w * 2.1][i], 6, _pdf_safe(h), border=1)
    pdf.ln()
    pdf.set_font("Helvetica", "", 8)
    for r in compliance_rows:
        if r["status"] == "PASS":
            pdf.set_text_color(30, 130, 76)
        else:
            pdf.set_text_color(200, 60, 60)
        pdf.cell(col_w * 1.1, 6, _pdf_safe(r["control"]), border=1)
        pdf.set_text_color(0, 0, 0)
        pdf.cell(col_w * 2.0, 6, _pdf_safe(r["title"][:42]), border=1)
        pdf.cell(col_w * 0.8, 6, _pdf_safe(r["status"]), border=1)
        pdf.cell(col_w * 2.1, 6, _pdf_safe(r["rationale"][:60]), border=1)
        pdf.ln()
    pdf.ln(4)

    # audit excerpt
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(24, 42, 77)
    pdf.cell(0, 8, "3. Audit Ledger Excerpt (last 50 events)", ln=1)
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "B", 8)
    for h in ["#", "ts", "action", "result"]:
        pdf.cell(52, 6, _pdf_safe(h), border=1)
    pdf.ln()
    pdf.set_font("Helvetica", "", 7)
    for row in audit_rows[-50:]:
        pdf.cell(10, 5, _pdf_safe(row.get("seq", "")), border=1)
        pdf.cell(30, 5, _pdf_safe(str(row.get("ts") or "")[:19]), border=1)
        pdf.cell(80, 5, _pdf_safe(str(row.get("action") or "")[:40]), border=1)
        pdf.cell(52, 5, _pdf_safe(str(row.get("result") or "")[:26]), border=1)
        pdf.ln()

    pdf.output(out_path)
    return out_path


def _sign(manifest_blob: bytes, signer) -> str:
    if not _CRYPTO_AVAIL or signer is None:
        return "unsigned-in-demo-mode"
    private_key, public_key = signer
    signature = private_key.sign(manifest_blob, ec.ECDSA(hashes.SHA256()))
    return {
        "algorithm": "ECDSA-P256-SHA256",
        "signature": signature.hex(),
        "public_key": public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode(),
    }


def load_or_create_signer(signer_path: str):
    """P-256 signer persisted (DPAPI-protected)."""
    from . import dpapi_binding as dpapi
    if _CRYPTO_AVAIL and os.path.exists(signer_path):
        try:
            raw = dpapi.dpapi_unprotect(open(signer_path, "rb").read())
            private_key = serialization.load_pem_private_key(raw, password=None)
            return private_key, private_key.public_key()
        except Exception:
            pass
    private_key = ec.generate_private_key(ec.SECP256R1())
    if _CRYPTO_AVAIL:
        pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        os.makedirs(os.path.dirname(signer_path), exist_ok=True)
        with open(signer_path, "wb") as f:
            f.write(dpapi.dpapi_protect(pem))
    return private_key, private_key.public_key()


def generate_reports(
    vault,
    audit_ledger,
    dest_dir: str,
    signer_path: str,
    kinds: tuple[str, ...] = ("compliance", "audit", "attestation"),
) -> dict:
    """Generate report artifacts into dest_dir and return their paths."""
    os.makedirs(dest_dir, exist_ok=True)
    report_id = f"RN-{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"

    evidence = policy.collect_evidence(vault, audit_ledger)
    rows = policy.score(evidence)
    summaries = policy.summarize(rows)

    artifacts: dict[str, str] = {}
    if "compliance" in kinds or "posture" in kinds:
        jp = os.path.join(dest_dir, f"report_{report_id}.json")
        with open(jp, "w", encoding="utf-8") as f:
            f.write(_json_script({
                "report_id": report_id,
                "generated": _now(),
                "framework_posture": summaries,
                "controls": rows,
                "evidence": {k: str(v) for k, v in evidence.items()},
            }))
        artifacts["json"] = jp

        if "compliance" in kinds:
            try:
                pp = os.path.join(dest_dir, f"report_{report_id}.pdf")
                build_pdf(rows, summaries, audit_ledger.export_rows(), evidence, pp)
                artifacts["pdf"] = pp
            except ReportError as e:
                artifacts["pdf"] = ""
                artifacts["pdf_error"] = str(e)
    else:
        jp = os.path.join(dest_dir, f"posture_{report_id}.json")
        with open(jp, "w", encoding="utf-8") as f:
            f.write(_json_script({"report_id": report_id, "generated": _now(),
                                  "framework_posture": summaries}))
        artifacts["json"] = jp

    if "audit" in kinds:
        rows_ = audit_ledger.export_rows()
        cp = os.path.join(dest_dir, f"audit_{report_id}.csv")
        with open(cp, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["seq", "ts", "action", "result", "category", "details"])
            w.writeheader()
            w.writerows(rows_)
        artifacts["csv"] = cp
        vp = os.path.join(dest_dir, f"audit_verify_{report_id}.json")
        with open(vp, "w", encoding="utf-8") as f:
            f.write(_json_script(audit_ledger.verify_chain()))
        artifacts["audit_verify"] = vp

    if "attestation" in kinds:
        zip_path = os.path.join(dest_dir, f"attestation_{report_id}.zip")
        signer = load_or_create_signer(signer_path)
        manifest = []
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
            for label, p in artifacts.items():
                if os.path.exists(p):
                    z.write(p, os.path.basename(p))
                    manifest.append({"artifact": os.path.basename(p), "sha256": _sha256_file(p)})
            manifest.append({"generated": _now(), "report_id": report_id})
            manifest_blob = json.dumps(manifest, indent=2).encode("utf-8")
            z.writestr("MANIFEST.json", manifest_blob)
            z.writestr("SIGNATURE.json", _json_script(_sign(manifest_blob, signer)))
        artifacts["zip"] = zip_path

    return {"report_id": report_id, "dir": dest_dir, "artifacts": artifacts,
            "summaries": summaries, "evidence": evidence}


def _sha256_file(p: str) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()