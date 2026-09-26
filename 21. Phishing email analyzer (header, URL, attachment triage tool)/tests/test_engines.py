"""Pytest suite for the analysis engines (header / URL / attachment / content / risk)."""
import base64
import email
import email.policy
import hashlib
import io
import time
import zipfile

import pytest

from src.app.engines import header_engine as HE
from src.app.engines.attachment_engine import AttachmentEngine
from src.app.engines.content_engine import ContentEngine
from src.app.engines.model import AnalysisReport, EngineResult, Finding, Severity
from src.app.engines.risk import score_report
from src.app.engines.url_engine import URLEngine


# ---------------------------------------------------------------------------
# header engine canon (RFC 6376)
# ---------------------------------------------------------------------------
def test_dkim_relaxed_header_lowercases():
    assert HE._relaxed_header(b"From", b"X") == b"from:X"


def test_dkim_relaxed_header_strips_wsp_around_colon():
    assert HE._relaxed_header(b"From", b" X ") == b"from:X"


def test_dkim_simple_body_preserves_whitespace():
    # RFC 6376 3.4.3: trailing lines are stripped and a CRLF is appended
    assert HE._simple_body(b"a\r\n\r\n") == b"a\r\n"


def test_dkim_relaxed_empty_body_null():
    assert HE._relaxed_body(b"") == b""


def test_dkim_relaxed_empty_hash_vector():
    assert base64.b64encode(hashlib.sha256(b"").digest()).decode("ascii") == "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="


# ---------------------------------------------------------------------------
# header engine end-to-end (regression: tag parser must read multi-char tags)
# ---------------------------------------------------------------------------
@pytest.fixture()
def dkim_signed_message():
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    now = int(time.time())
    value_tmpl = (f"v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel; "
                  f"h=from:to:subject; bh={{bh}}; t={now};b=")
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_b64 = base64.b64encode(priv.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).decode("ascii")

    raw_headers = (b"From: Alice Smith <alice@example.com>\r\n"
                   b"To: bob@example.com\r\n"
                   b"Subject: DKIM Test\r\n")
    body = b"Hello Bob, this message is signed.\r\n"
    canon_body = HE._relaxed_body(body)
    bh = base64.b64encode(hashlib.sha256(canon_body).digest()).decode("ascii")

    fields = HE._parse_raw_headers(raw_headers)
    parts = []
    for name in (b"from", b"to", b"subject"):
        n, segs = HE._find_last(fields, name)
        parts.append(HE._canon_field_from_segs(n, segs, "relaxed") + b"\r\n")
    parts.append(HE._relaxed_header(b"d", b"example.com") + b"\r\n")
    parts.append(HE._relaxed_header(b"s", b"sel") + b"\r\n")
    dk = HE._relaxed_header(b"DKIM-Signature", value_tmpl.format(bh=bh).encode("ascii"))
    parts.append(dk + b"\r\n")
    data = b"".join(parts)
    sig = base64.b64encode(priv.sign(data, padding.PKCS1v15(), hashes.SHA256())).decode()
    value = value_tmpl.format(bh=bh) + sig
    full = (raw_headers + b"DKIM-Signature: " + value.encode("ascii") +
            b"\r\n\r\n" + canon_body)
    header_bytes, actual_body = HE._split_raw(full)
    rec = f"v=DKIM1; k=rsa; p={pub_b64}"
    return value, header_bytes, actual_body, HE._parse_raw_headers(header_bytes), rec


def test_dkim_end_to_end_verify_passes(dkim_signed_message):
    value, header_bytes, body, fields, rec = dkim_signed_message
    orig = HE.dns.get_txt
    HE.dns.get_txt = lambda q: [rec] if q == "sel._domainkey.example.com" else []
    try:
        result, detail, _ = HE.verify_dkim_signature(
            b"DKIM-Signature: " + value.encode("ascii"), header_bytes, body, fields)
        assert result == "pass", detail
        # body tamper must now fail
        r2, d2, _ = HE.verify_dkim_signature(
            b"DKIM-Signature: " + value.encode("ascii"), header_bytes, body + b"X", fields)
        assert r2 == "fail", d2
    finally:
        HE.dns.get_txt = orig


# ---------------------------------------------------------------------------
# URL engine
# ---------------------------------------------------------------------------
def test_url_ssrf_private_ip_blocked():
    res = URLEngine(text_body="check http://192.168.1.10/admin now").analyze()
    codes = {f.code: f.severity for f in res.findings}
    assert codes.get("SSRF_BLOCK_IP") == Severity.HIGH


def test_url_embedded_credentials_flagged():
    res = URLEngine(text_body="login http://user:pass@c2.example.net/").analyze()
    codes = {f.code: f.severity for f in res.findings}
    assert codes.get("URL_CREDENTIALS") == Severity.HIGH


def test_url_shortener_flagged():
    res = URLEngine(text_body="see https://bit.ly/abc123").analyze()
    codes = {f.code: f.severity for f in res.findings}
    assert codes.get("URL_SHORTENER") == Severity.MEDIUM


def test_url_deobfuscate():
    res = URLEngine(text_body="url http://%65xample.com/x%3f").analyze()
    assert res.meta  # engine ran


# ---------------------------------------------------------------------------
# Attachment engine
# ---------------------------------------------------------------------------
def _attachment_msg(first_type, first_name, b64_data):
    raw = (b"From: a@b.c\r\nTo: d@e.f\r\nSubject: t\r\nMIME-Version: 1.0\r\n"
           b'Content-Type: multipart/mixed; boundary="XX"\r\n\r\n'
           b"--XX\r\n"
           + f'Content-Type: {first_type}; name="{first_name}"\r\n'.encode()
           + f'Content-Disposition: attachment; filename="{first_name}"\r\n'.encode()
           + b"Content-Transfer-Encoding: base64\r\n\r\n" + b64_data +
           b"\r\n--XX--\r\n")
    return email.message_from_bytes(raw, policy=email.policy.default)


def test_attach_pe_magic_flagged():
    pe = base64.b64encode(b"MZ\x90\x00fake-pe-bytes-00112233")
    msg = _attachment_msg("application/octet-stream", "tool.exe", pe)
    res = AttachmentEngine(msg).analyze()
    codes = {f.code: f.severity for f in res.findings}
    assert codes.get("ATT_EXEC") == Severity.HIGH


def test_attach_ole_macro_flagged():
    ole = base64.b64encode(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" + b"PROJECTVB" + b"Attribut")
    msg = _attachment_msg("application/msword", "macro.doc", ole)
    res = AttachmentEngine(msg).analyze()
    codes = {f.code: f.severity for f in res.findings}
    assert codes.get("ATT_OLE_MACRO") == Severity.HIGH


def test_attach_zip_bomb_profile_flagged():
    zb = io.BytesIO()
    with zipfile.ZipFile(zb, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(2001):
            zf.writestr(f"f{i:05d}.txt", b"x")
    msg = _attachment_msg(
        "application/zip", "archive.zip", base64.b64encode(zb.getvalue()))
    res = AttachmentEngine(msg).analyze()
    codes = {f.code: f.severity for f in res.findings}
    assert codes.get("ATT_ZIP_BOMB") == Severity.HIGH


# ---------------------------------------------------------------------------
# Content engine
# ---------------------------------------------------------------------------
def test_content_engine_flags_phish():
    raw = (b"Subject: t\r\n"
           b'Content-Type: text/plain; charset="utf-8"\r\n\r\n'
           b"URGENT: your account is locked. Verify your password immediately. "
           b"Please send a wire transfer to unlock. Call us now.")
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    res = ContentEngine(msg).analyze()
    codes = {f.code: f.severity for f in res.findings}
    assert codes.get("CRED_REQUEST") == Severity.HIGH
    assert codes.get("PAYMENT_LURE") == Severity.MEDIUM


# ---------------------------------------------------------------------------
# Risk matrix
# ---------------------------------------------------------------------------
def test_risk_quarantine_on_multi_signal():
    rep = AnalysisReport()
    url = EngineResult("url")
    url.findings = [Finding("url", "A", Severity.HIGH, "m", category="malicious")]
    att = EngineResult("attachment")
    att.findings = [Finding("attachment", "B", Severity.HIGH, "m", category="malicious")]
    rep.results["url"] = url
    rep.results["attachment"] = att
    score_report(rep)
    assert rep.verdict == "QUARANTINE"


def test_risk_single_high_sandboxes():
    rep = AnalysisReport()
    c = EngineResult("content")
    c.findings = [Finding("content", "D", Severity.HIGH, "m", category="malicious")]
    rep.results["content"] = c
    score_report(rep)
    assert rep.verdict == "SANDBOX"


def test_risk_no_signals_allow():
    rep = AnalysisReport()
    rep.results["header"] = EngineResult("header")
    score_report(rep)
    assert rep.verdict == "ALLOW"