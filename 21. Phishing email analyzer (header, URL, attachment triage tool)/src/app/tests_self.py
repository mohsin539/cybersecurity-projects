"""Headless security/engine self-tests. No GUI, no real network.

Run:  py -3.12 -m app.main --self-test

Covers (with control references):
  - AES-256-GCM round-trip, tamper/wrong-key fail-closed   [A02 / SC-28]
  - Hash-chained audit: append + offline tamper detection  [A09 / AU-3]
  - Identity: create/auth, wrong-password, lockout (AC-7),
    password rotation preserves the wrapped data_key        [A07 / IA-5]
  - RFC 6376 canonicalization test vectors (Appendix A)     [DKIM]
  - End-to-end DKIM sign -> inject -> verify + body-tamper
  - URL engine: SSRF private-literal block, credential URLs,
    shorteners, typosquat, text/href mismatch              [A10 / A03]
  - Attachment: magic bytes, PE/executable, zip-bomb, OLE macro
  - Content: phishing keywords, credential request, payment lure
  - Risk matrix fail-closed (QUARANTINE on multi-signal)
  - Full pipeline over a crafted phishing email -> QUARANTINE
  - Encrypted-at-rest: no plaintext secrets on disk
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import tempfile
import time
import zipfile

from .sec import constants as C

OK = 0
FAIL = 1


class Result:
    def __init__(self):
        self.failures = []

    def check(self, name: str, cond: bool, info: str = "") -> None:
        if cond:
            print(f"  [PASS] {name}")
        else:
            print(f"  [FAIL] {name} {info}")
            self.failures.append((name, info))

    @property
    def ok(self) -> bool:
        return not self.failures


# ---------------------------------------------------------------------------
# Cryptography
# ---------------------------------------------------------------------------

def _test_crypto(r: Result) -> None:
    from .sec.crypto import (SecurityError, decrypt_bytes, encrypt_bytes,
                             derive_key)

    key = derive_key("correct horse battery staple", b"sea-salt" * 2)
    blob = encrypt_bytes(b"top secret classification data", key, b"ctx/case-1")
    r.check("crypto: round-trip", decrypt_bytes(blob, key, b"ctx/case-1") ==
            b"top secret classification data")
    bad = bytearray(blob)
    bad[len(bad) // 2] ^= 0xFF
    try:
        decrypt_bytes(bytes(bad), key, b"ctx/case-1")
        r.check("crypto: tamper detected", False, "no SecurityError on tampered blob")
    except SecurityError:
        r.check("crypto: tamper detected", True)
    try:
        decrypt_bytes(blob, key, b"ctx/other")
        r.check("crypto: AAD binds context", False, "AAD not enforced")
    except SecurityError:
        r.check("crypto: AAD binds context", True)
    try:
        decrypt_bytes(blob, derive_key("wrong passphrase", b"sea-salt" * 2),
                      b"ctx/case-1")
        r.check("crypto: wrong key fails", False, "wrong key decrypted")
    except SecurityError:
        r.check("crypto: wrong key fails", True)
    r.check("crypto: empty plaintext",
            decrypt_bytes(encrypt_bytes(b"", key), key) == b"")
    # nonce uniqueness: two encryptions of same input differ
    r.check("crypto: nonce is unique",
            encrypt_bytes(b"s", key) != encrypt_bytes(b"s", key))


# ---------------------------------------------------------------------------
# Input validation (SI-10, fail-closed)
# ---------------------------------------------------------------------------

def _test_validation(r: Result) -> None:
    from .sec.validation import (validate_email_bytes, is_private_ip,
                                 sanitize_filename, InputError)

    try:
        validate_email_bytes(b"x" * (C.MAX_EMAIL_BYTES + 1))
        r.check("validation: oversize rejected", False)
    except InputError:
        r.check("validation: oversize rejected", True)
    try:
        validate_email_bytes(b"From: a\r\n\r\n\x00body")
        r.check("validation: NUL byte rejected", False)
    except InputError:
        r.check("validation: NUL byte rejected", True)
    try:
        validate_email_bytes(b"Subject: hi\r\n\r\n" + b"\n" * 200_001)
        r.check("validation: line bomb rejected", False)
    except InputError:
        r.check("validation: line bomb rejected", True)
    r.check("validation: private IP SSRF guard",
            is_private_ip("127.0.0.1") and is_private_ip("10.0.0.5") and
            is_private_ip("169.254.0.1") and is_private_ip("172.16.3.4") and
            is_private_ip("0.0.0.0"))
    r.check("validation: public IP allowed", not is_private_ip("8.8.8.8"))
    r.check("validation: filename sanitized",
            sanitize_filename("..\\..\\evil?.exe") == "....evil_.exe" or
            "/" not in sanitize_filename("a/b/c.exe"))


# ---------------------------------------------------------------------------
# Audit log tamper-evidence
# ---------------------------------------------------------------------------

def _test_audit(r: Result) -> None:
    from .sec.audit import AuditLog
    from .sec import constants as C_aud

    with tempfile.TemporaryDirectory() as tmp:
        log = AuditLog(os.path.join(tmp, "audit"),
                       hashlib.sha256(b"audit-test-key").digest())
        for i in range(5):
            log.append("LOGIN_SUCCESS", "alice", "admin", target=f"session-{i}")
        log.append("CASE_ANALYZED", "alice", "admin", target="case-1")
        problems = log.verify()
        r.check("audit: chain verifies clean", problems == [], str(problems))
        r.check("audit: entries readable", len(log.tail(10)) == 6)
        # offline tamper: flip one byte in a batch file
        batch = log.batches[min(log.batches)]
        raw = bytearray(open(batch, "rb").read())
        raw[len(raw) // 2] ^= 0x01
        with open(batch, "wb") as fh:
            fh.write(bytes(raw))
        r.check("audit: tamper detected", log.verify() != [])


# ---------------------------------------------------------------------------
# Identity / RBAC / lockout
# ---------------------------------------------------------------------------

def _test_identity(r: Result) -> None:
    from .sec import identity as ID
    from .sec import constants as C_orig

    # speed: reduce KDF iterations for the test run (constant is read live)
    C_orig.PBKDF2_ITERATIONS = 2000
    orig_sleep = ID.time.sleep
    ID.time.sleep = lambda _s: None
    try:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "profile.dat")
            store = ID.IdentityStore(path)
            store.create_profile("alice.sec", "CorrectHorse@2024!", "admin")
            r.check("identity: profile created", store.profile_exists())
            tok, key1 = store.authenticate("alice.sec", "CorrectHorse@2024!")
            r.check("identity: auth ok", tok["role"] == "admin" and len(key1) == 32)
            try:
                store.authenticate("alice.sec", "wrong-password-1")
                r.check("identity: wrong password rejected", False)
            except ID.AuthError:
                r.check("identity: wrong password rejected", True)
            # lockout after repeated failures (AC-7)
            locked = False
            for _ in range(C_orig.LOGIN_MAX_ATTEMPTS):
                try:
                    store.authenticate("alice.sec", "wrong-password-1")
                except ID.AuthError:
                    pass
            try:
                store.authenticate("alice.sec", "CorrectHorse@2024!")
                r.check("identity: lockout enforced", False, "auth succeeded while locked")
            except ID.AuthError as exc:
                locked = "locked" in str(exc).lower()
                r.check("identity: lockout enforced", locked, str(exc))
            # lockout expires (or admin clears) before continuing
            store._clear_lockout("alice.sec")
            # password change preserves the wrapped data_key
            store2 = ID.IdentityStore(path)
            _, key2 = store2.authenticate("alice.sec", "CorrectHorse@2024!")
            store2.change_password("alice.sec", "CorrectHorse@2024!", "NewHorse@2024!")
            store3 = ID.IdentityStore(path)
            _, key3 = store3.authenticate("alice.sec", "NewHorse@2024!")
            r.check("identity: password rotation keeps data_key",
                    key1 == key2 == key3,
                    "data_key changed across password rotation")
            try:
                ID.IdentityStore(path).authenticate(
                    "alice.sec", "CorrectHorse@2024!")
                r.check("identity: old password dead after rotation", False)
            except ID.AuthError:
                r.check("identity: old password dead after rotation", True)
            # RBAC role matrix
            s = ID.Session("alice.sec", "analyst", key1, "NewHorse@2024!")
            r.check("identity: analyst blocked from delete",
                    not s.can("delete_case"))
            r.check("identity: analyst can analyze", s.can("analyze"))
    finally:
        C_orig.PBKDF2_ITERATIONS = 600_000
        ID.time.sleep = orig_sleep


# ---------------------------------------------------------------------------
# RFC 6376 canonicalization vectors
# ---------------------------------------------------------------------------

def _test_canonicalization(r: Result) -> None:
    from .engines.header_engine import (_relaxed_header, _relaxed_body,
                                        _simple_body)

    # RFC 6376 3.4.5 example: relaxed header canonicalization
    rh = _relaxed_header(b"A", b" X")
    r.check("dkim: relaxed 'A: X' -> 'a:X'", rh == b"a:X", repr(rh))
    rh2 = _relaxed_header(b"B  ", b" Y \t\r\n \t Z  ")
    r.check("dkim: relaxed folded 'B' -> 'b:Y Z'", rh2 == b"b:Y Z", repr(rh2))

    # body canonicalization (RFC 6376 3.4.5 example 1)
    body = b" C \r\nD \t E\r\n\r\n\r\n"
    r.check("dkim: simple body preserves whitespace",
            _simple_body(body) == b" C \r\nD \t E\r\n", repr(_simple_body(body)))
    r.check("dkim: relaxed body trims/collapses",
            _relaxed_body(body) == b" C\r\nD E\r\n", repr(_relaxed_body(body)))

    # empty body rules: simple -> single CRLF, relaxed -> null input
    r.check("dkim: simple empty body = CRLF", _simple_body(b"") == b"\r\n")
    r.check("dkim: relaxed empty body = null", _relaxed_body(b"") == b"")
    h1 = base64.b64encode(hashlib.sha256(_simple_body(b"")).digest()).decode()
    h2 = base64.b64encode(hashlib.sha256(_relaxed_body(b"")).digest()).decode()
    r.check("dkim: simple empty body hash vector",
            h1 == "frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=", h1)
    r.check("dkim: relaxed empty body hash vector",
            h2 == "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", h2)


# ---------------------------------------------------------------------------
# End-to-end DKIM: sign -> inject -> verify (+ body tamper)
# ---------------------------------------------------------------------------

def _test_dkim_roundtrip(r: Result) -> None:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    from .engines import header_engine as HE

    now = int(time.time())
    value_tmpl = (f"v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel; "
                  f"h=from:to:subject; bh={{bh}}; t={now};b=")

    def sign_headers(raw_headers: bytes, body: bytes, priv) -> tuple:
        canon_body = HE._relaxed_body(body)
        bh = base64.b64encode(hashlib.sha256(canon_body).digest()).decode("ascii")
        fields = HE._parse_raw_headers(raw_headers)
        parts = []
        for name in (b"from", b"to", b"subject"):
            last = HE._find_last(fields, name)
            parts.append(HE._canon_field_from_segs(last[0], last[1], "relaxed") + b"\r\n")
        parts.append(HE._relaxed_header(b"d", b"example.com") + b"\r\n")
        parts.append(HE._relaxed_header(b"s", b"sel") + b"\r\n")
        dk = HE._relaxed_header(b"DKIM-Signature", value_tmpl.format(bh=bh).encode("ascii"))
        parts.append(dk + b"\r\n")
        data = b"".join(parts)
        sig = base64.b64encode(priv.sign(data, padding.PKCS1v15(), hashes.SHA256())).decode()
        return value_tmpl.format(bh=bh) + sig, canon_body

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_b64 = base64.b64encode(priv.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)).decode("ascii")

    raw_headers = (b"From: Alice Smith <alice@example.com>\r\n"
                   b"To: bob@example.com\r\n"
                   b"Subject: DKIM Test\r\n")
    body = b"Hello Bob, this message is signed.\r\n"

    value, canon_body = sign_headers(raw_headers, body, priv)
    full = (raw_headers + b"DKIM-Signature: " + value.encode("ascii") +
            b"\r\n\r\n" + canon_body)
    header_bytes, actual_body = HE._split_raw(full)
    fields = HE._parse_raw_headers(header_bytes)

    orig_get_txt = HE.dns.get_txt
    HE.dns.get_txt = lambda q: (
        [f"v=DKIM1; k=rsa; p={pub_b64}"] if q == "sel._domainkey.example.com" else [])

    try:
        result, detail, desc = HE.verify_dkim_signature(
            b"DKIM-Signature: " + value.encode("ascii"),
            header_bytes, actual_body, fields)
        r.check("dkim: end-to-end verify passes", result == "pass", f"{result} {detail}")
        # body tamper must now fail (bh= mismatch)
        tampered_body = actual_body + b"X"
        result2, detail2, _ = HE.verify_dkim_signature(
            b"DKIM-Signature: " + value.encode("ascii"),
            header_bytes, tampered_body, fields)
        r.check("dkim: body tamper fails", result2 == "fail", f"{result2} {detail2}")
        # header tamper must fail
        tampered_headers = header_bytes.replace(b"Subject: DKIM Test",
                                                b"Subject: Altered Title")
        fields3 = HE._parse_raw_headers(tampered_headers)
        result3, detail3, _ = HE.verify_dkim_signature(
            b"DKIM-Signature: " + value.encode("ascii"),
            tampered_headers, actual_body, fields3)
        r.check("dkim: header tamper fails", result3 == "fail", f"{result3} {detail3}")
    finally:
        HE.dns.get_txt = orig_get_txt


# ---------------------------------------------------------------------------
# URL engine
# ---------------------------------------------------------------------------

def _test_url_engine(r: Result) -> None:
    from .engines.url_engine import URLEngine
    from .engines.model import Severity

    codes = {}
    res = URLEngine(text_body="check http://192.168.1.10/admin now").analyze()
    for f in res.findings:
        codes[f.code] = f.severity
    r.check("url: SSRF private literal blocked",
            codes.get("SSRF_BLOCK_IP") == Severity.HIGH, str(codes))

    codes = {}
    res = URLEngine(text_body="login http://user:pass@c2.example.net/").analyze()
    for f in res.findings:
        codes[f.code] = f.severity
    r.check("url: embedded credentials flagged",
            codes.get("URL_CREDENTIALS") == Severity.HIGH, str(codes))

    codes = {}
    res = URLEngine(text_body="see https://bit.ly/abc123").analyze()
    for f in res.findings:
        codes[f.code] = f.severity
    r.check("url: shortener flagged", codes.get("URL_SHORTENER") == Severity.MEDIUM)

    codes = {}
    res = URLEngine(text_body="click http://paypa1.com/login").analyze()
    for f in res.findings:
        codes[f.code] = f.severity
    r.check("url: typosquat one-edit detected",
            codes.get("URL_TYPO") == Severity.MEDIUM, str(codes))

    codes = {}
    res = URLEngine(text_body="http://paypal-security.com/verify").analyze()
    for f in res.findings:
        codes[f.code] = f.severity
    r.check("url: brand-abuse domain detected",
            codes.get("URL_BRAND_TYPO") == Severity.HIGH, str(codes))

    codes = {}
    res = URLEngine(html_body='<a href="http://evil.evil/">http://paypal.com/secure</a>').analyze()
    for f in res.findings:
        codes[f.code] = f.severity
    r.check("url: text/href mismatch detected",
            codes.get("TEXT_HREF_MISMATCH") == Severity.HIGH, str(codes))

    res = URLEngine(text_body="just a note, no links").analyze()
    r.check("url: no-urls informational",
            any(f.code == "NO_URLS" for f in res.findings))

    # de-obfuscation: percent-encoding + html entity colon
    eng = URLEngine()
    r.check("url: deobfuscate percent + entity",
            eng._deobfuscate("http%3A//x.com/a?b=1&c=2&d=3&e=4") == "http://x.com/a?b=1&c=2&d=3&e=4",
            eng._deobfuscate("http%3A//x.com/a?b=1&c=2&d=3&e=4"))


# ---------------------------------------------------------------------------
# Attachment engine
# ---------------------------------------------------------------------------

def _test_attachment_engine(r: Result) -> None:
    import email
    import email.policy

    from .engines.attachment_engine import (AttachmentEngine, detect_magic,
                                            shannon_entropy)
    from .engines.model import Severity

    r.check("attach: PE magic", detect_magic(b"MZ\x90\x00") == "pe")
    r.check("attach: OLE magic", detect_magic(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") == "ole")
    r.check("attach: PDF magic", detect_magic(b"%PDF-1.7") == "pdf")
    r.check("attach: entropy low for zeros", shannon_entropy(b"\x00" * 4096) < 0.1)
    r.check("attach: entropy high for random",
            shannon_entropy(os.urandom(4096)) > 7.5)

    # executable disguised as PDF + macro OLE
    b64_pdf = base64.b64encode(b"MZ\x90\x00fake-pe-bytes-go-here-0123456789")
    b64_ole = base64.b64encode(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" + b"PROJECTVB" + b"Attribut")
    raw = (b"From: a@b.c\r\nTo: d@e.f\r\nSubject: t\r\nMIME-Version: 1.0\r\n"
           b'Content-Type: multipart/mixed; boundary="XX"\r\n\r\n'
           b"--XX\r\n"
           b'Content-Type: text/plain; name="invoice.pdf"\r\n'
           b'Content-Disposition: attachment; filename="invoice.pdf"\r\n'
           b"Content-Transfer-Encoding: base64\r\n\r\n" + b64_pdf +
           b"\r\n--XX\r\n"
           b'Content-Type: application/msword; name="macro.doc"\r\n'
           b'Content-Disposition: attachment; filename="macro.doc"\r\n'
           b"Content-Transfer-Encoding: base64\r\n\r\n" + b64_ole +
           b"\r\n--XX--\r\n")
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    res = AttachmentEngine(msg).analyze()
    codes = {f.code: f.severity for f in res.findings}
    r.check("attach: PE under PDF name flagged",
            codes.get("ATT_MIMESPOOF") == Severity.HIGH, str(codes))
    r.check("attach: OLE macro markers flagged",
            codes.get("ATT_OLE_MACRO") == Severity.HIGH, str(codes))

    # zip bomb profile (many entries)
    zb = io.BytesIO()
    with zipfile.ZipFile(zb, "w", zipfile.ZIP_DEFLATED) as zf:
        for i in range(2001):
            zf.writestr(f"f{i:05d}.txt", b"x")
    raw2 = (b"From: a@b.c\r\nTo: d@e.f\r\nSubject: z\r\nMIME-Version: 1.0\r\n"
            b'Content-Type: multipart/mixed; boundary="ZZ"\r\n\r\n'
            b"--ZZ\r\n"
            b'Content-Type: application/zip; name="archive.zip"\r\n'
            b'Content-Disposition: attachment; filename="archive.zip"\r\n'
            b"Content-Transfer-Encoding: base64\r\n\r\n" +
            base64.b64encode(zb.getvalue()) +
            b"\r\n--ZZ--\r\n")
    msg2 = email.message_from_bytes(raw2, policy=email.policy.default)
    res2 = AttachmentEngine(msg2).analyze()
    codes2 = {f.code: f.severity for f in res2.findings}
    r.check("attach: zip-bomb profile flagged",
            codes2.get("ATT_ZIP_BOMB") == Severity.HIGH, str(codes2))


# ---------------------------------------------------------------------------
# Content engine
# ---------------------------------------------------------------------------

def _test_content_engine(r: Result) -> None:
    import email
    import email.policy

    from .engines.content_engine import ContentEngine
    from .engines.model import Severity

    raw = (b"Subject: t\r\n"
           b'Content-Type: text/plain; charset="utf-8"\r\n\r\n'
           b"URGENT: your account is locked. Verify your password immediately. "
           b"Please send a wire transfer to unlock. Call us now.")
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    res = ContentEngine(msg).analyze()
    codes = {f.code: f.severity for f in res.findings}
    r.check("content: credential request HIGH",
            codes.get("CRED_REQUEST") == Severity.HIGH, str(codes))
    r.check("content: payment lure flagged",
            codes.get("PAYMENT_LURE") == Severity.MEDIUM, str(codes))
    r.check("content: keyword evidence present",
            codes.get("PHISH_KEYWORDS") == Severity.MEDIUM, str(codes))


# ---------------------------------------------------------------------------
# Risk matrix (fail-closed)
# ---------------------------------------------------------------------------

def _test_risk(r: Result) -> None:
    from .engines.model import AnalysisReport, EngineResult, Finding, Severity
    from .engines.risk import score_report

    rep = AnalysisReport()
    sev = EngineResult("url")
    sev.findings = [
        Finding("url", "A", Severity.HIGH, "m", category="malicious"),
        Finding("url", "B", Severity.MEDIUM, "m", category="anomaly"),
    ]
    att = EngineResult("attachment")
    att.findings = [Finding("attachment", "C", Severity.HIGH, "m", category="malicious")]
    rep.results["url"] = sev
    rep.results["attachment"] = att
    score_report(rep)
    r.check("risk: multi-signal -> QUARANTINE",
            rep.verdict == "QUARANTINE", rep.verdict)
    r.check("risk: score non-zero", 0 < rep.risk_score <= 100, str(rep.risk_score))

    rep2 = AnalysisReport()
    m = EngineResult("content")
    m.findings = [Finding("content", "D", Severity.HIGH, "m", category="malicious")]
    rep2.results["content"] = m
    score_report(rep2)
    r.check("risk: single high -> SANDBOX", rep2.verdict == "SANDBOX", rep2.verdict)

    rep3 = AnalysisReport()
    rep3.results["header"] = EngineResult("header")
    score_report(rep3)
    r.check("risk: no signals -> ALLOW", rep3.verdict == "ALLOW", rep3.verdict)


# ---------------------------------------------------------------------------
# Full pipeline over crafted phishing email -> QUARANTINE (fail-closed)
# ---------------------------------------------------------------------------

def _test_full_pipeline(r: Result) -> None:
    from .analysis import analyze_raw_email
    from .engines import header_engine as HE

    date_hdr = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
    headers = (f"Delivered-To: victim@example.com\r\n"
               f"Return-Path: <bounces@paypa1.com>\r\n"
               f"From: \"PayPal Support\" <secure@paypa1.com>\r\n"
               f"To: victim@example.com\r\n"
               f"Subject: Your account has been suspended\r\n"
               f"Date: {date_hdr}\r\n"
               f"Message-ID: <abc123@paypa1.com>\r\n"
               f"Reply-To: attacker@malicious-service.ru\r\n"
               f"MIME-Version: 1.0\r\n"
               f'Content-Type: multipart/mixed; boundary="B0"\r\n\r\n').encode("utf-8")
    exe = base64.b64encode(b"MZ\x90\x00fake-executable-bytes-00112233")
    body_block = (b"--B0\r\n"
                  b'Content-Type: text/plain; charset="utf-8"\r\n\r\n'
                  b"URGENT: your account has been locked due to unusual activity. "
                  b"Verify your password IMMEDIATELY or your email will be deleted. "
                  b"Open now: http://paypal-security.com/account/verify "
                  b"(short: https://bit.ly/xyz).\r\n"
                  b"--B0\r\n"
                  b'Content-Type: application/octet-stream; name="invoice.pdf.exe"\r\n'
                  b'Content-Disposition: attachment; filename="invoice.pdf.exe"\r\n'
                  b"Content-Transfer-Encoding: base64\r\n\r\n"
                  + exe + b"\r\n--B0--\r\n")
    raw = headers + body_block

    # No real DNS in self-test: stub lookup functions (fail-closed -> 'none')
    orig = {k: getattr(HE.dns, k) for k in
            ("get_txt", "get_a", "get_mx", "secure_resolve_host", "dns_available")}
    for k in ("get_txt", "get_a", "get_mx", "secure_resolve_host"):
        setattr(HE.dns, k, lambda *a, **kw: [])
    HE.dns.dns_available = lambda: False
    benign = (f"From: jenny@example.org\r\nDate: {date_hdr}\r\n"
              f"Subject: Lunch tomorrow?\r\nContent-Type: text/plain\r\n\r\n"
              f"Hi, are you free for lunch tomorrow? -- Jen\r\n").encode()
    try:
        report = analyze_raw_email(raw, resolve_hosts=False)
        rep2 = analyze_raw_email(benign, resolve_hosts=False)
    finally:
        for k, v in orig.items():
            setattr(HE.dns, k, v)

    r.check("pipeline: phishing email quarantined (fail-closed)",
            report.verdict == "QUARANTINE",
            f"verdict={report.verdict} score={report.risk_score}")
    r.check("pipeline: high risk score", report.risk_score >= 70,
            str(report.risk_score))
    codes = {f.code for f in report.all_findings()}
    must = {"DISPLAY_SPOOF", "URL_BRAND_TYPO", "URL_SHORTENER", "ATT_EXEC",
            "ATT_DOUBLE_EXT", "CRED_REQUEST", "PHISH_KEYWORDS"}
    missing = must - codes
    r.check("pipeline: expected signals present", not missing, str(missing))
    # benign message must NOT quarantine
    r.check("pipeline: benign mail not over-blocked",
            rep2.verdict in ("ALLOW", "FLAG"), rep2.verdict)


# ---------------------------------------------------------------------------
# Encrypted at rest: no plaintext secrets on disk
# ---------------------------------------------------------------------------

def _test_at_rest(r: Result) -> None:
    from .data.settings import SettingsVault
    from .data.store import CaseStore
    from .engines.model import AnalysisReport, EngineResult

    key = hashlib.sha256(b"at-rest-key").digest()
    with tempfile.TemporaryDirectory() as tmp:
        s = SettingsVault(os.path.join(tmp, "settings.dat"), key)
        s.set_text("vt_api_key", "SK_SECRET_TOKEN_9876")
        s.save()
        disk = open(os.path.join(tmp, "settings.dat"), "rb").read()
        r.check("at-rest: API key not plaintext on disk",
                b"SK_SECRET_TOKEN_9876" not in disk)

        cs = CaseStore(tmp, key)
        rep = AnalysisReport(subject="secret subject 42")
        rep.verdict = "QUARANTINE"
        rep.results["header"] = EngineResult("header")
        cid = cs.save(rep, raw=b"raw eml secret material", keep_raw=True)
        r.check("at-rest: case id generated", len(cid) == 32)
        r.check("at-rest: case round-trip",
                (cs.get(cid) or {}).get("verdict") == "QUARANTINE")
        r.check("at-rest: raw round-trip",
                cs.get_raw(cid) == b"raw eml secret material")
        r.check("at-rest: plaintext absent from case blob",
                b"secret subject 42" not in open(
                    os.path.join(cs.cases_dir, f"{cid}.case"), "rb").read())
        out = os.path.join(tmp, "case.json")
        r.check("at-rest: export works", cs.export_case(cid, out))
        r.check("at-rest: delete purges files", cs.delete(cid) and cs.get(cid) is None)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_all() -> tuple:
    """Execute all self-tests. Returns (ok: bool, failure_count: int)."""
    print("Phishing Email Analyzer - headless self-test")
    print("  (PBKDF2 iterations temporarily lowered in identity test for speed)")
    r = Result()
    for name in _TESTS:
        fn = globals().get(name)
        if not fn:
            r.check(f"registry: {name}", False)
            continue
        try:
            fn(r)
        except Exception as exc:  # noqa: BLE001
            import traceback
            r.check(f"{name}: no exception", False, f"raised {exc}")
            print(traceback.format_exc())
    print(f"SELF-TEST {'PASS' if r.ok else 'FAIL'}  failures={len(r.failures)}")
    return r.ok, len(r.failures)


_TESTS = (
    "_test_crypto",
    "_test_validation",
    "_test_audit",
    "_test_identity",
    "_test_canonicalization",
    "_test_dkim_roundtrip",
    "_test_url_engine",
    "_test_attachment_engine",
    "_test_content_engine",
    "_test_risk",
    "_test_full_pipeline",
    "_test_at_rest",
)