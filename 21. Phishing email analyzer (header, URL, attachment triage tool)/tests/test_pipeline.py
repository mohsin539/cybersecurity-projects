"""Integration tests: full pipeline verdicts, at-rest encryption, store round-trips."""
import base64
import hashlib
import os
import time

import pytest

from src.app.analysis import analyze_raw_email
from src.app.engines import header_engine as HE
from src.app.engines.model import AnalysisReport, EngineResult
from src.app.data.settings import SettingsVault
from src.app.data.store import CaseStore


@pytest.fixture()
def dns_stub(monkeypatch):
    """Fail-closed DNS: nothing available, so auth never 'passes' on faith."""
    for name in ("get_txt", "get_a", "get_mx", "secure_resolve_host"):
        monkeypatch.setattr(HE.dns, name, lambda *a, **kw: [])
    monkeypatch.setattr(HE.dns, "dns_available", lambda: False)


def _phishing_raw():
    date_hdr = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
    headers = (f"Delivered-To: victim@example.com\r\n"
               f"Return-Path: <bounces@paypa1.com>\r\n"
               f'From: "PayPal Support" <secure@paypa1.com>\r\n'
               f"To: victim@example.com\r\n"
               f"Subject: Your account has been suspended\r\n"
               f"Date: {date_hdr}\r\n"
               f"Message-ID: <abc123@paypa1.com>\r\n"
               f"Reply-To: attacker@malicious-service.ru\r\n"
               f"MIME-Version: 1.0\r\n"
               f'Content-Type: multipart/mixed; boundary="B0"\r\n\r\n').encode("utf-8")
    exe = base64.b64encode(b"MZ\x90\x00fake-executable-bytes-00112233")
    body = (b"--B0\r\n"
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
    return headers + body


def _benign_raw():
    date_hdr = time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())
    return (f"From: jenny@example.org\r\n"
            f"Date: {date_hdr}\r\n"
            f"Message-ID: <benign@example.org>\r\n"
            f"Subject: Lunch tomorrow?\r\n"
            f"Content-Type: text/plain\r\n\r\n"
            f"Hi, are you free for lunch tomorrow? -- Jen\r\n").encode()


def test_pipeline_phishing_quarantined(dns_stub):
    report = analyze_raw_email(_phishing_raw(), resolve_hosts=False)
    assert report.verdict == "QUARANTINE"
    assert report.risk_score >= 70
    codes = {f.code for f in report.all_findings()}
    must = {"DISPLAY_SPOOF", "URL_BRAND_TYPO", "URL_SHORTENER", "ATT_EXEC",
            "ATT_DOUBLE_EXT", "CRED_REQUEST", "PHISH_KEYWORDS"}
    assert must.issubset(codes), must - codes


def test_pipeline_benign_not_over_blocked(dns_stub):
    report = analyze_raw_email(_benign_raw(), resolve_hosts=False)
    assert report.verdict in ("ALLOW", "FLAG")


def test_pipeline_fail_closed_on_binary():
    with pytest.raises(ValueError):
        analyze_raw_email(b"\x00" * 500)


# ---------------------------------------------------------------------------
# At-rest encryption
# ---------------------------------------------------------------------------
def test_settings_secret_not_plaintext_on_disk(tmp_path):
    key = hashlib.sha256(b"at-rest-key").digest()
    s = SettingsVault(str(tmp_path / "settings.dat"), key)
    s.set_text("vt_api_key", "SK_SECRET_TOKEN_9876")
    s.save()
    disk = open(tmp_path / "settings.dat", "rb").read()
    assert b"SK_SECRET_TOKEN_9876" not in disk


def test_case_store_roundtrip_and_export(tmp_path):
    key = hashlib.sha256(b"at-rest-key").digest()
    cs = CaseStore(str(tmp_path), key)
    rep = AnalysisReport(subject="secret subject 42")
    rep.verdict = "QUARANTINE"
    rep.results["header"] = EngineResult("header")
    cid = cs.save(rep, raw=b"raw eml secret material", keep_raw=True)
    assert len(cid) == 32
    assert (cs.get(cid) or {}).get("verdict") == "QUARANTINE"
    assert cs.get_raw(cid) == b"raw eml secret material"
    disk = open(os.path.join(cs.cases_dir, f"{cid}.case"), "rb").read()
    assert b"secret subject 42" not in disk

    out = os.path.join(str(tmp_path), "export.json")
    assert cs.export_case(cid, out)
    cs.delete(cid)
    assert not os.path.exists(os.path.join(cs.cases_dir, f"{cid}.case"))