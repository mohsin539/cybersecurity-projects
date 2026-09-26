import pytest

from app.config import settings
from app.security.ratelimit import TokenBucket


def test_bucket_allows_until_limit():
    bucket = TokenBucket(limit=3, window_seconds=60)
    a1, _ = bucket.allow("k")
    a2, _ = bucket.allow("k")
    a3, _ = bucket.allow("k")
    a4, retry = bucket.allow("k")
    assert a1 and a2 and a3
    assert not a4
    assert retry >= 1


def test_bucket_independent_per_key():
    bucket = TokenBucket(limit=1, window_seconds=60)
    ok1, _ = bucket.allow("u1")
    ok2, _ = bucket.allow("u2")
    assert ok1 and ok2
    denied, _ = bucket.allow("u1")
    assert not denied


def test_window_resets_after_elapsed():
    bucket = TokenBucket(limit=1, window_seconds=1)
    assert bucket.allow("k")[0]
    assert not bucket.allow("k")[0]
    import time

    time.sleep(1.1)
    assert bucket.allow("k")[0]


def test_allowed_hosts_match():
    assert settings.host_allowed("localhost")
    assert settings.host_allowed("127.0.0.1")
    assert settings.host_allowed("evil.lab.local")
    assert settings.host_allowed("172.16.4.9")
    assert not settings.host_allowed("google.com")
    assert not settings.host_allowed("lab.local.attacker.io")


def test_validate_scan_url_accepts_allowed_hosts():
    from app.services.scanner_service import validate_scan_url

    validate_scan_url("http://localhost:5001/html?name=x")
    validate_scan_url("https://evil.lab.local/x")  # allowed + https on non-loopback -> ok


def test_validate_scan_url_rejects_external_and_bad_scheme():
    from app.services.scanner_service import ScanPolicyError, validate_scan_url

    with pytest.raises(ScanPolicyError):
        validate_scan_url("https://google.com/x")
    with pytest.raises(ScanPolicyError):
        validate_scan_url("http://attacker.io/x")
    with pytest.raises(ScanPolicyError):
        validate_scan_url("file:///etc/passwd")
    with pytest.raises(ScanPolicyError):
        validate_scan_url("javascript:alert(1)")


def test_non_local_requires_https_when_configured():
    from app.services.scanner_service import ScanPolicyError, validate_scan_url

    if settings.require_https_for_non_local:
        with pytest.raises(ScanPolicyError):
            validate_scan_url("http://172.16.4.9/x")  # allowed host, but http -> refused
    else:
        validate_scan_url("http://172.16.4.9/x")
    validate_scan_url("https://172.16.4.9/x")  # https variant always fine