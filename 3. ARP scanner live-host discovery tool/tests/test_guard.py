from arp_scanner.security.guard import (
    CONSENT_NOTICE,
    consent_given,
    validate_export_path,
)


def test_consent_notice_contains_controls():
    assert "AUTHORIZED-USE NOTICE" in CONSENT_NOTICE
    assert "unauthorized" in CONSENT_NOTICE.lower()


def test_consent_given_is_false_in_sandbox(monkeypatch, tmp_path):
    import os

    monkeypatch.setattr(os, "environ", {**os.environ, "APPDATA": str(tmp_path)})
    assert consent_given() is False


def test_export_path_rejects_traversal():
    try:
        validate_export_path(r"C:\Users\bob\..\..\Windows\bad.csv")
        assert False, "should reject traversal"
    except ValueError:
        pass


def test_export_path_accepts_normal(tmp_path):
    ok = validate_export_path(str(tmp_path / "scan.csv"))
    assert ok.name == "scan.csv"