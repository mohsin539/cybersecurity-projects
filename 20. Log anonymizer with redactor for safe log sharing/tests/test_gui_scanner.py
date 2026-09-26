"""Tests for the headless engine bridge + secure export used by the GUI."""

from __future__ import annotations

import pytest

from anonymizer.gui import dpapi
from anonymizer.gui.scanner import ENCRYPT_HEADER, EncryptedExportError, EngineBridge


@pytest.fixture
def bridge(tmp_path):
    return EngineBridge(audit_dir=tmp_path / "audit")


def sample_lines() -> list[str]:
    return [
        "ERROR [auth] user bob@example.com ssn 555-66-7777",
        "INFO  card 4539-6651-3101-6828 charged 99.95",
    ]


def test_scan_detects_and_redacts(bridge):
    session = bridge.scan(sample_lines(), policy_id="default")
    assert len(session.lines) == 2
    redacted = "\n".join(session.redacted_lines)
    assert "555-66-7777" not in redacted
    assert "bob@example.com" not in redacted
    assert "4539-6651-3101-6828" not in redacted
    assert session.audit_events >= 3
    assert len(session.chain_root) == 64


def test_scan_carries_per_line_entities(bridge):
    session = bridge.scan(["email a@b.co phone +1 (555) 100-0000"], policy_id="default")
    entities = session.lines[0].entities
    assert any(e.entity_type == "EMAIL" for e in entities)
    assert any(e.entity_type == "PHONE" for e in entities)


def test_policy_list_populated(bridge):
    ids = bridge.policies()
    assert "default" in ids
    assert "share-with-vendor" in ids
    assert "share-with-analytics" in ids


def test_verify_chain_is_intact_before_and_after(bridge):
    valid, _, count = bridge.verify_chain()
    assert valid is True
    assert count == 0
    bridge.scan(sample_lines(), policy_id="default")
    valid, _, count = bridge.verify_chain()
    assert valid is True
    assert count >= 3


def test_export_plain_and_json(bridge, tmp_path):
    lines = ["line one", "line two"]
    p = bridge.export_plain(lines, tmp_path / "out.log")
    assert p.read_text(encoding="utf-8").startswith("line one\n")
    j = bridge.export_json(lines, tmp_path / "out.json")
    assert "lines" in j.read_text(encoding="utf-8")


def test_export_encrypted_requires_password(bridge, tmp_path):
    with pytest.raises(EncryptedExportError):
        bridge.export_encrypted(["a"], tmp_path / "x.enc", "")


def test_export_encrypted_writes_header_and_ciphertext(bridge, tmp_path):
    path = bridge.export_encrypted(["secret redacted"], tmp_path / "x.enc", "hunter2-pass")
    raw = path.read_bytes()
    assert raw.startswith(ENCRYPT_HEADER)
    assert len(raw) > len(ENCRYPT_HEADER) + 16 + 8
    assert b"secret redacted" not in raw  # ciphertext must not leak the payload


def test_export_encrypted_roundtrip(bridge, tmp_path):
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    path = bridge.export_encrypted(["redacted-a", "redacted-b"], tmp_path / "x.enc", "password-1")
    raw = path.read_bytes()
    salt = raw[len(ENCRYPT_HEADER) : len(ENCRYPT_HEADER) + 16]
    token = raw[len(ENCRYPT_HEADER) + 16 :]
    kdf = Scrypt(salt=salt, length=32, n=2**17, r=8, p=1)
    import base64

    key = base64.urlsafe_b64encode(kdf.derive(b"password-1"))
    payload = Fernet(key).decrypt(token)
    assert b"redacted-a" in payload
    assert b"redacted-b" in payload


def test_different_salts_produce_different_ciphertexts(bridge, tmp_path):
    a = bridge.export_encrypted(["x"], tmp_path / "a.enc", "pass")
    b = bridge.export_encrypted(["x"], tmp_path / "b.enc", "pass")
    assert a.read_bytes() != b.read_bytes()


def test_recent_records_sanitised(bridge):
    bridge.scan(sample_lines(), policy_id="default")
    records = bridge.recent_records()
    assert records
    record = records[0]
    # raw values must never be persisted - only hashes
    assert "original_hash" in record
    assert "value" not in record


def test_dpapi_roundtrip_on_windows(tmp_path):
    if not dpapi.dpapi_available:
        pytest.skip("DPAPI unavailable on this platform")
    token = dpapi.protect(b"very secret payload", b"entropy-xyz")
    assert dpapi.unprotect(token, b"entropy-xyz") == b"very secret payload"
    with pytest.raises(Exception):  # noqa: B017 - DPAPI rejects wrong entropy
        dpapi.unprotect(token, b"wrong-entropy")
