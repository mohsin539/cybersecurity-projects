"""Pytest suite for the security core (crypto, validation, audit, identity).

Run from project root:  py -3.12 -m pytest -q
"""
import hashlib
import os
import tempfile

import pytest

from src.app.sec import constants as C
from src.app.sec.audit import AuditLog
from src.app.sec.crypto import SecurityError, decrypt_bytes, encrypt_bytes
from src.app.sec.identity import AuthError, IdentityStore, Session
from src.app.sec.validation import (
    is_private_ip,
    sanitize_filename,
    sanitize_text,
    validate_email_bytes,
)


# ---------------------------------------------------------------------------
# crypto
# ---------------------------------------------------------------------------
def test_crypto_roundtrip():
    key = hashlib.sha256(b"k1").digest()
    blob = encrypt_bytes(b"secret payload", key, b"aad")
    assert decrypt_bytes(blob, key, b"aad") == b"secret payload"


def test_crypto_tamper_detected():
    key = hashlib.sha256(b"k1").digest()
    blob = bytearray(encrypt_bytes(b"payload", key, b"aad"))
    blob[len(blob) // 2] ^= 0x01
    with pytest.raises(SecurityError):
        decrypt_bytes(bytes(blob), key, b"aad")


def test_crypto_wrong_key_fails():
    key = hashlib.sha256(b"k1").digest()
    other = hashlib.sha256(b"k2").digest()
    blob = encrypt_bytes(b"payload", key, b"aad")
    with pytest.raises(SecurityError):
        decrypt_bytes(blob, other, b"aad")


def test_crypto_aad_binds():
    key = hashlib.sha256(b"k1").digest()
    blob = encrypt_bytes(b"payload", key, b"ctxA")
    with pytest.raises(SecurityError):
        decrypt_bytes(blob, key, b"ctxB")


def test_crypto_empty_plaintext():
    key = hashlib.sha256(b"k1").digest()
    blob = encrypt_bytes(b"", key, b"aad")
    assert decrypt_bytes(blob, key, b"aad") == b""


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------
def test_validation_oversize_rejected():
    with pytest.raises(ValueError):
        validate_email_bytes(b"A" * (C.MAX_EMAIL_BYTES + 1))


def test_validation_private_ip_guard():
    assert is_private_ip("10.0.0.5")
    assert is_private_ip("192.168.1.1")
    assert is_private_ip("::1")
    assert not is_private_ip("8.8.8.8")


def test_validation_sanitize_filename():
    assert sanitize_filename("a/b\\c:d*e?f\"g<h>i|j.txt") == "a_b_c_d_e_f_g_h_i_j.txt"


def test_validation_sanitize_text_limits():
    assert len(sanitize_text("x" * 5000, 128)) == 128


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------
def test_audit_chain_verifies_clean():
    with tempfile.TemporaryDirectory() as tmp:
        key = hashlib.sha256(b"audit-key").digest()
        log = AuditLog(os.path.join(tmp, "audit"), key)
        log.append("APP_START", "alice", "admin", detail="started")
        log.append("CASE_ANALYZED", "alice", "admin", target="case abc")
        assert log.verify() == []


def test_audit_tamper_detected():
    with tempfile.TemporaryDirectory() as tmp:
        key = hashlib.sha256(b"audit-key").digest()
        log = AuditLog(os.path.join(tmp, "audit"), key)
        log.append("APP_START", "alice", "admin", detail="started")
        # corrupt first batch entry
        batch = log.batches[min(log.batches)]
        raw = bytearray(open(batch, "rb").read())
        raw[len(raw) // 2] ^= 0x01
        with open(batch, "wb") as fh:
            fh.write(bytes(raw))
        assert log.verify() != []


# ---------------------------------------------------------------------------
# identity / RBAC (PBKDF2 iterations lowered for speed)
# ---------------------------------------------------------------------------
@pytest.fixture()
def id_store(tmp_path, monkeypatch):
    monkeypatch.setattr(C, "PBKDF2_ITERATIONS", 2000)
    from src.app.sec import identity as ID
    monkeypatch.setattr(ID.time, "sleep", lambda _s: None)
    store = IdentityStore(str(tmp_path / "profile.dat"))
    store.create_profile("alice.sec", "CorrectHorse@2024!", "admin")
    return store


def test_identity_auth_and_wrong_password(id_store):
    tok, key = id_store.authenticate("alice.sec", "CorrectHorse@2024!")
    assert tok["role"] == "admin"
    assert len(key) == 32
    with pytest.raises(AuthError):
        id_store.authenticate("alice.sec", "nope")


def test_identity_lockout(id_store, tmp_path):
    from src.app.sec import identity as ID
    for _ in range(C.LOGIN_MAX_ATTEMPTS):
        with pytest.raises(AuthError):
            id_store.authenticate("alice.sec", "wrong-password-1")
    with pytest.raises(AuthError) as ei:
        id_store.authenticate("alice.sec", "CorrectHorse@2024!")
    assert "locked" in str(ei.value).lower()
    id_store._clear_lockout("alice.sec")
    tok, _ = id_store.authenticate("alice.sec", "CorrectHorse@2024!")
    assert tok["role"] == "admin"


def test_identity_password_rotation_keeps_data_key(id_store):
    _, key1 = id_store.authenticate("alice.sec", "CorrectHorse@2024!")
    id_store.change_password("alice.sec", "CorrectHorse@2024!", "NewHorse@2024!")
    _, key2 = id_store.authenticate("alice.sec", "NewHorse@2024!")
    assert key1 == key2
    with pytest.raises(AuthError):
        id_store.authenticate("alice.sec", "CorrectHorse@2024!")


def test_rbac_matrix():
    s = Session("alice.sec", "analyst", b"x" * 32, "pw")
    assert s.can("analyze")
    assert not s.can("delete_case")
    admin = Session("bob.sec", "admin", b"x" * 32, "pw")
    assert admin.can("delete_case")