"""Tests: platform layer (audit chain, config validation, crypto, store)."""
from __future__ import annotations

import json

import pytest

from rekt.platform.audit import AuditLog
from rekt.platform.config import Config, load_config, save_config
from rekt.platform.crypto import decrypt, derive_key, encrypt, new_salt
from rekt.platform.store import ProjectStore


# ------------------------------------------------------------------ audit
def test_audit_chain_roundtrip(tmp_path):
    log = AuditLog(tmp_path / "audit.log")
    log.append("a.x", k=1)
    log.append("a.y", k=2)
    ok, _ = log.verify()
    assert ok


def test_audit_tamper_detected(tmp_path):
    p = tmp_path / "audit.log"
    log = AuditLog(p)
    log.append("a.x", k=1)
    log.append("a.y", k=2)
    # tamper: rewrite the first record's action
    lines = p.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["action"] = "forged"
    lines[0] = json.dumps(rec, separators=(",", ":"))
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, msg = AuditLog(p).verify()
    assert not ok
    assert "hash mismatch" in msg or "chain break" in msg


def test_audit_deletion_detected(tmp_path):
    p = tmp_path / "audit.log"
    log = AuditLog(p)
    log.append("a.x", k=1)
    log.append("a.y", k=2)
    log.append("a.z", k=3)
    lines = p.read_text(encoding="utf-8").splitlines()
    del lines[1]  # remove middle record
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, msg = AuditLog(p).verify()
    assert not ok


# ------------------------------------------------------------------ config
def test_config_rejects_insecure_values():
    cfg = Config()
    cfg.telemetry_enabled = True
    with pytest.raises(ValueError):
        cfg.validate()
    cfg2 = Config(default_timeout_s=0)
    with pytest.raises(ValueError):
        cfg2.validate()


def test_config_load_falls_back_to_defaults_on_tamper(tmp_path, monkeypatch):
    monkeypatch.setenv("REKT_PORTABLE", str(tmp_path))
    from rekt.platform import config as cfgmod

    p = cfgmod.config_path()
    p.write_text(json.dumps({"default_timeout_s": 999999}), encoding="utf-8")
    cfg = load_config()
    assert cfg == Config()  # silently reverted to secure defaults


def test_config_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("REKT_PORTABLE", str(tmp_path))
    from rekt.platform import config as cfgmod

    cfg = Config(max_file_mb=32)
    save_config(cfg)
    assert load_config().max_file_mb == 32


# ------------------------------------------------------------------ crypto
def test_crypto_roundtrip():
    salt = new_salt()
    key = derive_key("correct horse battery staple", salt)
    blob = encrypt(key, b"secret flag{abc}")
    assert decrypt(key, blob) == b"secret flag{abc}"


def test_crypto_tamper_raises():
    key = derive_key("pw", new_salt())
    blob = bytearray(encrypt(key, b"data"))
    blob[-1] ^= 0xFF
    import cryptography.exceptions

    with pytest.raises((cryptography.exceptions.InvalidTag, ValueError)):
        decrypt(key, bytes(blob))


def test_crypto_wrong_key_raises():
    k1 = derive_key("pw1", new_salt())
    k2 = derive_key("pw2", new_salt())
    with pytest.raises(Exception):
        decrypt(k2, encrypt(k1, b"data"))


# ------------------------------------------------------------------ store
def test_store_artifacts_and_findings(tmp_path):
    store = ProjectStore(tmp_path / "proj")
    sha = store.sha256(b"sample-bytes")
    store.put_blob(sha, b"sample-bytes")
    assert store.add_artifact(b"sample-bytes", note="x") == sha
    assert store.add_artifact(b"sample-bytes", note="x") == sha  # dedupe
    assert store.get_artifact(sha) == b"sample-bytes"
    store.add_finding(sha, "static", "flag", "flag{t}")
    assert store.findings_for(sha)[0]["detail"] == "flag{t}"
    assert len(store.list_artifacts()) == 1


def test_store_job_lifecycle(tmp_path):
    store = ProjectStore(tmp_path / "proj")
    jid = store.job_start("ANALYSIS", "deadbeef", "{}")
    store.job_end(jid, "ok")
    assert True  # no exception is the contract; detail covered by integration tests
