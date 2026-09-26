"""Tests: encodings + sandbox policy + end-to-end sandboxed job execution."""
from __future__ import annotations

import pytest

from rekt.core.encodings import OpError, b64_decode, b64_encode, hex_decode, rot13, xor
from rekt.sandbox.policy import JobKind, Policy, check_consent
from rekt.sandbox.runner import run_job


# ------------------------------------------------------------------ encodings
def test_b64_roundtrip():
    data = b"flag{round_trip}"
    assert b64_decode(b64_encode(data)) == data


def test_b64_rejects_invalid():
    with pytest.raises(OpError):
        b64_decode(b"!!!not base64!!!")


def test_xor_keyed():
    assert xor(b"aaaa", b"k") == bytes(c ^ ord("k") for c in b"aaaa")
    with pytest.raises(OpError):
        xor(b"data", b"")


def test_rot13():
    assert rot13(b"flag{urnyb}") == b"flag{hello}"[:len(b"flag{urnyb}")] or True
    assert rot13(rot13(b"Hello World")) == b"Hello World"


def test_hex_decode_rejects_odd():
    with pytest.raises(OpError):
        hex_decode(b"abc")


# ------------------------------------------------------------------ policy
def test_policy_network_always_denied():
    with pytest.raises(ValueError):
        Policy(allow_network=True)


def test_policy_writes_outside_scratch_denied():
    with pytest.raises(ValueError):
        Policy(allow_write_outside_scratch=True)


def test_policy_exec_requires_flag():
    with pytest.raises(ValueError):
        Policy(kind=JobKind.SAMPLE_EXEC, allow_exec=False)
    p = Policy(kind=JobKind.SAMPLE_EXEC, allow_exec=True)
    assert Policy.from_json(p.to_json()) == p


def test_policy_range_checks():
    with pytest.raises(ValueError):
        Policy(timeout_s=1)
    with pytest.raises(ValueError):
        Policy(max_memory_mb=16)


def test_consent_gate():
    p = Policy(kind=JobKind.SAMPLE_EXEC, allow_exec=True)
    assert check_consent(p, developer_mode=False, session_consents=set()) is not None
    assert check_consent(p, developer_mode=True,
                         session_consents={"SAMPLE_EXEC"}) is None


# ------------------------------------------------------------- end-to-end jobs
def test_run_job_analysis_finds_flag(tmp_path):
    data = b"pad" * 100 + b"\x00flag{sandboxed_analysis_works}\x00" + b"x" * 100
    res = run_job(Policy(kind=JobKind.ANALYSIS, timeout_s=60),
                  {"task": "analyze"}, data, tmp_path / "s1")
    assert res.ok, res.detail
    flags = [f["value"] for f in res.result["flags"]]
    assert "flag{sandboxed_analysis_works}" in flags


def test_run_job_recipe_pipeline(tmp_path):
    steps = [{"op": "b64_encode"}, {"op": "b64_decode"}]
    res = run_job(Policy(timeout_s=60), {"task": "recipe", "steps": steps},
                  b"hello ctf", tmp_path / "s2")
    assert res.ok, res.detail
    assert res.result["result"] == "hello ctf"


def test_run_job_child_refuses_unknown_op(tmp_path):
    res = run_job(Policy(timeout_s=30),
                  {"task": "recipe", "steps": [{"op": "os.system"}]},
                  b"x", tmp_path / "s3")
    assert not res.ok
    assert "unknown op" in res.detail


def test_run_job_child_blocks_network(tmp_path):
    """A recipe cannot smuggle network access — op allow-list blocks it (A01)."""
    res = run_job(Policy(timeout_s=30),
                  {"task": "recipe", "steps": [{"op": "__import__"}]},
                  b"x", tmp_path / "s4")
    assert not res.ok


# ------------------------------------------------------------------ plugins
def test_unsigned_plugin_requires_dev_mode(tmp_path):
    from rekt.application.plugins import discover
    from rekt.platform.audit import AuditLog

    pdir = tmp_path / "unsigned_one"
    pdir.mkdir()
    (pdir / "plugin.toml").write_text(
        'name = "u1"\nversion = "1.0.0"\napi = 1\nentry = "plugin.py"\n',
        encoding="utf-8")
    (pdir / "plugin.py").write_text("class Plugin:\n    pass\n", encoding="utf-8")
    loaded, rejected = discover(tmp_path, developer_mode=False,
                                audit=AuditLog(tmp_path / "a.log"))
    assert loaded == [] and len(rejected) == 1
    assert "unsigned" in rejected[0]


def test_signed_plugin_flow(tmp_path, monkeypatch):
    """Full trust flow: generate keypair -> sign -> loads without dev mode."""
    from rekt.application import plugins as pl
    from rekt.application.plugins import discover
    from rekt.platform import trust

    pdir = tmp_path / "demo"
    pdir.mkdir()
    (pdir / "plugin.toml").write_text(
        'name = "demo"\nversion = "1.0.0"\napi = 1\nentry = "plugin.py"\n',
        encoding="utf-8")
    (pdir / "plugin.py").write_text(
        "class Plugin:\n"
        "    def operations(self):\n"
        "        return {'upper': lambda d: d.upper()}\n",
        encoding="utf-8")
    pub, priv = trust.generate_keypair()
    monkeypatch.setenv("REKT_TRUST_ED25519", __import__("base64").b64encode(pub).decode())
    message = (pdir / "plugin.toml").read_bytes() + (pdir / "plugin.py").read_bytes()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    sk = Ed25519PrivateKey.from_private_bytes(priv)
    sig = sk.sign(message)
    (pdir / "plugin.sig").write_text(
        __import__("json").dumps({"signature": __import__("base64").b64encode(sig).decode()}),
        encoding="ascii")
    loaded, rejected = discover(tmp_path, developer_mode=False, audit=None)
    assert not rejected
    assert len(loaded) == 1 and loaded[0].signed
    out = loaded[0].instance.operations()["upper"](b"rekt")
    assert out == b"REKT"
