"""PolicyGuard tests — evidence RO contract, sandbox containment, egress."""
import os

import pytest

from sap.security.policy import (
    DEFAULT_MAX_SAMPLE_BYTES,
    EgressGate,
    PolicyViolation,
    SandboxPolicy,
    gate_pe_magic,
    gate_sample_size,
    open_evidence,
)


def test_open_evidence_is_read_only(tmp_path):
    p = tmp_path / "sample.bin"
    p.write_bytes(b"data" * 32)
    fd = open_evidence(p)
    try:
        assert os.read(fd, 4) == b"data"
        with pytest.raises(OSError):
            os.write(fd, b"tamper")
    finally:
        os.close(fd)


def test_open_evidence_missing_raises():
    with pytest.raises(FileNotFoundError):
        open_evidence("C:/definitely/not/here.bin")


def test_gate_sample_size():
    gate_sample_size(1)
    gate_sample_size(DEFAULT_MAX_SAMPLE_BYTES)
    with pytest.raises(PolicyViolation):
        gate_sample_size(0)
    with pytest.raises(PolicyViolation):
        gate_sample_size(-5)
    with pytest.raises(PolicyViolation):
        gate_sample_size(DEFAULT_MAX_SAMPLE_BYTES + 1)
    with pytest.raises(PolicyViolation):
        gate_sample_size("123")
    with pytest.raises(PolicyViolation):
        gate_sample_size(42, max_bytes=10)


def test_gate_pe_magic():
    assert gate_pe_magic(b"MZ\x90\x00")
    assert not gate_pe_magic(b"This is AHK script")


def test_sandbox_containment(tmp_path):
    policy = SandboxPolicy(tmp_path)
    inside = policy.write("reports", "card.json")
    assert inside == (tmp_path / "reports" / "card.json").resolve()
    assert inside.parent.exists()

    with pytest.raises(PolicyViolation):
        policy.resolve("..", "escape.txt")
    with pytest.raises(PolicyViolation):
        policy.resolve(str(tmp_path.parent / "outside.txt"))
    with pytest.raises(PolicyViolation):
        policy.write("..", "nope.txt")


def test_egress_deny_by_default():
    gate = EgressGate()
    with pytest.raises(PolicyViolation):
        gate.check("api.virustotal.com", "a" * 64)


def test_egress_allowlisted_and_hashed_only():
    gate = EgressGate(allowed=True)
    gate.check("api.virustotal.com", "a" * 64)
    assert gate.used == 1
    with pytest.raises(PolicyViolation):
        gate.check("evil.example.org", "a" * 64)
    with pytest.raises(PolicyViolation):
        gate.check("api.virustotal.com", "not-a-sha")
    with pytest.raises(PolicyViolation):
        gate.check("api.virustotal.com", "a" * 63)


def test_egress_daily_cap():
    gate = EgressGate(allowed=True, daily_cap=2)
    gate.check("threatfox.abuse.ch", "b" * 64)
    gate.check("threatfox.abuse.ch", "c" * 64)
    with pytest.raises(PolicyViolation):
        gate.check("threatfox.abuse.ch", "d" * 64)