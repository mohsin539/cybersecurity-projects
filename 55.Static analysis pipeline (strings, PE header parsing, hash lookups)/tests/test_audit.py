"""Audit ledger tests — chaining, tamper detection, seal, custody genesis."""
import json

import pytest

from sap.security.audit import (
    ACTION_GENESIS,
    ACTION_SAMPLE_SEALED,
    AuditLedger,
    AuditTamperedError,
)
from sap.security.crypto import Signer


def test_genesis_and_chain(tmp_path):
    ledger = AuditLedger(tmp_path / "ledger.jsonl")
    assert ledger.count == 1
    assert ledger.events[0]["action"] == ACTION_GENESIS
    assert ledger.events[0]["prev_hash"] is None

    e1 = ledger.log("analyst", ACTION_SAMPLE_SEALED, {"sha256": "ab" * 32})
    e2 = ledger.log("analyst", "ENGINE_PE_DONE", {"how": "pefile"})
    assert e1["prev_hash"] == ledger.events[0]["hash"]
    assert e2["prev_hash"] == e1["hash"]
    assert e1["hash"] != e2["hash"]
    assert ledger.head == e2["hash"]
    assert ledger.verify()


def test_reload_detects_tampered_line(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = AuditLedger(path)
    ledger.log("analyst", "ENGINE_PE_DONE", {"x": 1})

    lines = path.read_text("utf-8").splitlines()
    # mutate the payload of the 2nd event (line index 1)
    ev = json.loads(lines[1])
    ev["payload"]["x"] = 999
    lines[1] = json.dumps(ev, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", "utf-8")

    with pytest.raises(AuditTamperedError):
        AuditLedger(path)


def test_reload_detects_broken_prev_hash(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = AuditLedger(path)
    ledger.log("analyst", "A", {})
    ledger.log("analyst", "B", {})

    lines = path.read_text("utf-8").splitlines()
    ev = json.loads(lines[1])
    ev["prev_hash"] = "0" * 64
    lines[1] = json.dumps(ev, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", "utf-8")

    with pytest.raises(AuditTamperedError):
        AuditLedger(path)


def test_reload_detects_middle_removal(tmp_path):
    """Removing a middle link must break the chain -> detected immediately."""
    path = tmp_path / "ledger.jsonl"
    ledger = AuditLedger(path)
    ledger.log("analyst", "A", {})
    ledger.log("analyst", "B", {})

    lines = path.read_text("utf-8").splitlines()
    # drop event A (line index 1); B still references A's hash -> torn chain
    del lines[1]
    path.write_text("\n".join(lines) + "\n", "utf-8")
    with pytest.raises(AuditTamperedError):
        AuditLedger(path)


def test_tail_truncation_is_undetectable_without_anchors(tmp_path):
    """Append-only ledgers cannot see leading truncation (documented residual
    risk, security.md RE-1); the shortened chain must still verify."""
    path = tmp_path / "ledger.jsonl"
    ledger = AuditLedger(path)
    ledger.log("analyst", "A", {})
    ledger.log("analyst", "B", {})
    path.write_text("\n".join(path.read_text("utf-8").splitlines()[:1]) + "\n", "utf-8")
    probe = AuditLedger(path)
    assert probe.count == 1
    assert probe.verify()


def test_verify_detects_tamper_on_disk(tmp_path):
    path = tmp_path / "ledger.jsonl"
    ledger = AuditLedger(path)
    ledger.log("analyst", "A", {})
    assert ledger.verify()
    path.write_text("\n".join(path.read_text("utf-8").splitlines()) + "\nX\n", "utf-8")
    assert not ledger.verify()


def test_custody_genesis_accepted(tmp_path):
    led = AuditLedger(tmp_path / "custody.jsonl", genesis_action="CUSTODY_GENESIS")
    assert led.events[0]["action"] == "CUSTODY_GENESIS"
    led2 = AuditLedger(tmp_path / "custody.jsonl")
    assert led2.count == 1


def test_seal_uses_signer(tmp_path):
    ledger = AuditLedger(tmp_path / "ledger.jsonl")
    signer = Signer.generate_and_save(tmp_path / "keys")
    ledger.log("analyst", "A", {})
    seal = ledger.seal(signer, "analyst")
    assert seal["signature_hex"]
    # chain_head is frozen BEFORE the CASE_SEALED event is appended
    assert seal["chain_head"] == ledger.events[-2]["hash"]
    assert seal["events"] == 2  # genesis + A (CASE_SEALED appended after)
    assert (tmp_path / "seal.json").exists()