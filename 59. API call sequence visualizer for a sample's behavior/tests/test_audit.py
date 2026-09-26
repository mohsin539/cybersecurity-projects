"""Audit chain + integrity + redaction tests."""

from __future__ import annotations

import json

import pytest

from acsv.audit import AuditService
from acsv.crypto import DPAPIStore, IntegrityService
from acsv.redaction import RedactionService
from acsv.registry import SchemaRegistry


class TestAuditChain:
    def test_entries_chained(self, services):
        h1 = services.audit.record("POLICY_LOAD", {"ver": "1.0"})
        h2 = services.audit.record("SAMPLE_INTAKE", {"sha256": "x" * 64})
        assert h1 and h2
        entries = services.audit.iter_entries(reverse=False)
        assert entries[0]["seq"] == 1
        assert entries[1]["seq"] == 2
        assert entries[0]["entry_hash"] != entries[1]["entry_hash"]
        # each prev_hash links back
        assert entries[1]["prev_hash"] == entries[0]["entry_hash"]
        assert entries[0]["prev_hash"] == "00" * 32

    def test_verify_ok(self, services):
        services.audit.record("APP_START", {})
        services.audit.record("APP_EXIT", {})
        ok, fails = services.audit.verify_chain()
        assert ok is True
        assert fails == []

    def test_tamper_detected(self, services):
        services.audit.record("APP_START", {})
        services.audit.record("POLICY_LOAD", {"a": 1})
        # flip one hex char in the first entry hash -> breaks the chain
        raw = services.audit.journal.read_text()
        first_hash = raw.split('"entry_hash":"')[1].split('"')[0]
        flipped = ("0" if first_hash[0] != "0" else "1") + first_hash[1:]
        raw = raw.replace(first_hash, flipped, 1)
        services.audit.journal.write_text(raw)
        ok, fails = services.audit.verify_chain()
        assert ok is False
        assert len(fails) >= 1

    def test_unknown_action_rejected(self, services):
        with pytest.raises(ValueError):
            services.audit.record("NOT_A_REAL_ACTION", {})

    def test_dpapi_roundtrip(self, services):
        key = services.dapi.get_hmac_key()
        assert len(key) == 32
        key2 = services.dapi.get_hmac_key()
        assert key == key2
        assert services.dapi.path.exists()


class TestRedaction:
    def test_redacts_token_string(self):
        svc = RedactionService([
            r"(?i)(?P<key>(authorization|token|secret))[\"']?\s*[:=]\s*(?P<val>(?:\"[^\"]*\")|(?:'[^']*')|\S+)",
        ])
        red = svc.redact_json({"api_token": "abcdef123456", "Authorization": "Bearer 123456"})
        assert red["api_token"] == "[REDACTED]"
        assert red["Authorization"] == "[REDACTED]"

    def test_disabled_pass_through(self):
        svc = RedactionService([r"(?i)password"], enabled=False)
        assert svc.redact_json({"pw": "hunter2"})["pw"] == "hunter2"


class TestSchemaRegistry:
    def test_event_validation(self):
        probs = SchemaRegistry.validate_event({"seq": 1, "ts_ns": 2, "tid": 1, "pid": 1,
                                                "category": "File", "api": "NtReadFile",
                                                "ret": "0x0"})
        assert probs == []

    def test_invalid_event(self):
        probs = SchemaRegistry.validate_event({"api": "x"})
        assert len(probs) >= 4

    def test_integrity_sha(self):
        assert IntegrityService.sha256_hex(b"abc").startswith("ba7816bf")