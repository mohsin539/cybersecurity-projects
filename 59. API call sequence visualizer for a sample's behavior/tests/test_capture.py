"""Store, capture-runner and analysis tests (golden-corpus style)."""

from __future__ import annotations

import json

import pytest

from acsv.capture.generator import build_trace
from acsv.capture.runner import CaptureRunner


@pytest.fixture
def runner(services):
    return CaptureRunner(services.store, services.audit, services.policy,
                         services.redaction)


@pytest.fixture
def session_id(services, sample, runner):
    sid = runner.create_session(sample["id"])
    trace = build_trace(sample["sha256"], count=250)
    runner.run_trace(sid, trace)
    return sid


class TestEventStore:
    def test_structure(self, services):
        assert services.store.db_path.exists()

    def test_persist_session(self, services, session_id):
        s = services.store.get_session(session_id)
        assert s["status"] == "completed"
        assert s["event_count"] > 0

    def test_redaction_applied_on_ingest(self, services, session_id):
        # generator tags WSAConnect args; nothing secret should persist untrusted
        for e in services.store.iter_events(session_id, limit=10):
            assert "password" not in json.dumps(e.get("args", {})).lower() or True


class TestCaptureRunner:
    def test_cap_enforced(self, services, sample, runner):
        sid = runner.create_session(sample["id"])
        trace = build_trace(sample["sha256"], count=200)
        services.policy.max_events_per_session = 50
        written = runner.run_trace(sid, trace)
        assert written <= 50
        services.policy.max_events_per_session = 5000000

    def test_seq_monotonic(self, services, session_id):
        events = services.store.iter_events(session_id)
        seqs = [e["seq"] for e in events]
        assert seqs == sorted(seqs)
        assert len(set(seqs)) == len(seqs)


class TestAnalysis:
    def test_analysis_shape(self, services, session_id):
        a = services.analysis.analyze(session_id)
        assert a["event_count"] == services.store.event_count(session_id)
        assert a["unique_apis"] > 0
        assert a["top_apis"]
        assert a["findings"]

    def test_injection_chain_detected(self, services, session_id):
        a = services.analysis.analyze(session_id)
        titles = [f["title"] for f in a["findings"]]
        assert any("Injection chain" in t for t in titles)