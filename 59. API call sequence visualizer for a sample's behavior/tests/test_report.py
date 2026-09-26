"""Report exports + compliance mapping tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from acsv.capture.generator import build_trace
from acsv.capture.runner import CaptureRunner


@pytest.fixture
def session_id(services):
    from acsv.intake import SampleIntake
    import tempfile
    sample = services.intake.register_virtual()
    runner = CaptureRunner(services.store, services.audit, services.policy,
                           services.redaction)
    sid = runner.create_session(sample["id"])
    runner.run_trace(sid, build_trace(sample["sha256"], count=120))
    return sid


class TestExports:
    @pytest.mark.parametrize("fmt", ["json", "csv", "html", "pdf", "stix"])
    def test_all_formats(self, services, session_id, fmt, tmp_path):
        res = services.report_engine.render_and_save(session_id, fmt, tmp_path)
        assert res["path"] and res["sha256"]
        blob = (tmp_path / res["path"].split("\\")[-1]).read_bytes()
        assert len(blob) > 0
        # reported sha matches actual bytes
        from acsv.crypto import IntegrityService
        assert IntegrityService.sha256_hex(blob) == res["sha256"]

    def test_json_document(self, services, session_id, tmp_path):
        res = services.report_engine.render_and_save(session_id, "json", tmp_path)
        fname = Path(res["path"]).name
        raw = (tmp_path / fname).read_bytes()
        from acsv.crypto import IntegrityService
        assert IntegrityService.sha256_hex(raw) == res["sha256"]
        doc = json.loads(raw)
        inner = {k: v for k, v in doc.items() if k not in ("_meta", "report_sha256")}
        can = IntegrityService.canonical_bytes(inner)
        assert IntegrityService.sha256_hex(can) == doc["report_sha256"]
        assert doc["compliance"]["cover"]["total"] > 0
        assert doc["summary"]["event_count"] > 0

    def test_report_row_recorded(self, services, session_id, tmp_path):
        services.report_engine.render_and_save(session_id, "html", tmp_path)
        rows = list(services.store.list_reports())
        assert len(rows) == 1
        assert rows[0]["format"] == "html"


class TestCompliance:
    def test_frameworks_present(self):
        from acsv.compliance import FRAMEWORKS
        assert set(FRAMEWORKS) == {"ISO27001", "NIST", "OWASP"}

    def test_coverage_summary(self, services):
        s = services.compliance.coverage_summary(["A.8.15", "OWASP-A09"])
        assert s["total"] > 0
        assert 0 < s["coverage_pct"] <= 100

    def test_map_finding(self, services):
        ids = services.compliance.map_finding(["owasp-a03", "A.8.28"])
        assert "OWASP-A03" in ids
        assert "A.8.28" in ids