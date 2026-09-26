"""Report + history tests."""

from __future__ import annotations

import json

import pytest

from cisguard.application.report_service import HistoryStore, ReportService
from cisguard.application.scan_service import ScanService
from cisguard.infrastructure.test_collectors import (
    FakeAuditpol, FakeCommands, FakeDefender, FakeRegistry, FakeServices, FakeSystem,
)


@pytest.fixture()
def record():
    svc = ScanService(FakeRegistry({}), FakeServices({}), FakeCommands({}),
                      FakeAuditpol({}), FakeDefender({}), FakeSystem())
    return svc.scan()


def test_html_report_is_selfcontained_and_escaped(record, tmp_path):
    out = ReportService().export_html(record, tmp_path / "r.html")
    text = out.read_text(encoding="utf-8")
    assert text.startswith("<!DOCTYPE html>")
    assert "CSP" in text or "Content-Security-Policy" in text
    assert "<script" not in text.lower()
    assert record.summary.hostname in text


def test_json_report_structure(record, tmp_path):
    out = ReportService().export_json(record, tmp_path / "r.json")
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["scan"]["counts"]["total"] == len(record.results)
    assert len(payload["results"]) == len(record.results)
    first = payload["results"][0]
    for key in ("control_id", "title", "status", "observed", "expected", "evidence_source", "recommendation"):
        assert key in first


def test_csv_report_rows(record, tmp_path):
    out = ReportService().export_csv(record, tmp_path / "r.csv")
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == len(record.results) + 1  # header + rows


def test_history_roundtrip(record, tmp_path):
    store = HistoryStore(tmp_path / "h.db")
    store.save(record)
    store.save(record)  # idempotent upsert
    rows = store.list_scans()
    assert len(rows) == 1
    assert rows[0][0] == record.summary.scan_id
    assert abs(rows[0][3] - record.summary.score) < 0.01
    store.close()
