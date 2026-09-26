"""End-to-end pipeline tests: find it, parse it, map frameworks and render all formats."""

import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from redteam_report.frameworks.catalog import (
    OWASP_CROSS_MAP,
    map_finding_owasp,
)
from redteam_report.frameworks.iso27001 import ISO_BY_ID
from redteam_report.frameworks.nist import NIST_BY_ID
from redteam_report.frameworks.owasp import OWASP_BY_ID
from redteam_report.pipeline import Engagement, generate, load_engagement

SAMPLE = Path(__file__).resolve().parents[1] / "sample_findings.json"


def test_load_sample():
    engagement = load_engagement(SAMPLE)
    assert len(engagement.findings) == 9
    assert engagement.name.startswith("Project Helios")
    assert all(f.valid_cvss for f in engagement.findings)


def test_framework_catalog_lookup():
    mapping = map_finding_owasp("A03", finding=None)
    assert mapping.owasp.code == "A03"
    assert mapping.owasp.name == "Injection"
    assert mapping.nist_controls[0].code == "SI-10"
    assert mapping.iso_controls[0].code == "A.8.26"
    for fw in ("A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"):
        nist_codes, iso_codes = OWASP_CROSS_MAP[fw]
        for nist in nist_codes:
            assert nist in NIST_BY_ID, f"missing NIST {nist}"
        for iso in iso_codes:
            assert iso in ISO_BY_ID, f"missing ISO {iso}"
        assert fw in OWASP_BY_ID


def test_cross_framework_mapping_traces():
    engagement = load_engagement(SAMPLE)
    mappings = engagement.mappings()
    nist_codes = {c.code for m in mappings for c in m.nist_controls}
    iso_codes = {c.code for m in mappings for c in m.iso_controls}
    assert "SI-10" in nist_codes
    assert "A.8.28" in iso_codes


def test_executive_summary_metrics():
    engagement = load_engagement(SAMPLE)
    summary = engagement.executive_summary()
    assert summary.total_findings == 9
    assert 0.0 < summary.avg_cvss <= 10.0
    assert summary.max_cvss >= summary.avg_cvss >= summary.min_cvss
    assert 0.0 <= summary.risk_score <= 100.0
    assert len(summary.priorities) == 9
    assert summary.priorities[0].score >= summary.priorities[-1].score
    assert summary.owasp_counts.get("A03", 0) == 1
    assert summary.narrative


def test_generate_all_formats(tmp_path):
    engagement = load_engagement(SAMPLE)
    results = generate(engagement, tmp_path, formats=["csv", "xlsx", "html"])
    assert set(results) == {"csv", "xlsx", "html"}
    for fmt, result in results.items():
        assert result.files, f"{fmt} produced no files"
        for kind, path in result.files.items():
            assert path.exists(), f"{fmt}/{kind} missing"
            assert path.stat().st_size > 0


def test_unsupported_format_rejected(tmp_path):
    engagement = Engagement(findings=[])
    with pytest.raises(ValueError):
        generate(engagement, tmp_path, formats=["pdf"])


def test_empty_engagement():
    engagement = Engagement(findings=[])
    summary = engagement.executive_summary()
    assert summary.total_findings == 0
    assert summary.risk_score == 0.0