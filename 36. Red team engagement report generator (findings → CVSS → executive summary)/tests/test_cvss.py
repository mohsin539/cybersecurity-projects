"""Tests for the CVSS v3.1 scoring engine."""

import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

from redteam_report.models.cvss import CVSS3Engine, Severity, score_vector

# (vector, expected score, expected severity) - known published values
KNOWN_VECTORS = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, Severity.CRITICAL),  # Log4Shell
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, Severity.CRITICAL),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, Severity.HIGH),  # Heartbleed
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, Severity.MEDIUM),
    ("CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:N", 0.0, Severity.NONE),
]


def test_known_vector_scores():
    for vector, expected, severity in KNOWN_VECTORS:
        result = score_vector(vector)
        assert result.valid, result.validation_errors
        assert result.base_score == pytest.approx(expected, abs=0.05), vector
        assert result.severity is severity, vector


def test_severity_boundaries():
    assert Score.check(0.0) == Severity.NONE


def test_temp_and_env_score_present():
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RL:O/RC:C/CR:H/IR:H/AR:H/MAV:N"
    result = score_vector(vector)
    assert result.temporal_score is not None
    assert result.environmental_score is not None
    assert 0.0 <= result.environmental_score <= 10.0


def test_invalid_vector_reported():
    result = score_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U")
    assert not result.valid
    assert any("C" in err for err in result.validation_errors)


def test_invalid_metric_value():
    result = score_vector("CVSS:3.1/AV:ZZ/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    assert not result.valid


def test_metric_decomposition():
    engine = CVSS3Engine("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    result = engine.score()
    assert result.metrics["AV"] == "N"
    assert result.metrics["I"] == "H"
    assert result.describe_metric("AV").startswith("Attack Vector")


def test_roundup_behavior():
    result = score_vector("CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L")
    assert result.base_score == pytest.approx(4.5, abs=0.05)


class Score:
    @staticmethod
    def check(score: float) -> Severity:
        from redteam_report.models.cvss import severity_from_score

        return severity_from_score(score)


def test_severity_band_mapping():
    assert Score.check(9.0) == Severity.CRITICAL
    assert Score.check(8.9) == Severity.HIGH
    assert Score.check(7.0) == Severity.HIGH
    assert Score.check(6.9) == Severity.MEDIUM
    assert Score.check(4.0) == Severity.MEDIUM
    assert Score.check(3.9) == Severity.LOW
    assert Score.check(0.1) == Severity.LOW
    assert Score.check(0.0) == Severity.NONE