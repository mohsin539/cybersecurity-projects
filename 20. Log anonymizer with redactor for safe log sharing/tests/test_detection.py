"""Tests for the detection engine (pattern + context layers)."""

import pytest

from anonymizer.core.models import DataClassification, RedactionStrategy
from anonymizer.detection import DetectionEngine


@pytest.fixture
def engine():
    return DetectionEngine()


def test_detects_ssn(engine):
    entities = engine.detect("user login failed for SSN: 123-45-6789")
    types = {e.entity_type for e in entities}
    assert "SSN" in types
    ssn = next(e for e in entities if e.entity_type == "SSN")
    assert ssn.value == "123-45-6789"
    assert ssn.classification == DataClassification.CRITICAL
    assert ssn.strategy == RedactionStrategy.FULL_REDACT


def test_detects_email(engine):
    entities = engine.detect("error from john.smith@example.com user")
    assert any(e.entity_type == "EMAIL" for e in entities)


def test_detects_credit_card_with_luhn(engine):
    # Valid Luhn test number (4539 6651 3101 6828)
    entities = engine.detect("payment card=4539665131016828 completed")
    cards = [e for e in entities if e.entity_type == "CREDIT_CARD"]
    assert len(cards) == 1
    assert cards[0].confidence >= 0.99  # elevated by context + validator


def test_rejects_invalid_card_via_luhn(engine):
    entities = engine.detect("payment card=4539665100000000 completed")
    assert not any(e.entity_type == "CREDIT_CARD" for e in entities)


def test_detects_password_secret(engine):
    entities = engine.detect("connection secret=supersecretpwd established")
    assert any(e.entity_type == "PASSWORD_SUSPECT" for e in entities)


def test_detects_api_key(engine):
    entities = engine.detect("api_key=abc123xyz789 token refresh")
    assert any(e.entity_type == "API_KEY_SUSPECT" for e in entities)


def test_detects_phone(engine):
    entities = engine.detect("contact via +1 (555) 123-4567")
    assert any(e.entity_type == "PHONE" for e in entities)


def test_no_false_positive_on_plain_text(engine):
    entities = engine.detect("request completed in 42ms with status 200")
    assert len(entities) == 0 or all(e.confidence < 0.7 for e in entities)


def test_contextual_refinement_keeps_keyed_values(engine):
    entities = engine.detect("ip=192.168.1.100 latency=12ms")
    ips = [e for e in entities if e.entity_type == "IP_ADDRESS"]
    assert ips
    assert any(e.context_key for e in ips)


def test_full_analyze_result_shape(engine):
    result = engine.analyze("email a@b.co ssn 111-22-3333")
    assert result.original
    assert result.line_id
    assert result.processing_time_ms >= 0
    assert len(result.entities) >= 2
