"""Tests for security controls: audit trail, validation, policy engine."""

import pytest

from anonymizer.core.models import DataClassification, RedactionStrategy
from anonymizer.security import (
    AuditTrail,
    InputValidator,
    hmac_chain_step,
    verify_chain,
)
from anonymizer.security.input_validation import ValidationError
from anonymizer.services import LoadedPolicy, PolicyEngine, RedactionRule

# ---------- Audit trail ----------


def test_audit_record_creation(tmp_path):
    trail = AuditTrail(output_dir=tmp_path / "audit")
    rec = trail.record_redaction(
        original_value="123-45-6789",
        redacted_value="[REDACTED]",
        action="FULL_REDACT",
        data_class="CRITICAL",
        entity_type="SSN",
    )
    assert rec.event_id
    assert rec.original_hash != "123-45-6789"  # never store original
    assert trail.record_count == 1
    assert len(trail.chain_root) == 64


def test_audit_chain_is_tamper_evident(tmp_path):
    trail = AuditTrail(output_dir=tmp_path / "audit")
    for i in range(5):
        trail.record_redaction(
            original_value=f"value-{i}",
            redacted_value=f"[REDACTED-{i}]",
            action="MASK",
            data_class="MEDIUM",
            entity_type="EMAIL",
        )
    # Recomputing root from disk matches the in-memory root
    assert trail.rebuild_root_from_disk() == trail.chain_root


def test_verify_chain_function():
    hashes = ["h1", "h2", "h3"]
    root = "0" * 64
    for h in hashes:
        root = hmac_chain_step(root, h)
    assert verify_chain(hashes, root)
    assert not verify_chain(hashes, "f" * 64)


# ---------- Input validation ----------


def test_validation_rejects_null_byte():
    v = InputValidator()
    with pytest.raises(ValidationError) as exc:
        v.validate_line("log line \\x00 with null")  # escaped NUL sequence
    assert exc.value.code == "NULL_BYTE"


def test_validation_rejects_control_char():
    v = InputValidator()
    with pytest.raises(ValidationError) as exc:
        v.validate_line("log line \x00 with null")  # literal NUL byte
    assert exc.value.code == "CONTROL_CHAR"


def test_validation_rejects_oversized():
    v = InputValidator(max_line_length=10)
    with pytest.raises(ValidationError):
        v.validate_line("x" * 50)


def test_validation_rejects_embedded_newline():
    v = InputValidator()
    with pytest.raises(ValidationError):
        v.validate_line("line1\nline2")


def test_validation_accepts_normal():
    v = InputValidator()
    assert v.validate_line("normal log entry here") == "normal log entry here"


def test_batch_limit():
    v = InputValidator(max_batch_size=3)
    with pytest.raises(ValidationError):
        v.validate_batch(["a"] * 5)


# ---------- Policy engine ----------


def test_policy_forbids_critical_data():
    policy = LoadedPolicy(
        id="share-vendor",
        description="Vendor sharing",
        allowed_data_classes=["SAFE", "LOW"],
        rules=[],
    )
    assert not policy.allows(DataClassification.CRITICAL)
    strategy = policy.strategy_for("SSN", DataClassification.CRITICAL, RedactionStrategy.TOKENIZE)
    assert strategy == RedactionStrategy.FULL_REDACT  # forced downgrade


def test_policy_rule_overrides_strategy():
    policy = LoadedPolicy(
        id="p2",
        description="Analytics",
        allowed_data_classes=["SAFE", "LOW", "MEDIUM"],
        rules=[RedactionRule(strategy=RedactionStrategy.GENERALIZE, data_classes=["MEDIUM"])],
    )
    assert (
        policy.strategy_for("EMAIL", DataClassification.MEDIUM, RedactionStrategy.FULL_REDACT)
        == RedactionStrategy.GENERALIZE
    )


def test_policy_from_dict():
    engine = PolicyEngine()
    engine.register(
        PolicyEngine.from_dict(
            {
                "policies": [
                    {
                        "id": "p3",
                        "description": "test",
                        "allowed_data_classes": ["SAFE", "LOW"],
                        "redaction_rules": [{"strategy": "FULL_REDACT"}],
                        "retention_days": 7,
                    }
                ]
            }
        )
    )
    assert engine.get("p3") is not None
    assert engine.list_ids() == ["p3"]
