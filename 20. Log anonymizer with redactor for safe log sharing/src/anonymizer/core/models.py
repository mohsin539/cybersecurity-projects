"""Core model definitions for the Log Anonymizer system."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any


class DataClassification(Enum):
    """Data classification levels per security framework."""

    CRITICAL = auto()  # Direct unique identifiers
    HIGH = auto()  # Sensitive financial/health data
    MEDIUM = auto()  # Quasi-identifiers
    LOW = auto()  # Context-dependent data
    SAFE = auto()  # Non-sensitive operational data


class RedactionStrategy(Enum):
    """Supported redaction techniques."""

    FULL_REDACT = auto()
    PARTIAL_MASK = auto()
    TOKENIZE = auto()
    PSEUDONYMIZE = auto()
    GENERALIZE = auto()
    DATE_SHIFT = auto()
    CONTEXTUAL = auto()


@dataclass
class SensitiveEntity:
    """A detected sensitive data element."""

    entity_type: str  # e.g., 'SSN', 'EMAIL', 'CREDIT_CARD'
    value: str  # original text
    start: int  # start index in log line
    end: int  # end index in log line
    confidence: float = 1.0
    classification: DataClassification = DataClassification.MEDIUM
    strategy: RedactionStrategy = RedactionStrategy.FULL_REDACT
    context_key: str | None = None


@dataclass
class DetectionResult:
    """Result of detection pass over one log line."""

    line_id: str
    original: str
    redacted: str
    entities: list[SensitiveEntity] = field(default_factory=list)
    processing_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    policy_id: str = "default"

    def to_dict(self) -> dict[str, Any]:
        return {
            "line_id": self.line_id,
            "redacted": self.redacted,
            "entity_count": len(self.entities),
            "entity_types": [e.entity_type for e in self.entities],
            "processing_time_ms": round(self.processing_time_ms, 3),
            "timestamp": self.timestamp.isoformat(),
            "policy_id": self.policy_id,
        }


@dataclass
class AuditRecord:
    """Immutable audit entry for every redaction action."""

    event_id: str
    timestamp: str
    action: str
    data_class: str
    entity_type: str
    original_hash: str
    redacted_hash: str
    policy_applied: str
    confidence: float
    merkle_proof: str = ""
    chain_input: str = ""
    seq: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "seq": self.seq,
            "timestamp": self.timestamp,
            "action": self.action,
            "data_class": self.data_class,
            "entity_type": self.entity_type,
            "original_hash": self.original_hash,
            "redacted_hash": self.redacted_hash,
            "policy_applied": self.policy_applied,
            "confidence": self.confidence,
            "merkle_proof": self.merkle_proof,
            "chain_input": self.chain_input,
        }
