from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Sample:
    """Normalized intake record (see architecture.md: Malware Vault / Sample Collector)."""

    sha256: str
    original_name: str
    size: int
    ext: str
    magic_hex: str
    magic_hint: str
    quarantined_path: str
    created_iso: str


@dataclass
class StaticFindings:
    """Results of the read-only Static Analyzer (architecture.md section 6.4)."""

    entropy: float
    block_high_entropy_ratio: float
    strings: list[str] = field(default_factory=list)
    pe_info: dict[str, Any] = field(default_factory=dict)
    crypto_imports: list[str] = field(default_factory=list)
    ransom_indicators: list[str] = field(default_factory=list)


@dataclass
class AnalysisSummary:
    """Aggregated outcome of one analysis job."""

    sample_id: int
    fingerprint: dict[str, Any]
    pattern: str
    risk_flag: bool
    confidence: float
    report_md: str
    report_json: str


@dataclass
class AuditEvent:
    seq: int
    ts: str
    actor: str
    action: str
    detail: str
    prev_hash: str
    hash: str = ""


# Normalized result-model schema version (architecture.md section 7.5)
RESULT_SCHEMA_VERSION = "sba.pattern.v1"