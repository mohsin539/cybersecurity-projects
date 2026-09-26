"""Domain models — plain dataclasses, zero framework/OS imports."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"   # CIS L1/Scored, direct attack-surface impact
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"          # collector could not read state
    NOT_APPLICABLE = "N/A"


class Category(str, Enum):
    ACCOUNT_POLICIES = "1. Account Policies"
    LOCAL_POLICIES = "2. Local Policies"
    EVENT_LOG = "3. Event Log"
    SYSTEM_SERVICES = "4. System Services"
    REGISTRY = "5. Registry (Additional Controls)"
    DEFENSE = "6. Defender / Additional Hardening"


@dataclass(frozen=True, slots=True)
class Control:
    """A CIS-style control definition (static catalog data)."""

    control_id: str            # e.g. "1.1.1"
    title: str
    category: Category
    level: int                 # CIS Level 1 / 2
    severity: Severity
    rationale: str             # why this matters (analyst-facing)
    recommendation: str        # remediation hint (advisory text only)
    audit_type: str            # registry | service | command | auditpol
    audit_spec: dict = field(default_factory=dict)  # collector-specific args


@dataclass(frozen=True, slots=True)
class Evidence:
    """Raw observed state — kept verbatim for the audit trail."""

    source: str                # "HKLM\\...\\SystemLog", "sc query W32Time", ...
    observed: str              # human-readable observed value


@dataclass(frozen=True, slots=True)
class Result:
    control_id: str
    status: Status
    observed: str
    expected: str
    evidence: Evidence
    detail: str = ""           # error text when status == ERROR


@dataclass(frozen=True, slots=True)
class ScanSummary:
    scan_id: str
    started_at: datetime
    finished_at: datetime
    hostname: str
    os_caption: str
    total: int
    passed: int
    failed: int
    errors: int
    not_applicable: int
    score: float               # 0-100, weighted


@dataclass(frozen=True, slots=True)
class ScanRecord:
    summary: ScanSummary
    results: list[Result]
    controls_by_id: dict[str, Control]
