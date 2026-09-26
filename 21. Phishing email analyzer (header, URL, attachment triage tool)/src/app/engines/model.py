"""Shared analysis data model.

Findings are the atomic unit of evidence. Each finding carries severity,
a stable code, a human message, and optional evidence detail. Risk engine
aggregates findings into a verdict with full explainability (A04 - human readable).
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @property
    def rank(self) -> int:
        return self.value

    def __str__(self) -> str:  # display in UI
        return self.name.capitalize()

    @classmethod
    def from_rank(cls, rank: int) -> "Severity":
        return cls(max(1, min(5, rank)))


@dataclass
class Finding:
    engine: str                  # header | url | attachment | content | system
    code: str                    # stable, e.g. SPF_FAIL
    severity: Severity
    message: str
    detail: str = ""
    category: str = ""           # auth | anomaly | malicious | obfuscation | reputation

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("severity")
        d["severity"] = self.severity.name
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Finding":
        f = cls(engine=d.get("engine"), code=d["code"],
                severity=Severity[d.get("severity", "INFO")],
                message=d.get("message"), detail=d.get("detail", ""),
                category=d.get("category", ""))
        return f

    @property
    def display(self) -> str:
        return f"[{self.severity.value:1d}/{self.severity.name}] {self.engine.upper()} {self.code}: {self.message}"


@dataclass
class EngineResult:
    engine: str
    findings: List[Finding] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)  # extra evidence (records etc.)

    def add(self, code: str, severity: Severity, message: str,
            detail: str = "", category: str = "") -> None:
        self.findings.append(Finding(self.engine, code, severity, message, detail, category))

    @property
    def worst(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max((f.severity for f in self.findings), key=lambda s: s.rank)


@dataclass
class AnalysisReport:
    subject: str = ""
    message_id: str = ""
    from_addr: str = ""
    from_display: str = ""
    to: str = ""
    date: str = ""
    results: Dict[str, EngineResult] = field(default_factory=dict)
    risk_score: int = 0                     # 0..100
    verdict: str = "ALLOW"                  # allow/flag/sandbox/quarantine/block
    verdict_reason: str = ""
    created: float = 0.0

    def result(self, engine: str) -> EngineResult:
        r = self.results.setdefault(engine, EngineResult(engine))
        return r

    def all_findings(self) -> List[Finding]:
        out: List[Finding] = []
        for r in self.results.values():
            out.extend(r.findings)
        return sorted(out, key=lambda f: f.severity.rank, reverse=True)