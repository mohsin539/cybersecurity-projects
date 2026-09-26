"""Scoring engine that turns analysis findings into an aggregate verdict."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List

from src.config import SCORE_THRESHOLD_HIGH, SCORE_THRESHOLD_SUSPICIOUS
from src.detection.analyzers import Finding, Severity, analyze_record
from src.generator import TrafficRecord


class Verdict(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    FRONTED = "fronted"


@dataclass
class FlowVerdict:
    record_id: str
    scenario: str
    sni: str
    host_header: str
    dest_ip: str
    cdn_owner: str
    score: int
    label: Verdict
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "record_id": self.record_id,
            "scenario": self.scenario,
            "sni": self.sni,
            "host_header": self.host_header,
            "dest_ip": self.dest_ip,
            "cdn_owner": self.cdn_owner,
            "score": self.score,
            "label": self.label.value,
            "findings": len(self.findings),
        }


def _score(findings: List[Finding]) -> int:
    return min(100, sum(f.weight for f in findings))


def _label(score: int) -> Verdict:
    if score >= SCORE_THRESHOLD_HIGH:
        return Verdict.FRONTED
    if score >= SCORE_THRESHOLD_SUSPICIOUS:
        return Verdict.SUSPICIOUS
    return Verdict.BENIGN


def evaluate(rec: TrafficRecord) -> FlowVerdict:
    findings = analyze_record(rec)
    score = _score(findings)
    return FlowVerdict(
        record_id=rec.record_id,
        scenario=rec.scenario,
        sni=rec.sni,
        host_header=rec.host_header,
        dest_ip=rec.dest_ip,
        cdn_owner=rec.cdn_owner,
        score=score,
        label=_label(score),
        findings=findings,
    )


def evaluate_all(records: List[TrafficRecord]) -> Dict[str, FlowVerdict]:
    return {rec.record_id: evaluate(rec) for rec in records}