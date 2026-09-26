"""Report data model aggregating demo results for the exporters."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List

from src.detection.analyzers import Finding
from src.detection.engine import FlowVerdict
from src.frameworks import summary_stats
from src.generator import TrafficRecord


@dataclass
class ReportBundle:
    project: str
    version: str
    generated_at: str
    records: List[TrafficRecord]
    verdicts: List[FlowVerdict]
    findings: List[Finding]
    framework_stats: dict
    meta: dict = field(default_factory=dict)

    @classmethod
    def build(cls, records: List[TrafficRecord],
              verdicts: List[FlowVerdict],
              findings: List[Finding],
              generated_at: str) -> "ReportBundle":
        return cls(
            project="Traffic Obfuscation Techniques Demo",
            version="1.0.0",
            generated_at=generated_at,
            records=records,
            verdicts=verdicts,
            findings=findings,
            framework_stats=summary_stats(),
            meta={
                "scenarios": sorted({r.scenario for r in records}),
                "typical_score": {
                    r.scenario: [v for v in verdicts if v.scenario == r.scenario][0].score
                    for r in records
                },
            },
        )

    def verdict_rows(self) -> List[dict]:
        return [v.to_dict() for v in self.verdicts]

    def finding_rows(self) -> List[dict]:
        return [asdict(f) for f in self.findings]

    def summary_of_records(self) -> List[dict]:
        return [r.to_dict() for r in self.records]