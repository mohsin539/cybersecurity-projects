"""Scoring: weighted risk per finding + device/org aggregates (architecture §2.4).

risk = base_severity × exposure × blast_radius ÷ mitigations
"""
from __future__ import annotations

from typing import List

BASE = {"critical": 10, "high": 7, "medium": 4, "low": 1}
EXPOSURE = {"internet": 2.0, "internal": 1.2, "isolated": 0.5}
BLAST = {"many": 1.5, "some": 1.0, "none": 0.6}


def score_finding(finding: dict, exposure="internet", blast_radius="some",
                  compensations: int = 1, blast_weights=None) -> float:
    blast_weights = blast_weights or BLAST
    raw = BASE.get(finding.get("severity", "low"), 1)
    risk = raw * EXPOSURE.get(exposure, 1.0) * blast_weights.get(blast_radius, 1.0)
    if compensations > 0:
        risk /= float(compensations)
    return round(min(risk, 20.0), 2)


def aggregate(findings: List[dict], device: str = "") -> dict:
    """Device/org aggregate: 0-100 risk, higher = worse."""
    if not findings:
        return {"device": device, "score": 0.0, "count": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "low")
        if sev in totals:
            totals[sev] += 1
    score = round(min(sum(
        score_finding(f) for f in findings
    ) / max(len(findings), 1) * 10.0, 100.0), 1)
    return {
        "device": device, "score": score, "count": len(findings),
        **totals,
    }