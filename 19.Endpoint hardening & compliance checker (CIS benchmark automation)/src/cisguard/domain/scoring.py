"""Compliance scoring: weighted, severity-driven.

score = 100 × (earned weight / applicable weight)
Weights: critical=10, high=6, medium=3, low=1. ERROR results are excluded
from the denominator (cannot assert either way) but reported.
"""

from __future__ import annotations

from cisguard.domain.models import Result, ScanSummary, Severity, Status

WEIGHTS: dict[Severity, float] = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 6.0,
    Severity.MEDIUM: 3.0,
    Severity.LOW: 1.0,
    Severity.INFO: 0.0,
}


def compute_summary(
    scan_id: str,
    started_at,
    finished_at,
    hostname: str,
    os_caption: str,
    results: list[Result],
) -> ScanSummary:
    earned = 0.0
    possible = 0.0
    passed = failed = errors = na = 0
    for r in results:
        if r.status == Status.PASS:
            passed += 1
        elif r.status == Status.FAIL:
            failed += 1
        elif r.status == Status.ERROR:
            errors += 1
        else:
            na += 1
    return ScanSummary(
        scan_id=scan_id,
        started_at=started_at,
        finished_at=finished_at,
        hostname=hostname,
        os_caption=os_caption,
        total=len(results),
        passed=passed,
        failed=failed,
        errors=errors,
        not_applicable=na,
        score=0.0,
    )


def weighted_score(results: list[Result], controls: dict) -> float:
    """controls: control_id -> Control (for severity weights)."""
    earned = possible = 0.0
    for r in results:
        ctrl = controls.get(r.control_id)
        if ctrl is None:
            continue
        w = WEIGHTS.get(ctrl.severity, 1.0)
        if r.status == Status.PASS:
            earned += w
            possible += w
        elif r.status == Status.FAIL:
            possible += w
        # ERROR / N/A: excluded from denominator
    return round(100.0 * earned / possible, 1) if possible > 0 else 0.0
