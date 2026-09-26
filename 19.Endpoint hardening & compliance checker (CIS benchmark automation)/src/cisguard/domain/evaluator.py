"""Evaluation engine: Evidence + Control -> Result.

Pure functions; comparison operators shared by all collectors.
"""

from __future__ import annotations

from cisguard.domain.models import Control, Evidence, Result, Status


def _coerce_pair(observed, expected):
    """Numeric-aware comparison: '1' == 1, '255' == 255, else string compare."""
    if isinstance(observed, (int, float)) or isinstance(expected, (int, float)):
        try:
            return float(observed), float(expected)
        except (TypeError, ValueError):
            return str(observed), str(expected)
    return observed, expected


def _cmp(op: str, observed, expected) -> bool:
    try:
        if op == "eq":
            o, e = _coerce_pair(observed, expected)
            return o == e
        if op == "ne":
            o, e = _coerce_pair(observed, expected)
            return o != e
        if op == "gte":
            return float(observed) >= float(expected)
        if op == "lte":
            return float(observed) <= float(expected)
        if op == "gt":
            return float(observed) > float(expected)
        if op == "lt":
            return float(observed) < float(expected)
        if op == "in":
            return str(observed).lower() in [str(x).lower() for x in expected]
        if op == "not_in":
            return str(observed).lower() not in [str(x).lower() for x in expected]
        if op == "contains":
            return str(expected).lower() in str(observed).lower()
        if op == "regex":
            import re

            return re.match(str(expected), str(observed), re.IGNORECASE) is not None
    except (TypeError, ValueError):
        return False
    return False


def evaluate(control: Control, evidence: Evidence, op: str, expected) -> Result:
    """op/expected come from the control's audit_spec['expect'] = [op, value]."""
    expected_str = str(expected)
    try:
        ok = _cmp(op, evidence.observed, expected)
        status = Status.PASS if ok else Status.FAIL
        detail = ""
    except Exception as exc:  # defensive: evaluator must never raise
        status, detail = Status.ERROR, f"evaluator error: {exc}"
    return Result(
        control_id=control.control_id,
        status=status,
        observed=evidence.observed,
        expected=expected_str,
        evidence=evidence,
        detail=detail,
    )
