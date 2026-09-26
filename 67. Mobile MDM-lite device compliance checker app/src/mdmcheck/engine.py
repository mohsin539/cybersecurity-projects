"""Compliance engine: evaluates device telemetry against a policy."""
from __future__ import annotations

import re
from typing import Any

from .model import (
    PASS_THRESHOLD,
    PLATFORMS,
    SEVERITY_WEIGHT,
    VERDICTS,
    Rule,
    RuleResult,
    ScanResult,
    now_iso,
)


def _verdict_for_rule(rule: Rule, platform: str, telemetry: dict) -> tuple[str, Any]:
    """Return (verdict, actual_value) for one rule against device telemetry."""
    if rule.platform != "both" and rule.platform != platform:
        return "NA", None

    t = telemetry or {}
    osv = t.get("os", {})
    sec = t.get("security", {})
    apps = t.get("apps", {})
    installed = apps.get("installed", []) or []

    actual = None
    try:
        if rule.kind == "version_gte":
            actual = str(osv.get("version", ""))
            verdict = "PASS" if version_gte(actual, str(rule.expected)) else "FAIL"
        elif rule.kind == "boolean":
            actual = sec.get(rule.id.split(".")[-1], rule.expected)
            if not isinstance(actual, bool):
                actual = bool(actual)
            verdict = "PASS" if actual == rule.expected else "FAIL"
            # anchor alternative keys used by collectors
            key = rule.id.split(".")[-1]
            if key == "jailbreak":
                actual = sec.get("rooted", sec.get("jailbreak", False))
                verdict = "PASS" if actual == rule.expected else "FAIL"
            if key == "unknownsources":
                actual = sec.get("unknown_sources", False)
                verdict = "PASS" if actual == rule.expected else "FAIL"
            if key == "allowUntrusted":
                actual = sec.get("side_loading", False)
                verdict = "PASS" if actual == rule.expected else "FAIL"
        elif rule.kind == "allowlist":
            required = rule.expected or []
            missing = [a for a in required if a not in installed]
            actual = missing
            verdict = "PASS" if not missing else "FAIL"
        elif rule.kind == "denylist":
            banned = rule.expected or []
            found = [a for a in banned if a in installed]
            actual = found
            verdict = "PASS" if not found else "FAIL"
        elif rule.kind == "list_contains":
            items = rule.expected or []
            actual = [i for i in items if i in installed]
            verdict = "PASS" if actual else "FAIL"
        else:
            verdict = "NA"
    except Exception:
        verdict = "NA"
    return verdict, actual


def version_gte(actual: str, minimum: str) -> bool:
    def key(v: str):
        v = v.strip().lower()
        m = re.match(r"(\d+(?:\.\d+)*)", v)
        parts = [int(x) for x in (m.group(1).split(".") if m else [])] or [0]
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])

    return key(actual) >= key(minimum)


def evaluate(policy: dict, device_id: str, platform: str, telemetry: dict) -> ScanResult:
    """Run all applicable rules and produce a ScanResult."""
    if platform not in PLATFORMS:
        platform = "android"

    results: list[RuleResult] = []
    total_w = 0
    pass_w = 0
    for r in policy.get("rules", []):
        rule = Rule(**r) if not isinstance(r, Rule) else r
        verdict, actual = _verdict_for_rule(rule, platform, telemetry)
        w = SEVERITY_WEIGHT.get(rule.severity, 1)
        results.append(
            RuleResult(
                rule_id=rule.id,
                group=rule.group,
                label=rule.label,
                description=rule.description,
                severity=rule.severity,
                verdict=verdict,
                actual=actual,
                expected=rule.expected,
                remediation=rule.remediation,
            )
        )
        if verdict in ("PASS", "FAIL"):
            total_w += w
            if verdict == "PASS":
                pass_w += w

    crit_fail = any(
        r.severity == "critical" and r.verdict == "FAIL" for r in results
    )
    ratio = pass_w / total_w if total_w else 0.0
    threshold = float(policy.get("threshold", PASS_THRESHOLD))
    status = "COMPLIANT" if (not crit_fail and ratio >= threshold) else "NON_COMPLIANT"

    return ScanResult(
        at=now_iso(),
        mode="engine",
        status=status,
        score=round(ratio * 100, 1),
        pass_count=sum(r.verdict == "PASS" for r in results),
        fail_count=sum(r.verdict == "FAIL" for r in results),
        na_count=sum(r.verdict == "NA" for r in results),
        results=[r.to_dict() for r in results],
    )