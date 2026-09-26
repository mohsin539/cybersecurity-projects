"""ScanService: catalog + collectors -> ScanRecord (evidence-backed results).

Read-only end to end. Every result carries Evidence (source + observed) so the
report is an audit artifact, not just a score.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Callable

from cisguard.domain.catalog import CONTROLS
from cisguard.domain.errors import CollectorError
from cisguard.domain.models import Control, Evidence, Result, ScanRecord, Status
from cisguard.domain.scoring import weighted_score

Progress = Callable[[int, int, str], None]  # done, total, control_id


class ScanService:
    def __init__(self, registry, services, commands, auditpol, defender, system) -> None:
        self._registry = registry
        self._services = services
        self._commands = commands
        self._auditpol = auditpol
        self._defender = defender
        self._system = system

    def scan(self, progress: Progress | None = None) -> ScanRecord:
        report = progress or (lambda done, total, cid: None)
        started = datetime.now(timezone.utc)
        hostname = self._system.hostname()
        os_caption = self._system.os_caption()
        results: list[Result] = []
        total = len(CONTROLS)

        # Prefetch: one batched call for all Defender preference controls.
        defender_names = [c.audit_spec["pref"] for c in CONTROLS if c.audit_type == "defender"]
        defender_cache: dict[str, str] = {}
        if defender_names and hasattr(self._defender, "preferences"):
            try:
                defender_cache = dict(self._defender.preferences(defender_names))
            except Exception:
                defender_cache = {}
        self._defender_cache = defender_cache

        for idx, control in enumerate(CONTROLS):
            report(idx, total, control.control_id)
            results.append(self._assess(control))
        report(total, total, "")

        finished = datetime.now(timezone.utc)
        controls_by_id = {c.control_id: c for c in CONTROLS}
        summary = _summary(scan_id=uuid.uuid4().hex[:12], started=started, finished=finished,
                           hostname=hostname, os_caption=os_caption, results=results,
                           controls=controls_by_id)
        return ScanRecord(summary=summary, results=results, controls_by_id=controls_by_id)

    # -- per-control dispatch ---------------------------------------------

    def _assess(self, control: Control) -> Result:
        spec = control.audit_spec
        try:
            if control.audit_type == "registry":
                return self._assess_registry(control, spec)
            if control.audit_type == "service":
                return self._assess_service(control, spec)
            if control.audit_type == "command":
                return self._assess_command(control, spec)
            if control.audit_type == "auditpol":
                return self._assess_auditpol(control, spec)
            if control.audit_type == "defender":
                return self._assess_defender(control, spec)
            return _error_result(control, f"unknown audit_type {control.audit_type}")
        except CollectorError as exc:
            return _error_result(control, str(exc))

    def _assess_registry(self, control: Control, spec: dict) -> Result:
        from cisguard.domain.evaluator import evaluate

        raw = self._registry.read_value(spec["hive"], spec["path"], spec["value"])
        source = f'{spec["hive"]}\\{spec["path"]}:{spec["value"]}'
        if raw is None:
            missing = spec.get("missing", "fail")
            observed = "(value not present)"
            status = {"pass": Status.PASS, "fail": Status.FAIL, "na": Status.NOT_APPLICABLE}[missing]
            return Result(control.control_id, status, observed, str(spec["expect"][1]),
                          Evidence(source, observed),
                          detail="Value absent from registry" if status == Status.FAIL else "")
        observed = raw if isinstance(raw, (int, str)) else str(raw)
        if spec.get("value_type") == "int" and isinstance(raw, str) and raw.isdigit():
            observed = int(raw)
        ev = Evidence(source, str(observed))
        op, expected = spec["expect"]
        return evaluate(control, ev, op, expected)

    def _assess_service(self, control: Control, spec: dict) -> Result:
        from cisguard.domain.evaluator import evaluate

        state = self._services.query(spec["name"])
        ev = Evidence(f"sc query {spec['name']}", state)
        op, expected = spec["expect"]
        return evaluate(control, ev, op, expected)

    def _assess_command(self, control: Control, spec: dict) -> Result:
        from cisguard.domain.evaluator import evaluate
        from cisguard.infrastructure.parsers import parse

        out = self._commands.run(list(spec["argv"]))
        observed = parse(spec["parse"], out)
        if observed == "(empty)":
            # Tool failed/unavailable (e.g. manage-bde on non-BitLocker SKU):
            # cannot assert either way -> N/A, never a silent FAIL.
            ev = Evidence(" ".join(spec["argv"]), "(tool unavailable)")
            return Result(control.control_id, Status.NOT_APPLICABLE, ev.observed,
                          str(spec["expect"][1]), ev,
                          detail="Assessment tool returned no usable output")
        ev = Evidence(" ".join(spec["argv"]), observed)
        op, expected = spec["expect"]
        return evaluate(control, ev, op, expected)

    def _assess_auditpol(self, control: Control, spec: dict) -> Result:
        name = spec["subcategory"]
        state = self._auditpol.subcategory(name)
        checks: list[tuple[bool, bool]] = []  # (got, want)
        if spec.get("expect_success") is not None and "expect_success" in spec:
            checks.append((state["Success"], bool(spec["expect_success"])))
        if "expect_failure" in spec:
            checks.append((state["Failure"], bool(spec["expect_failure"])))
        ev = Evidence(f"auditpol /get /subcategory:'{name}'",
                      f"Success={state['Success']}, Failure={state['Failure']}")
        ok = all(got == want for got, want in checks)
        expected = ", ".join(
            f"{field}={'Enabled' if want else 'not required'}"
            for field, want in (
                ([("Success", bool(spec["expect_success"]))] if "expect_success" in spec else [])
                + ([("Failure", bool(spec["expect_failure"]))] if "expect_failure" in spec else [])
            )
        )
        return Result(control.control_id,
                      Status.PASS if ok else Status.FAIL,
                      ev.observed, expected, ev)

    def _assess_defender(self, control: Control, spec: dict) -> Result:
        from cisguard.domain.evaluator import evaluate

        cache = getattr(self, "_defender_cache", {})
        if spec["pref"] in cache:
            val = cache[spec["pref"]]
        else:
            val = self._defender.preference(spec["pref"])
        # Normalize PowerShell bool rendering: False -> 0, True -> 1
        if val in ("False", "True"):
            val = {"False": "0", "True": "1"}[val]
        ev = Evidence(f"Get-MpPreference.{spec['pref']}", val or "(unavailable)")
        op, expected = spec["expect"]
        return evaluate(control, ev, op, expected)


def _error_result(control: Control, message: str) -> Result:
    return Result(control.control_id, Status.ERROR, "(could not read)",
                  str(control.audit_spec.get("expect", ["", ""])[1] if control.audit_spec else ""),
                  Evidence(control.audit_type, "(no evidence)"), detail=message)


def _summary(scan_id, started, finished, hostname, os_caption, results, controls):
    from cisguard.domain.models import ScanSummary

    passed = sum(1 for r in results if r.status == Status.PASS)
    failed = sum(1 for r in results if r.status == Status.FAIL)
    errors = sum(1 for r in results if r.status == Status.ERROR)
    na = sum(1 for r in results if r.status == Status.NOT_APPLICABLE)
    return ScanSummary(
        scan_id=scan_id, started_at=started, finished_at=finished,
        hostname=hostname, os_caption=os_caption, total=len(results),
        passed=passed, failed=failed, errors=errors, not_applicable=na,
        score=weighted_score(results, controls),
    )
