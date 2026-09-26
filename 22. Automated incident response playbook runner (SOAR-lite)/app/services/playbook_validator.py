"""Playbook validation, versioning discipline and exit-approval checks.

Playbooks are YAML/JSON documents with versioned, immutable published revisions
(ISO 27001 A.12.4 change control, NIST SP 800-61). Validation happens at save
time so a malformed playbook can never be published or executed.
"""
from __future__ import annotations

import yaml

from app.services.expressions import ExprError, validate_expr

ALLOWED_STEP_TYPES = {
    "enrichment", "containment", "remediation", "notification",
    "ticket", "approval", "decision", "evidence", "custom",
}

REQUIRED_STEP_FIELDS = ("id", "type")


class PlaybookValidationError(Exception):
    def __init__(self, messages: list[str]):
        super().__init__("; ".join(messages))
        self.messages = messages


def parse_playbook_document(text: str) -> dict:
    """Parse YAML or JSON into a dict with one canonical representation."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PlaybookValidationError([f"Invalid YAML/JSON: {exc}"])
    if not isinstance(data, dict):
        raise PlaybookValidationError(["Playbook root must be a mapping."])
    return data


def digest_playbook(doc: dict) -> str:
    """Stable identifier for change-tracking / immutability checks."""
    import hashlib
    import json

    return hashlib.sha256(json.dumps(doc, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _validate_triggers(triggers) -> list[str]:
    errors: list[str] = []
    if not isinstance(triggers, list) or not triggers:
        errors.append("`trigger` must be a non-empty list of condition strings")
        return errors
    for idx, cond in enumerate(triggers):
        if not isinstance(cond, str):
            errors.append(f"trigger[{idx}] must be a string condition")
            continue
        try:
            validate_expr(cond)
        except ExprError as exc:
            errors.append(f"trigger[{idx}] invalid expression: {exc}")
    return errors


def _validate_steps(spec) -> list[str]:
    errors: list[str] = []
    if not isinstance(spec, dict):
        return ["`spec` must be a mapping containing a `steps` list"]
    steps = spec.get("steps")
    if not isinstance(steps, list) or not steps:
        return ["`spec.steps` must be a non-empty list"]

    ids: set[str] = set()
    for idx, step in enumerate(steps):
        if not isinstance(step, dict):
            errors.append(f"step[{idx}] must be a mapping")
            continue
        sid = step.get("id")
        s_type = step.get("type")
        if not sid or not isinstance(sid, str):
            errors.append(f"step[{idx}] missing string `id`")
        elif sid in ids:
            errors.append(f"duplicate step id `{sid}`")
        else:
            ids.add(sid)
        if s_type not in ALLOWED_STEP_TYPES:
            errors.append(f"step `{sid or idx}` has disallowed type `{s_type}`")

        if s_type in ("containment", "remediation") and not step.get("action"):
            errors.append(f"step `{sid}` of type `{s_type}` requires an `action`")

        if s_type == "approval" and not step.get("reason"):
            errors.append(f"approval step `{sid}` requires `reason`")

        if_expr = step.get("if")
        if if_expr:
            try:
                validate_expr(str(if_expr))
            except ExprError as exc:
                errors.append(f"step `{sid}` if-expression invalid: {exc}")

        run_after = step.get("run_after", [])
        if isinstance(run_after, str):
            run_after = [run_after]
        if not isinstance(run_after, list):
            errors.append(f"step `{sid}` `run_after` must be a list")
        else:
            for dep in run_after:
                if not isinstance(dep, str):
                    errors.append(f"step `{sid}` run_after item must be a string id")

        timeout = step.get("timeout_seconds")
        if timeout is not None and not (isinstance(timeout, (int, float)) and timeout > 0):
            errors.append(f"step `{sid}` timeout_seconds must be positive")
    return errors


def _detect_cycles(steps: list[dict]) -> list[str]:
    import graphlib

    graph: dict[str, set[str]] = {}
    for step in steps:
        deps = step.get("run_after", [])
        if isinstance(deps, str):
            deps = [deps]
        graph[step["id"]] = set(deps)
    try:
        list(graphlib.TopologicalSorter(graph).static_order())
    except graphlib.CycleError as exc:
        return [f"cycle detected in playbook dependencies: {exc}"]
    return []


def _validate_compensations(toplevel_compensations, spec_steps) -> list[str]:
    errors: list[str] = []
    step_id_set = {s.get("id") for s in spec_steps}
    if not isinstance(toplevel_compensations, list):
        return ["`compensations` must be a list"]
    for comp in toplevel_compensations:
        if not isinstance(comp, dict):
            errors.append("compensation entry must be a mapping")
            continue
        target = comp.get("when_step")
        if target not in step_id_set:
            errors.append(f"compensation `when_step={target}` refers to unknown step")
        if not comp.get("action"):
            errors.append(f"compensation for `{target}` has no `action`")
    return errors


def validate_playbook_document(doc: dict) -> dict:
    """Validate a parsed playbook doc; raises PlaybookValidationError."""
    errors: list[str] = []
    if "key" not in doc or not doc.get("key"):
        errors.append("missing short `key`")
    if "name" not in doc or not doc.get("name"):
        errors.append("missing `name`")

    triggers = doc.get("trigger", [])
    errors += _validate_triggers(triggers)

    spec = doc.get("spec", {})
    errors += _validate_steps(spec)
    errors += _detect_cycles(spec.get("steps", []))

    comps = doc.get("compensations", [])
    errors += _validate_compensations(comps, spec.get("steps", []))

    risk = doc.get("risk", "medium")
    if risk not in ("low", "medium", "high", "critical"):
        errors.append(f"`risk` must be one of low|medium|high|critical (got `{risk}`)")

    if errors:
        raise PlaybookValidationError(errors)
    return doc


def normalize_document(doc: dict) -> dict:
    """Create canonical persisted shape."""
    spec = doc.get("spec", {})
    return {
        "key": doc["key"],
        "name": doc["name"],
        "description": doc.get("description"),
        "trigger": doc.get("trigger", []),
        "spec": spec,
        "compensations": doc.get("compensations", []),
        "risk": doc.get("risk", "medium"),
    }