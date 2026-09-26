"""Orchestrator: alert→case→playbook selection, durable step execution.

This module implements a durable, replayable execution model on top of the
relational store (NIST SP 800-61 automated response / ISO 27001 A.16). Every
step transition is committed before the next step is attempted, so a crash at
any point leaves the run resumable by the worker loop (`app.worker`).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import logging
import time

from sqlalchemy import asc, select, update
from sqlalchemy.orm import Session

from app.db.models import (
    Alert,
    ApprovalRequest,
    Case,
    CaseTimeline,
    ExecutionRun,
    Playbook,
    StepRun,
)
from app.services import connector_runtime, cases as case_service
from app.services.expressions import eval_expr
from app.services.playbook_validator import digest_playbook

log = logging.getLogger("soarlite.engine")

RUN_PENDING = "pending"
RUN_RUNNING = "running"
RUN_AWAITING = "awaiting_approval"
RUN_SUCCEEDED = "succeeded"
RUN_FAILED = "failed"
RUN_COMPENSATED = "compensated"
RUN_CANCELLED = "cancelled"

STEP_QUEUED = "queued"
STEP_RUNNING = "running"
STEP_SUCCEEDED = "succeeded"
STEP_FAILED = "failed"
STEP_SKIPPED = "skipped"
STEP_AWAITING = "awaiting_approval"


# ------------------------------------------------------------------ selection

def select_playbook(db: Session, alert: Alert) -> Playbook | None:
    """Choose the highest-version published playbook whose triggers match."""
    context = alert_context(alert)
    playbooks = db.execute(
        select(Playbook)
        .where(Playbook.status == "published")
        .order_by(asc(Playbook.key), asc(Playbook.version))
    ).scalars().all()

    # group by key, take latest version per key, evaluate
    latest: dict[str, Playbook] = {}
    for pb in playbooks:
        latest[pb.key] = pb
    for pb in latest.values():
        triggers = pb.trigger or []
        for condition in triggers:
            try:
                if eval_expr(condition, context):
                    return pb
            except Exception as exc:  # malformed trigger should never block
                log.exception("trigger eval failed pb=%s: %s", pb.key, exc)
    return None


def alert_context(alert: Alert) -> dict:
    return {
        "alert": {
            "id": alert.id,
            "source": alert.source,
            "category": alert.category,
            "subcategory": alert.subcategory,
            "title": alert.title,
            "severity": alert.severity,
            "score": alert.score,
            "asset_id": alert.asset_id,
            "attack_tactic": alert.attack_tactic,
            "attack_technique": alert.attack_technique,
            "indicators": alert.indicators or [],
            "external_id": alert.external_id,
            "status": alert.status,
        },
        "raw": alert.raw_json,
    }


# ------------------------------------------------------------------ lifecycle

def open_case_for_alert(db: Session, alert: Alert, user: str = "system") -> Case:
    case = Case(title=f"[{alert.source.upper()}] {alert.title}", severity=alert.severity)
    db.add(case)
    db.flush()
    alert.case_id = case.id
    alert.status = "assigned"
    db.add(CaseTimeline(case_id=case.id, actor=user, event_type="case_opened",
                        message="Case opened from alert", detail={"alert_id": alert.id}))
    db.commit()
    db.refresh(case)
    return case


def start_run(db: Session, playbook: Playbook, alert: Alert | None = None, case: Case | None = None) -> ExecutionRun:
    run = ExecutionRun(
        case_id=case.id if case else None,
        alert_id=alert.id if alert else None,
        playbook_id=playbook.id,
        trigger_summary=f"playbook={playbook.key} v{playbook.version}",
        data={"playbook_digest": digest_playbook(_playbook_doc(playbook))},
        status=RUN_PENDING,
    )
    db.add(run)
    db.flush()

    # Pre-create step records (durable scheduling artifact; idempotency keys set later)
    for step in _steps_for(playbook):
        step_run = StepRun(
            run_id=run.id,
            step_id=step["id"],
            step_type=step.get("type", "custom"),
            action=step.get("action"),
            if_expr=step.get("if"),
            run_after=step.get("run_after", []),
            status=STEP_QUEUED,
            max_retries=int(step.get("retries", 0)),
        )
        db.add(step_run)
    db.commit()
    return run


def _playbook_doc(playbook: Playbook) -> dict:
    return {
        "key": playbook.key, "name": playbook.name, "version": playbook.version,
        "description": playbook.description, "trigger": playbook.trigger,
        "spec": playbook.spec, "compensations": playbook.compensations, "risk": playbook.risk,
    }


def _steps_for(playbook: Playbook) -> list[dict]:
    spec = playbook.spec or {}
    return spec.get("steps", [])


def _compensations_for(playbook: Playbook) -> list[dict]:
    return playbook.compensations or []


def build_run_context(db: Session, run: ExecutionRun) -> dict:
    ctx: dict = {"steps": {}}
    if run.case_id:
        case = db.get(Case, run.case_id)
        if case:
            ctx["case"] = {"id": case.id, "status": case.status, "nist_phase": case.nist_phase, "severity": case.severity}
    if run.alert_id:
        alert = db.get(Alert, run.alert_id)
        if alert:
            ctx["alert"] = alert_context(alert)["alert"]
            ctx["raw"] = alert.raw_json
    for step in run.steps:
        ctx["steps"][step.step_id] = {
            "status": step.status,
            "result": step.result or {},
            "action": step.action,
        }
    return ctx


# ------------------------------------------------------------------ worker.tick: the heart of durable execution

def tick(db: Session, now: dt.datetime | None = None) -> dict:
    """Run any number of ready executions one step forward. Called by worker loop."""
    now = now or dt.datetime.utcnow()
    stats = {"started": 0, "advanced": 0, "completed": 0, "failed": 0, "awaiting": 0}

    runs = db.execute(
        select(ExecutionRun).where(
            ExecutionRun.status.in_([RUN_PENDING, RUN_RUNNING, RUN_AWAITING])
        ).order_by(asc(ExecutionRun.created_at)).limit(50)
    ).scalars().all()

    for run in runs:
        try:
            progressed = _advance(db, run, now)
        except Exception as exc:  # never let one run kill the worker
            log.exception("run %s failed unexpectedly: %s", run.id, exc)
            run.status = RUN_FAILED
            run.finished_at = dt.datetime.utcnow()
            db.commit()
            stats["failed"] += 1
            continue

        if progressed == "awaiting":
            stats["awaiting"] += 1
        elif progressed == "done":
            stats["completed"] += 1
        elif progressed:
            stats["advanced"] += 1
        else:
            stats["started"] += 1
    return stats


def _advance(db: Session, run: ExecutionRun, now: dt.datetime) -> str | bool:
    """Advance one run as far as possible on the current tick. Mutates + commits."""
    playbook = db.get(Playbook, run.playbook_id)
    if playbook is None:
        run.status = RUN_FAILED
        db.commit()
        return "done"

    ctx = build_run_context(db, run)

    if run.status == RUN_PENDING:
        run.status = RUN_RUNNING
        run.started_at = now
        db.commit()

    # First pass: set idempotency keys + start approval records where required.
    for step_run in run.steps:
        if step_run.status == STEP_QUEUED and step_run.step_type in ("enrichment", "containment", "remediation", "notification", "ticket", "evidence", "custom", "decision"):
            args = _step_args(playbook, step_run.step_id)
            step_run.idempotency_key = connector_runtime.make_idempotency_key(run.id, step_run.step_id, step_run.action or "", args)
        if step_run.status == STEP_QUEUED and step_run.step_type == "approval":
            _ensure_approval(db, run, playbook, step_run)

    # Find the next ready step
    while True:
        ready = _next_ready_step(db, run, ctx)
        if ready is None:
            # Nothing ready. If any awaiting approval, pause the run.
            awaiting = [s for s in run.steps if s.status == STEP_AWAITING]
            failed = [s for s in run.steps if s.status == STEP_FAILED]
            if awaiting:
                run.status = RUN_AWAITING
                run.current_step_id = awaiting[0].step_id
                db.commit()
                return "awaiting"
            if failed:
                run.status = _close_run_with_failure(db, run, playbook)
                return "done"
            # All steps terminaled? finalize success
            remaining = [s for s in run.steps if s.status in (STEP_QUEUED, STEP_RUNNING)]
            if not remaining:
                run.status = RUN_SUCCEEDED
                run.finished_at = dt.datetime.utcnow()
                if run.case_id:
                    case_service.advance_case_phase(db, db.get(Case, run.case_id), "post_incident")
                db.commit()
                return "done"
            return "started"

        step = ready
        status = _execute_step(db, run, playbook, step, ctx, now)
        if status == "awaiting":
            run.status = RUN_AWAITING
            run.current_step_id = step.step_id
            db.commit()
            return "awaiting"
        if status == "failed":
            # attempt compensations and stop this run on this tick
            run.status = _close_run_with_failure(db, run, playbook)
            return "done"
        if status == "done":
            # control-only step, keep looping
            ctx = build_run_context(db, run)
            continue
        # status == "advanced": step executed and committed; loop for next step
        ctx = build_run_context(db, run)


def _close_run_with_failure(db: Session, run: ExecutionRun, playbook: Playbook) -> str:
    comps = _compensations_for(playbook)
    triggered = False
    for comp in comps:
        target = comp.get("when_step")
        try:
            step_run = next(s for s in run.steps if s.step_id == target)
        except StopIteration:
            continue
        if step_run.status == STEP_FAILED:
            action = comp.get("action")
            args = comp.get("args", {})
            log.info("compensating run=%s step=%s action=%s", run.id, target, action)
            try:
                connector = _resolve_connector(db, action)
                result = connector_runtime.execute_action(db, connector, _action_name(action), args)
                db.add(StepRun(
                    run_id=run.id, step_id=f"comp-{target}", step_type="compensation",
                    action=action, status=STEP_SUCCEEDED if result.get("ok") else STEP_FAILED,
                    message=f"compensation for step {target}",
                    result=result, idempotency_key=hashlib.sha256(f"{run.id}:comp:{target}".encode()).hexdigest(),
                ))
                triggered = True
            except Exception as exc:
                log.exception("compensation failed run=%s step=%s: %s", run.id, target, exc)
    final_status = RUN_COMPENSATED if triggered else RUN_FAILED
    run.finished_at = dt.datetime.utcnow()
    if run.case_id:
        case = db.get(Case, run.case_id)
        if case:
            case_service.add_timeline(db, case.id, actor="system", event_type="run_failed",
                                      message=f"Playbook run {run.id} {final_status}",
                                      detail={"status": final_status})
    db.commit()
    return final_status


# ---------------------------------------------------------------- step readiness

def _next_ready_step(db: Session, run: ExecutionRun, ctx: dict) -> StepRun | None:
    steps_by_id = {s.step_id: s for s in run.steps}
    for step in run.steps:
        if step.status not in (STEP_QUEUED, STEP_FAILED):
            continue
        if step.status == STEP_FAILED and (step.retries_done >= step.max_retries or step.max_retries == 0):
            continue  # only re-tryable ones are picked below

        # dependency check
        deps = step.run_after or []
        if isinstance(deps, str):
            deps = [deps]
        blocked = False
        for dep_id in deps:
            dep = steps_by_id.get(dep_id)
            if dep is None or dep.status not in (STEP_SUCCEEDED, STEP_SKIPPED):
                blocked = True
                break
        if blocked:
            continue

        # condition check
        if step.if_expr:
            try:
                if not eval_expr(step.if_expr, ctx):
                    if step.status == STEP_QUEUED:
                        step.status = STEP_SKIPPED
                        step.message = f"condition false: {step.if_expr}"
                        db.commit()
                        continue
            except Exception as exc:
                step.status = STEP_SKIPPED
                step.message = f"condition error: {exc}"
                db.commit()
                continue

        # approval ordering: if a previous approval for this step is pending/… 
        if step.step_type == "approval":
            appr = db.query(ApprovalRequest).filter_by(run_id=run.id, step_id=step.step_id).first()
            if appr and appr.status == "pending":
                return None  # wait for decision
            if appr and appr.status == "approved":
                if step.status == STEP_QUEUED:
                    step.status = STEP_SUCCEEDED
                    step.message = "approval granted"
                    step.result = {"approved": True}
                    db.commit()
                    continue  # control step passed
            if appr and appr.status == "denied":
                step.status = STEP_SKIPPED
                step.message = "approval denied"
                db.commit()
                continue

        if step.status == STEP_FAILED:
            if step.retries_done < step.max_retries:
                step.status = STEP_QUEUED
                step.retries_done += 1
                step.next_attempt_at = dt.datetime.utcnow() + dt.timedelta(seconds=step.retries_done * 2)
                db.commit()
                return step
            continue
        return step
    return None


def _ensure_approval(db: Session, run: ExecutionRun, playbook: Playbook, step_run: StepRun) -> None:
    existing = db.query(ApprovalRequest).filter_by(run_id=run.id, step_id=step_run.step_id).first()
    if existing:
        return
    approval = ApprovalRequest(
        run_id=run.id,
        step_id=step_run.step_id,
        case_id=run.case_id,
        reason=next((s.get("reason") for s in _steps_for(playbook) if s.get("id") == step_run.step_id), step_run.action),
        requested_by=step_run.action or "playbook",
    )
    db.add(approval)
    step_run.status = STEP_AWAITING
    db.commit()


# ---------------------------------------------------------------- step execution

def _execute_step(db: Session, run: ExecutionRun, playbook: Playbook, step: StepRun, ctx: dict, now: dt.datetime) -> str:
    step_def = next((s for s in _steps_for(playbook) if s.get("id") == step.step_id), {})
    step_type = step_def.get("type", step.step_type)

    if step_type == "maybe":  # reserved
        return "done"

    if step_type == "decision":
        expr = step_def.get("expr") or step.if_expr
        try:
            value = eval_expr(expr, ctx) if expr else True
            step.status = STEP_SUCCEEDED
            step.result = {"decision": bool(value)}
            step.message = f"decision → {bool(value)}"
        except Exception as exc:
            step.status = STEP_FAILED
            step.message = str(exc)
        step.finished_at = dt.datetime.utcnow()
        db.commit()
        return "done" if step.status == STEP_SUCCEEDED else "failed"

    if step_type == "approval":
        # approved already handled in readiness; if we reach here, keep awaiting
        appr = db.query(ApprovalRequest).filter_by(run_id=run.id, step_id=step.step_id).first()
        if appr:
            step.status = STEP_AWAITING
            step.message = "awaiting analyst approval"
            db.commit()
            return "awaiting"
        return "done"

    if step_type == "custom":
        # custom steps run through a connector action like any other
        pass

    if step_type == "evidence":
        step.status = STEP_RUNNING
        step.started_at = now
        raw = ctx.get("raw") or {}
        content = json.dumps({k: v for k, v in raw.items() if k not in ("raw_json",)}, sort_keys=True, default=str).encode("utf-8")
        sha = hashlib.sha256(content).hexdigest()
        step.status = STEP_SUCCEEDED
        step.result = {"sha256": sha, "bytes": len(content)}
        step.finished_at = dt.datetime.utcnow()
        db.commit()
        return "done"

    # generic action steps (enrichment/containment/…) require connector resolution
    action = step.action or step_def.get("action")
    args = step_def.get("args", {}) or {}
    if not action:
        step.status = STEP_FAILED
        step.message = "no action defined"
        step.finished_at = dt.datetime.utcnow()
        db.commit()
        return "failed"

    try:
        connector = _resolve_connector(db, action)
    except Exception as exc:
        step.status = STEP_FAILED
        step.message = f"connector resolution failed: {exc}"
        step.finished_at = dt.datetime.utcnow()
        db.commit()
        return "failed"

    # Rerun guard: if a previous execution of the same step already succeeded (idempotent)
    if step.idempotency_key:
        prior = db.query(StepRun).filter(
            StepRun.run_id == run.id,
            StepRun.step_id == step.step_id,
            StepRun.status == STEP_SUCCEEDED,
            StepRun.id != step.id,
        ).first()
        if prior:
            step.status = STEP_SUCCEEDED
            step.result = {"replayed": True, **prior.result}
            step.message = "idempotent replay of prior success"
            step.finished_at = dt.datetime.utcnow()
            db.commit()
            return "advanced"

    step.status = STEP_RUNNING
    step.started_at = now
    db.commit()
    try:
        result = connector_runtime.execute_action(db, connector, _action_name(action), args)
    except Exception as exc:
        log.exception("step failed run=%s step=%s: %s", run.id, step.step_id, exc)
        result = {"ok": False, "body": {"error": f"{exc.__class__.__name__}: {exc}"}}
    step.finished_at = dt.datetime.utcnow()

    if result.get("ok") is False:
        step.status = STEP_FAILED
        step.result = result
        step.message = (result.get("body") or {}).get("error") or result.get("body", "failed")
    else:
        step.status = STEP_SUCCEEDED
        step.result = result
        step.message = f"{result.get('body') if not isinstance(result.get('body'), dict) else result.get('body', {}).get('ref', 'ok')}"
        if step_type in ("containment", "remediation") and run.case_id:
            case = db.get(Case, run.case_id)
            if case:
                if step_type == "containment":
                    case_service.advance_case_phase(db, case, "containment")
                elif step_type == "remediation":
                    case_service.advance_case_phase(db, case, "eradication")
                case_service.add_timeline(
                    db, case.id, actor="system", event_type="step_succeeded",
                    message=f"Step `{step.step_id}` ({step_type}) via {action}",
                    detail={"run_id": run.id, "result": step.result},
                )
    db.commit()
    return "advanced" if step.status == STEP_SUCCEEDED else "failed"


def _step_args(playbook: Playbook, step_id: str) -> dict:
    for s in _steps_for(playbook):
        if s.get("id") == step_id:
            return s.get("args", {}) or {}
    return {}


def _resolve_connector(db: Session, action: str):
    """action format: <connector_name>.<action_name>."""
    from app.db.models import Connector

    if "." not in action:
        raise ValueError(f"action must be `connector.action`, got {action!r}")
    conn_name, _ = action.split(".", 1)
    connector = db.query(Connector).filter(Connector.name == conn_name).first()
    if connector is None:
        raise ValueError(f"connector `{conn_name}` does not exist")
    return connector


def _action_name(action: str) -> str:
    if "." not in action:
        return action
    return action.split(".", 1)[1]


def cancel_run(db: Session, run_id: str) -> ExecutionRun | None:
    run = db.get(ExecutionRun, run_id)
    if run and run.status in (RUN_PENDING, RUN_RUNNING, RUN_AWAITING):
        run.status = RUN_CANCELLED
        run.finished_at = dt.datetime.utcnow()
        db.commit()
    return run