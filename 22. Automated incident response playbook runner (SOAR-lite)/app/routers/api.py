"""REST API: ingestion, cases, playbooks, approvals, connectors, audit, ops.

OWASP A1: every endpoint enforces RBAC via `require_perm`. Fields returned by
the API never include secrets (vault), password hashes, or connector secret refs
that leak an auth method other than existence.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request, UploadFile, File, Form, status
from pydantic import BaseModel
from sqlalchemy import asc, desc, func
from sqlalchemy.orm import Session

from app.config import settings
from app.core import audit as audit_svc
from app.core.security import require_perm
from app.db.base import db_session
from app.db.models import (
    Alert,
    ApprovalRequest,
    AuditEvent,
    Case,
    CaseTimeline,
    Connector,
    DeadLetter,
    ExecutionRun,
    Playbook,
    SecretVault,
    Setting,
    StepRun,
    User,
)
from app.services import cases as case_service, engine, ingestion
from app.services.playbook_validator import PlaybookValidationError, normalize_document, parse_playbook_document, validate_playbook_document
from app.services import connector_runtime

router = APIRouter(prefix="/api/v1", tags=["api"])


# ------------------------------------------------------------------ helpers
def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def _playbook_out(pb: Playbook) -> dict:
    return {
        "id": pb.id, "key": pb.key, "name": pb.name, "version": pb.version,
        "description": pb.description, "risk": pb.risk, "status": pb.status,
        "trigger": pb.trigger, "spec": pb.spec, "compensations": pb.compensations,
        "created_at": pb.created_at.isoformat() if pb.created_at else None,
        "published_at": pb.published_at.isoformat() if pb.published_at else None,
    }


def _alert_out(a: Alert) -> dict:
    return {
        "id": a.id, "external_id": a.external_id, "source": a.source, "category": a.category,
        "title": a.title, "description": a.description, "severity": a.severity, "score": a.score,
        "asset_id": a.asset_id, "attack_tactic": a.attack_tactic, "attack_technique": a.attack_technique,
        "indicators": a.indicators, "status": a.status, "case_id": a.case_id,
        "is_duplicate_of": a.is_duplicate_of, "redacted": a.redacted,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }


def _case_out(c: Case) -> dict:
    return {
        "id": c.id, "title": c.title, "severity": c.severity, "status": c.status,
        "nist_phase": c.nist_phase, "assigned_to": c.assigned_to, "sla_breached": c.sla_breached,
        "opened_at": c.opened_at.isoformat() if c.opened_at else None,
        "closed_at": c.closed_at.isoformat() if c.closed_at else None,
        "contained_at": c.contained_at.isoformat() if c.contained_at else None,
        "lessons": c.lessons,
    }


# ------------------------------------------------------------------ ingestion

class IngestAlertRequest(BaseModel):
    source: str
    category: str = "unknown"
    subcategory: str | None = None
    title: str
    description: str | None = None
    severity: str = "unknown"
    severity_score: int | None = None
    external_id: str | None = None
    asset_id: str | None = None
    asset_criticality: str = "unknown"
    attack_tactic: str | None = None
    attack_technique: str | None = None
    indicators: list = []
    raw: dict = {}


@router.post("/ingest/alerts")
def ingest_alert(
    payload: IngestAlertRequest,
    request: Request,
    db: Session = Depends(db_session),
    user: User = Depends(require_perm("ingest")),
):
    """Receive an alert from SIEM/EDR/other. Validates HMAC signature if configured."""
    body = payload.model_dump()
    if settings.ingest_hmac_key:
        body_raw = json.dumps({k: v for k, v in body.items()}, sort_keys=True).encode("utf-8")
        provided = request.headers.get("X-Signature", "")
        expected = "sha256=" + hmac.new(settings.ingest_hmac_key.encode(), body_raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(provided, expected):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid HMAC signature")

    try:
        alert = ingestion.create_alert(db, body)
    except Exception as exc:
        dle = DeadLetter(source="ingest", payload=body, reason=str(exc))
        db.add(dle)
        db.commit()
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Alert rejected: {exc}")

    audit_svc.append_audit(db, action="alert.ingest", actor=user.username, resource_type="alert",
                           resource_id=alert.id, ip=_client_ip(request), detail={"duplicate": bool(alert.is_duplicate_of)})

    if alert.is_duplicate_of:
        return {"alert_id": alert.id, "duplicate_of": alert.is_duplicate_of, "matched_playbook": None}

    # Auto-open a case for non-suppressed alerts and look for a playbook.
    case = case_service.open_case_for_alert(db, alert, user="ingest")
    engine.advance_case_phase(db, case, "analysis")

    playbook = engine.select_playbook(db, alert)
    if playbook:
        run = engine.start_run(db, playbook, alert, case)
        audit_svc.append_audit(db, action="run.start", actor=user.username, resource_type="run",
                               resource_id=run.id, ip=_client_ip(request),
                               detail={"playbook": playbook.key, "case_id": case.id})
        return {"alert_id": alert.id, "case_id": case.id, "matched_playbook": playbook.key, "run_id": run.id}

    return {"alert_id": alert.id, "case_id": case.id, "matched_playbook": None}


class DeadLetterResend(BaseModel):
    ids: list[str] = []


@router.get("/ingest/dead-letters", dependencies=[Depends(require_perm("alerts.read"))])
def dead_letters(db: Session = Depends(db_session), limit: int = Query(50, le=500)):
    rows = db.query(DeadLetter).order_by(desc(DeadLetter.created_at)).limit(limit).all()
    return [{"id": r.id, "source": r.source, "reason": r.reason, "payload": r.payload,
             "created_at": r.created_at.isoformat() if r.created_at else None} for r in rows]


# ------------------------------------------------------------------ alerts

@router.get("/alerts", dependencies=[Depends(require_perm("alerts.read"))])
def list_alerts(db: Session = Depends(db_session), limit: int = Query(50, le=200),
                source: str | None = None, category: str | None = None, status_: str | None = Query(None, alias="status")):
    q = db.query(Alert)
    if source:
        q = q.filter(Alert.source == source)
    if category:
        q = q.filter(Alert.category == category)
    if status_:
        q = q.filter(Alert.status == status_)
    rows = q.order_by(desc(Alert.created_at)).limit(limit).all()
    return [_alert_out(a) for a in rows]


@router.get("/alerts/{alert_id}", dependencies=[Depends(require_perm("alerts.read"))])
def get_alert(alert_id: str, db: Session = Depends(db_session)):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="alert not found")
    out = _alert_out(alert)
    out["raw"] = alert.raw_json
    return out


# ------------------------------------------------------------------ cases

@router.get("/cases", dependencies=[Depends(require_perm("cases.read"))])
def list_cases(db: Session = Depends(db_session), limit: int = Query(100, le=500),
               status_: str | None = Query(None, alias="status")):
    q = db.query(Case)
    if status_:
        q = q.filter(Case.status == status_)
    rows = q.order_by(desc(Case.updated_at)).limit(limit).all()
    return [_case_out(c) for c in rows]


@router.get("/cases/{case_id}", dependencies=[Depends(require_perm("cases.read"))])
def get_case(case_id: int, db: Session = Depends(db_session)):
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="case not found")
    result = _case_out(case)
    result["alerts"] = [_alert_out(a) for a in case.alerts]
    result["timeline"] = [
        {"ts": t.ts.isoformat() if t.ts else None, "actor": t.actor, "event_type": t.event_type,
         "message": t.message, "detail": t.detail}
        for t in case.timeline
    ]
    result["evidence"] = [
        {"id": e.id, "filename": e.filename, "sha256": e.sha256, "size": e.size,
         "collector": e.collector, "collected_at": e.collected_at.isoformat() if e.collected_at else None}
        for e in case.evidence
    ]
    runs = db.query(ExecutionRun).filter(ExecutionRun.case_id == case_id).order_by(desc(ExecutionRun.created_at)).all()
    result["runs"] = [
        {"id": r.id, "status": r.status, "playbook_id": r.playbook_id, "current_step": r.current_step_id,
         "created_at": r.created_at.isoformat() if r.created_at else None,
         "finished_at": r.finished_at.isoformat() if r.finished_at else None}
        for r in runs
    ]
    return result


class CaseUpdate(BaseModel):
    status: str | None = None
    nist_phase: str | None = None
    assigned_to: str | None = None
    lessons: str | None = None


@router.patch("/cases/{case_id}")
def update_case(case_id: int, payload: CaseUpdate, request: Request, db: Session = Depends(db_session),
                user: User = Depends(require_perm("cases.write"))):
    validate_csrf_or_bearer(request)
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="case not found")
    changed = []
    if payload.status is not None:
        case.status = payload.status
        case_service.add_timeline(db, case_id, actor=user.username, event_type="status",
                                  message=f"Status → {payload.status}")
        changed.append("status")
    if payload.nist_phase is not None:
        if case_service.advance_case_phase(db, case, payload.nist_phase):
            changed.append("nist_phase")
    if payload.assigned_to is not None:
        case.assigned_to = payload.assigned_to
        changed.append("assigned_to")
    if payload.lessons is not None:
        case.lessons = payload.lessons
        changed.append("lessons")
        case.status = "closed"
        case.closed_at = dt.datetime.utcnow()
        case_service.add_timeline(db, case_id, actor=user.username, event_type="closure",
                                  message="Case closed with lessons learned", detail={"lessons": payload.lessons})
    db.commit()
    audit_svc.append_audit(db, action="case.update", actor=user.username, resource_type="case",
                           resource_id=str(case_id), ip=_client_ip(request), detail={"changed": changed})
    return _case_out(case)


def validate_csrf_or_bearer(request: Request):
    """Browsers send CSRF cookie; API clients send Bearer tokens only."""
    if request.cookies.get("csrf_token"):
        from app.core.security import validate_csrf

        validate_csrf(request)


class TimelinePost(BaseModel):
    message: str
    event_type: str = "analyst_note"


@router.post("/cases/{case_id}/timeline")
def add_case_note(case_id: int, payload: TimelinePost, request: Request, db: Session = Depends(db_session),
                  user: User = Depends(require_perm("cases.comment"))):
    validate_csrf_or_bearer(request)
    if not db.get(Case, case_id):
        raise HTTPException(status_code=404, detail="case not found")
    entry = case_service.add_timeline(db, case_id, actor=user.username, event_type=payload.event_type,
                                      message=payload.message[:2000])
    audit_svc.append_audit(db, action="case.comment", actor=user.username, resource_type="case",
                           resource_id=str(case_id), ip=_client_ip(request))
    return {"timeline_id": entry.id}


@router.post("/cases/{case_id}/evidence")
def upload_evidence(case_id: int, request: Request, file: UploadFile = File(...),
                    db: Session = Depends(db_session), user: User = Depends(require_perm("evidence.create"))):
    validate_csrf_or_bearer(request)
    content = file.file.read()
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="evidence file too large (max 5MB)")
    ev = case_service.add_evidence(db, case_id, filename=file.filename or "evidence.bin",
                                   content=content, collector=user.username)
    audit_svc.append_audit(db, action="evidence.create", actor=user.username, resource_type="evidence",
                           resource_id=str(ev.id), ip=_client_ip(request), detail={"sha256": ev.sha256})
    return {"evidence_id": ev.id, "sha256": ev.sha256}


# ------------------------------------------------------------------ playbooks

class PlaybookCreate(BaseModel):
    document: str  # YAML or JSON


@router.get("/playbooks", dependencies=[Depends(require_perm("playbooks.read"))])
def list_playbooks(db: Session = Depends(db_session)):
    rows = db.query(Playbook).order_by(asc(Playbook.key), desc(Playbook.version)).all()
    return [_playbook_out(p) for p in rows]


@router.get("/playbooks/{playbook_id}", dependencies=[Depends(require_perm("playbooks.read"))])
def get_playbook(playbook_id: str, db: Session = Depends(db_session)):
    pb = db.get(Playbook, playbook_id)
    if not pb:
        raise HTTPException(status_code=404, detail="playbook not found")
    return _playbook_out(pb)


@router.post("/playbooks/validate")
def validate_playbook(payload: PlaybookCreate, user: User = Depends(require_perm("playbooks.write"))):
    """Parse + validate a playbook document without persisting. Safe to use unsaved."""
    try:
        doc = parse_playbook_document(payload.document)
        validate_playbook_document(doc)
    except PlaybookValidationError as exc:
        return {"valid": False, "errors": exc.messages}
    return {"valid": True, "errors": [], "digest": hashlib.sha256(payload.document.encode("utf-8")).hexdigest()}


@router.post("/playbooks", status_code=201)
def create_playbook(payload: PlaybookCreate, request: Request, db: Session = Depends(db_session),
                    user: User = Depends(require_perm("playbooks.write"))):
    validate_csrf_or_bearer(request)
    try:
        doc = parse_playbook_document(payload.document)
        validate_playbook_document(doc)
    except PlaybookValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    norm = normalize_document(doc)

    latest = db.query(Playbook).filter(Playbook.key == norm["key"]).order_by(desc(Playbook.version)).first()
    new_version = (latest.version + 1) if latest else 1
    pb = Playbook(
        key=norm["key"], name=norm["name"], description=norm["description"],
        trigger=norm["trigger"], spec=norm["spec"], compensations=norm["compensations"],
        risk=norm["risk"], version=new_version, status="draft",
        created_by=user.id, previous_id=latest.id if latest else None,
    )
    db.add(pb)
    db.commit()
    audit_svc.append_audit(db, action="playbook.create", actor=user.username, resource_type="playbook",
                           resource_id=pb.id, ip=_client_ip(request), detail={"key": pb.key, "version": pb.version})
    return _playbook_out(pb)


@router.post("/playbooks/{playbook_id}/publish")
def publish_playbook(playbook_id: str, request: Request, db: Session = Depends(db_session),
                     user: User = Depends(require_perm("playbooks.publish"))):
    validate_csrf_or_bearer(request)
    pb = db.get(Playbook, playbook_id)
    if not pb:
        raise HTTPException(status_code=404, detail="playbook not found")
    if pb.status == "published":
        raise HTTPException(status_code=409, detail="playbook already published (version immutable)")
    pb.status = "published"
    pb.published_at = dt.datetime.utcnow()
    db.commit()
    audit_svc.append_audit(db, action="playbook.publish", actor=user.username, resource_type="playbook",
                           resource_id=pb.id, ip=_client_ip(request), detail={"key": pb.key, "version": pb.version})
    return _playbook_out(pb)


@router.post("/playbooks/{playbook_id}/archive")
def archive_playbook(playbook_id: str, request: Request, db: Session = Depends(db_session),
                     user: User = Depends(require_perm("playbooks.write"))):
    validate_csrf_or_bearer(request)
    pb = db.get(Playbook, playbook_id)
    if not pb:
        raise HTTPException(status_code=404, detail="playbook not found")
    pb.status = "archived"
    db.commit()
    audit_svc.append_audit(db, action="playbook.archive", actor=user.username, resource_type="playbook",
                           resource_id=pb.id, ip=_client_ip(request))
    return _playbook_out(pb)


# ------------------------------------------------------------------ runs

@router.get("/runs/{run_id}", dependencies=[Depends(require_perm("runs.read"))])
def get_run(run_id: str, db: Session = Depends(db_session)):
    run = db.get(ExecutionRun, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    return {
        "id": run.id, "case_id": run.case_id, "status": run.status, "trigger_summary": run.trigger_summary,
        "playbook_id": run.playbook_id, "current_step": run.current_step_id,
        "created_at": run.created_at.isoformat() if run.created_at else None,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "data": run.data,
        "steps": [
            {"id": s.id, "step_id": s.step_id, "type": s.step_type, "action": s.action,
             "status": s.status, "retries_done": s.retries_done, "max_retries": s.max_retries,
             "message": s.message, "result": s.result,
             "started_at": s.started_at.isoformat() if s.started_at else None,
             "finished_at": s.finished_at.isoformat() if s.finished_at else None}
            for s in run.steps
        ],
    }


@router.post("/runs/{run_id}/cancel")
def cancel_run(run_id: str, request: Request, db: Session = Depends(db_session),
               user: User = Depends(require_perm("runs.cancel"))):
    validate_csrf_or_bearer(request)
    run = engine.cancel_run(db, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    audit_svc.append_audit(db, action="run.cancel", actor=user.username, resource_type="run", resource_id=run_id,
                           ip=_client_ip(request))
    return {"run_id": run.id, "status": run.status}


@router.post("/alerts/{alert_id}/replay")
def replay_for_alert(alert_id: str, request: Request, db: Session = Depends(db_session),
                     user: User = Depends(require_perm("replay"))):
    """Re-run playbook matching for an existing alert (creates new run)."""
    validate_csrf_or_bearer(request)
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="alert not found")
    playbook = engine.select_playbook(db, alert)
    if not playbook:
        raise HTTPException(status_code=404, detail="no matching playbook")
    case = db.get(Case, alert.case_id) if alert.case_id else None
    if not case:
        case = case_service.open_case_for_alert(db, alert, user="replay")
    run = engine.start_run(db, playbook, alert, case)
    audit_svc.append_audit(db, action="run.replay", actor=user.username, resource_type="run", resource_id=run.id,
                           ip=_client_ip(request), detail={"alert_id": alert_id})
    return {"run_id": run.id, "status": run.status}


# ------------------------------------------------------------------ approvals

class ApprovalDecision(BaseModel):
    approve: bool
    note: str | None = None


@router.get("/approvals", dependencies=[Depends(require_perm("approvals.read"))])
def list_approvals(db: Session = Depends(db_session), pending_only: bool = True):
    q = db.query(ApprovalRequest)
    if pending_only:
        q = q.filter(ApprovalRequest.status == "pending")
    rows = q.order_by(desc(ApprovalRequest.created_at)).limit(100).all()
    out = []
    for a in rows:
        run = db.get(ExecutionRun, a.run_id)
        out.append({
            "id": a.id, "run_id": a.run_id, "step_id": a.step_id, "case_id": a.case_id,
            "reason": a.reason, "status": a.status, "requested_by": a.requested_by,
            "decision_note": a.decision_note,
            "playbook": run.trigger_summary if run else None,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        })
    return out


@router.post("/approvals/{approval_id}/decide")
def decide_approval(approval_id: int, payload: ApprovalDecision, request: Request,
                    db: Session = Depends(db_session), user: User = Depends(require_perm("approvals.decide"))):
    validate_csrf_or_bearer(request)
    approval = db.get(ApprovalRequest, approval_id)
    if not approval:
        raise HTTPException(status_code=404, detail="approval not found")
    if approval.status != "pending":
        raise HTTPException(status_code=409, detail="approval already decided")
    approval.status = "approved" if payload.approve else "denied"
    approval.decided_by = user.id
    approval.decision_note = payload.note
    approval.decided_at = dt.datetime.utcnow()

    step = db.query(StepRun).filter_by(run_id=approval.run_id, step_id=approval.step_id).first()
    if step:
        step.status = "approved" if payload.approve else "skipped"
        step.message = f"decision by {user.username}: {payload.note or ('approved' if payload.approve else 'denied')}"
    db.commit()
    audit_svc.append_audit(db, action="approval.decide", actor=user.username, resource_type="approval",
                           resource_id=str(approval_id), ip=_client_ip(request),
                           detail={"approve": payload.approve, "run_id": approval.run_id})
    return {"approval_id": approval.id, "status": approval.status}


# ------------------------------------------------------------------ connectors

class ConnectorPayload(BaseModel):
    name: str
    conn_type: str = "generic_http"
    base_url: str = ""
    auth_type: str = "none"
    auth_secret_name: str | None = None  # create/update vault secret
    allowed_hosts: list[str] = []
    enabled: bool = True
    description: str = ""


@router.get("/connectors", dependencies=[Depends(require_perm("connectors.manage"))])
def list_connectors(db: Session = Depends(db_session)):
    out = []
    for c in db.query(Connector).order_by(asc(Connector.name)).all():
        out.append({
            "id": c.id, "name": c.name, "conn_type": c.conn_type, "base_url": c.base_url,
            "auth_type": c.auth_type, "has_secret": bool(c.auth_secret_ref),
            "allowed_hosts": c.allowed_hosts, "enabled": c.enabled, "description": c.extra.get("description"),
        })
    return out


@router.post("/connectors", status_code=201)
def create_connector(payload: ConnectorPayload, request: Request, db: Session = Depends(db_session),
                     user: User = Depends(require_perm("connectors.manage"))):
    validate_csrf_or_bearer(request)
    existing = db.query(Connector).filter(Connector.name == payload.name).first()
    if existing:
        raise HTTPException(status_code=409, detail="connector name already exists")
    secret_ref = ""
    if payload.auth_secret_name:
        secret_ref = _store_secret(db, payload.auth_secret_name, "placeholder", "update")
    conn = Connector(
        name=payload.name, conn_type=payload.conn_type, base_url=payload.base_url,
        auth_type=payload.auth_type, auth_secret_ref=secret_ref,
        allowed_hosts=payload.allowed_hosts, extra={"description": payload.description},
        enabled=payload.enabled,
    )
    db.add(conn)
    db.commit()
    audit_svc.append_audit(db, action="connector.create", actor=user.username, resource_type="connector",
                           resource_id=conn.id, ip=_client_ip(request))
    return {"id": conn.id, "name": conn.name}


def _store_secret(db: Session, name: str, value: str, purpose: str) -> str:
    """Create/overwrite a vault secret with the encrypted value."""
    from app.core import cipher as vault

    key_id, ct = vault.encrypt_secret(value)
    row = db.query(SecretVault).filter(SecretVault.name == name).first()
    if row:
        row.ciphertext = ct
        row.key_id = key_id
    else:
        row = SecretVault(name=name, ciphertext=ct, key_id=key_id)
        db.add(row)
    db.commit()
    return f"vault:{name}"


@router.patch("/connectors/{connector_id}")
def update_connector(connector_id: str, payload: ConnectorPayload, request: Request,
                     db: Session = Depends(db_session), user: User = Depends(require_perm("connectors.manage"))):
    validate_csrf_or_bearer(request)
    conn = db.get(Connector, connector_id)
    if not conn:
        raise HTTPException(status_code=404, detail="connector not found")
    conn.base_url = payload.base_url
    conn.conn_type = payload.conn_type
    conn.auth_type = payload.auth_type
    conn.allowed_hosts = payload.allowed_hosts
    conn.enabled = payload.enabled
    conn.extra = {"description": payload.description}
    if payload.auth_secret_name:
        conn.auth_secret_ref = _store_secret(db, payload.auth_secret_name, "placeholder", "update")
    db.commit()
    audit_svc.append_audit(db, action="connector.update", actor=user.username, resource_type="connector",
                           resource_id=connector_id, ip=_client_ip(request))
    return {"id": conn.id, "name": conn.name}


@router.post("/connectors/{connector_id}/test")
def test_connector(connector_id: str, request: Request, db: Session = Depends(db_session),
                   user: User = Depends(require_perm("connectors.manage"))):
    validate_csrf_or_bearer(request)
    conn = db.get(Connector, connector_id)
    if not conn:
        raise HTTPException(status_code=404, detail="connector not found")
    try:
        result = connector_runtime.execute_action(db, conn, "ping", {"message": "soarlite test"})
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": bool(result.get("ok")), "result": result}


@router.post("/secrets", status_code=201)
def store_secret(name: str, value: str, request: Request, db: Session = Depends(db_session),
                 user: User = Depends(require_perm("connectors.manage"))):
    validate_csrf_or_bearer(request)
    sec_ref = _store_secret(db, name, value, "manual")
    audit_svc.append_audit(db, action="secret.store", actor=user.username, resource_type="secret",
                           resource_id=name, ip=_client_ip(request))
    return {"name": name, "stored": True}


# ------------------------------------------------------------------ users / access

class UserPayload(BaseModel):
    username: str
    email: str = ""
    role: str = "viewer"
    password: str | None = None
    is_active: bool = True


@router.get("/users", dependencies=[Depends(require_perm("users.manage"))])
def list_users(db: Session = Depends(db_session)):
    out = []
    for u in db.query(User).order_by(asc(User.username)).all():
        out.append({
            "id": u.id, "username": u.username, "email": u.email, "role": u.role,
            "is_active": u.is_active, "must_change_password": u.must_change_password,
            "last_login": u.last_login.isoformat() if u.last_login else None,
        })
    return out


@router.post("/users", status_code=201)
def create_user(payload: UserPayload, request: Request, db: Session = Depends(db_session),
                user: User = Depends(require_perm("users.manage"))):
    validate_csrf_or_bearer(request)
    if payload.role not in ("viewer", "analyst", "approver", "author", "admin", "automation"):
        raise HTTPException(status_code=422, detail="invalid role")
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=409, detail="username exists")
    from app.core.security import hash_password

    u = User(
        username=payload.username, email=payload.email, role=payload.role,
        password_hash=hash_password(payload.password or "ChangeMe!Temp0"), is_active=payload.is_active,
        must_change_password=True,
    )
    db.add(u)
    db.commit()
    audit_svc.append_audit(db, action="user.create", actor=user.username, resource_type="user",
                           resource_id=u.id, ip=_client_ip(request), detail={"role": payload.role})
    return {"id": u.id, "username": u.username}


# ------------------------------------------------------------------ audit

@router.get("/audit", dependencies=[Depends(require_perm("audit.read"))])
def list_audit(db: Session = Depends(db_session), limit: int = Query(200, le=1000), actor: str | None = None):
    q = db.query(AuditEvent)
    if actor:
        q = q.filter(AuditEvent.actor == actor)
    rows = q.order_by(desc(AuditEvent.seq)).limit(limit).all()
    return [
        {"seq": e.seq, "ts": e.ts.isoformat() if e.ts else None, "actor": e.actor, "action": e.action,
         "resource_type": e.resource_type, "resource_id": e.resource_id, "ip": e.ip,
         "detail": e.detail, "hash": e.hash, "prev_hash": e.prev_hash}
        for e in rows
    ]


@router.get("/audit/verify", dependencies=[Depends(require_perm("audit.verify"))])
def verify_audit_chain(db: Session = Depends(db_session)):
    ok, checked, first_broken = audit_svc.verify_chain(db)
    return {"chain_valid": ok, "checked": checked, "first_broken_id": first_broken}


# ------------------------------------------------------------------ reports / kpis

@router.get("/reports/kpis", dependencies=[Depends(require_perm("reports.read"))])
def kpis(db: Session = Depends(db_session)):
    now = dt.datetime.utcnow()
    day_ago = now - dt.timedelta(hours=24)
    week_ago = now - dt.timedelta(days=7)

    def count(model, since=None, filters=()):
        q = db.query(func.count(model.id))
        for f in filters:
            q = q.filter(f)
        if since is not None:
            q = q.filter(model.created_at >= since)
        return q.scalar() or 0

    open_cases = count(Case, filters=[Case.status != "closed"])
    alerts_24 = count(Alert, since=day_ago)
    alerts_7d = count(Alert, since=week_ago)
    total_runs = count(ExecutionRun)
    succeeded = count(ExecutionRun, filters=[ExecutionRun.status == "succeeded"])
    failed = count(ExecutionRun, filters=[ExecutionRun.status.in_(["failed", "compensated"])])
    awaiting = count(ExecutionRun, filters=[ExecutionRun.status == "awaiting_approval"])
    pending_approvals = db.query(func.count(ApprovalRequest.id)).filter(ApprovalRequest.status == "pending").scalar() or 0
    dlq = count(DeadLetter)
    sla_breaches = count(Case, filters=[Case.sla_breached.is_(True)])

    # response time: avg minutes between case open and first containment
    mttc = db.query(func.avg(func.julianday(Case.contained_at) - func.julianday(Case.opened_at))).filter(
        Case.contained_at.isnot(None)).scalar()
    mttc = (mttc * 24 * 60) if mttc else 0

    return {
        "open_cases": open_cases, "alerts_24h": alerts_24, "alerts_7d": alerts_7d,
        "total_runs": total_runs, "succeeded": succeeded, "failed": failed, "awaiting": awaiting,
        "success_rate": round((succeeded / total_runs * 100), 1) if total_runs else 0.0,
        "pending_approvals": pending_approvals, "dlq_count": dlq, "sla_breaches": sla_breaches,
        "mttc_minutes": round(mttc, 1),
    }


@router.get("/reports/top-alerts", dependencies=[Depends(require_perm("reports.read"))])
def top_alerts(db: Session = Depends(db_session), limit: int = Query(10, le=50)):
    rows = db.query(Alert.source, func.count(Alert.id).label("n")).group_by(Alert.source).order_by(desc("n")).limit(limit).all()
    return [{"source": r.source, "count": r.n} for r in rows]


# ------------------------------------------------------------------ settings

@router.get("/settings")
def get_settings_endpoint(db: Session = Depends(db_session), user: User = Depends(require_perm("settings.manage"))):
    rows = db.query(Setting).all()
    return {r.key: r.value for r in rows}


@router.put("/settings/{key}")
def set_setting(key: str, value: dict, request: Request, db: Session = Depends(db_session),
                user: User = Depends(require_perm("settings.manage"))):
    validate_csrf_or_bearer(request)
    row = db.get(Setting, key)
    if row:
        row.value = value
    else:
        row = Setting(key=key, value=value)
        db.add(row)
    db.commit()
    audit_svc.append_audit(db, action="settings.update", actor=user.username, resource_type="setting",
                           resource_id=key, ip=_client_ip(request))
    return {"key": key, "value": value}