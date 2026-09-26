"""Server-rendered web console (Jinja2 + minimal vanilla JS).

Each page is rendered only after authn/authz; data is read through the same
service layer as the REST API so business rules stay in one place.
"""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path
from sqlalchemy import asc, desc, func
from sqlalchemy.orm import Session

from app.core.security import get_current_user
from app.db.base import db_session
from app.db.models import (
    Alert,
    ApprovalRequest,
    AuditEvent,
    Case,
    Connector,
    DeadLetter,
    ExecutionRun,
    Playbook,
)
from app.db.models import (  # noqa: F401 (used by some pages)
    User,
)

router = APIRouter()


class Templates:
    _instance: Jinja2Templates | None = None

    @classmethod
    def get(cls):
        if cls._instance is None:
            from pathlib import Path

            cls._instance = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent.parent / "templates"))
        return cls._instance


templates = Templates.get()


def _ctx(request: Request, user: User, **extra):
    base = {
        "request": request,
        "user": user,
        "csrf_token": request.cookies.get("csrf_token", ""),
        "now": dt.datetime.utcnow(),
    }
    base.update(extra)
    return base


# ------------------------------------------------------------------ auth pages

@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, user: User | None = Depends(get_current_user)):
    if user:
        return templates.TemplateResponse(request, "redirect.html", {"target": "/", "notice": "already logged in"})
    return templates.TemplateResponse(request, "login.html", {"request": request, "csrf_token": request.cookies.get("csrf_token", "")})


# ------------------------------------------------------------------ core pages

@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(db_session), user: User = Depends(get_current_user)):
    now = dt.datetime.utcnow()
    day_ago = now - dt.timedelta(hours=24)
    week_ago = now - dt.timedelta(days=7)

    open_cases = db.query(func.count(Case.id)).filter(Case.status != "closed").scalar() or 0
    alerts_24h = db.query(func.count(Alert.id)).filter(Alert.created_at >= day_ago).scalar() or 0
    alerts_7d = db.query(func.count(Alert.id)).filter(Alert.created_at >= week_ago).scalar() or 0
    pending_approvals = db.query(func.count(ApprovalRequest.id)).filter(ApprovalRequest.status == "pending").scalar() or 0
    dlq = db.query(func.count(DeadLetter.id)).scalar() or 0
    runs = db.query(ExecutionRun).order_by(desc(ExecutionRun.created_at)).limit(10).all()
    recent_alerts = db.query(Alert).order_by(desc(Alert.created_at)).limit(10).all()
    sla = db.query(func.count(Case.id)).filter(Case.sla_breached.is_(True), Case.closed_at.is_(None)).scalar() or 0

    mttc = db.query(func.avg(func.julianday(Case.contained_at) - func.julianday(Case.opened_at))).filter(
        Case.contained_at.isnot(None)).scalar()
    mttc_min = round((mttc * 24 * 60), 1) if mttc else 0

    return templates.TemplateResponse(request, "dashboard.html", _ctx(
        request, user,
        open_cases=open_cases, alerts_24h=alerts_24h, alerts_7d=alerts_7d,
        pending_approvals=pending_approvals, dlq=dlq, runs=runs,
        recent_alerts=recent_alerts, sla=sla, mttc_min=mttc_min,
    ))


@router.get("/alerts", response_class=HTMLResponse)
def alerts_page(request: Request, db: Session = Depends(db_session), user: User = Depends(get_current_user)):
    rows = db.query(Alert).order_by(desc(Alert.created_at)).limit(150).all()
    return templates.TemplateResponse(request, "alerts.html", _ctx(request, user, alerts=rows))


@router.get("/alerts/{alert_id}", response_class=HTMLResponse)
def alert_detail(request: Request, alert_id: str, db: Session = Depends(db_session), user: User = Depends(get_current_user)):
    alert = db.get(Alert, alert_id)
    if not alert:
        return templates.TemplateResponse(request, "error.html", _ctx(request, user, code=404, message="alert not found"))
    return templates.TemplateResponse(request, "alert_detail.html", _ctx(request, user, alert=alert))


@router.get("/cases", response_class=HTMLResponse)
def cases_page(request: Request, db: Session = Depends(db_session), user: User = Depends(get_current_user)):
    rows = db.query(Case).order_by(desc(Case.updated_at)).limit(150).all()
    return templates.TemplateResponse(request, "cases.html", _ctx(request, user, cases=rows))


@router.get("/cases/{case_id}", response_class=HTMLResponse)
def case_detail(request: Request, case_id: int, db: Session = Depends(db_session), user: User = Depends(get_current_user)):
    case = db.get(Case, case_id)
    if not case:
        return templates.TemplateResponse(request, "error.html", _ctx(request, user, code=404, message="case not found"))
    runs = db.query(ExecutionRun).filter(ExecutionRun.case_id == case_id).order_by(desc(ExecutionRun.created_at)).all()
    return templates.TemplateResponse(request, "case_detail.html", _ctx(request, user, case=case, runs=runs))


@router.get("/playbooks", response_class=HTMLResponse)
def playbooks_page(request: Request, db: Session = Depends(db_session), user: User = Depends(get_current_user)):
    rows = db.query(Playbook).order_by(asc(Playbook.key), desc(Playbook.version)).all()
    return templates.TemplateResponse(request, "playbooks.html", _ctx(request, user, playbooks=rows))


@router.get("/playbooks/{playbook_id}", response_class=HTMLResponse)
def playbook_detail(request: Request, playbook_id: str, db: Session = Depends(db_session), user: User = Depends(get_current_user)):
    pb = db.get(Playbook, playbook_id)
    if not pb:
        return templates.TemplateResponse(request, "error.html", _ctx(request, user, code=404, message="playbook not found"))
    return templates.TemplateResponse(request, "playbook_detail.html", _ctx(request, user, playbook=pb))


@router.get("/playbooks/new", response_class=HTMLResponse)
def playbook_new(request: Request, db: Session = Depends(db_session), user: User = Depends(get_current_user)):
    with open(Path(__file__).resolve().parent.parent.parent / "templates" / "playbook_template.yaml", "r", encoding="utf-8") as fh:
        template = fh.read()
    return templates.TemplateResponse(request, "playbook_new.html", _ctx(request, user, template=template))


@router.get("/approvals", response_class=HTMLResponse)
def approvals_page(request: Request, db: Session = Depends(db_session), user: User = Depends(get_current_user)):
    rows = db.query(ApprovalRequest).order_by(desc(ApprovalRequest.created_at)).limit(100).all()
    return templates.TemplateResponse(request, "approvals.html", _ctx(request, user, approvals=rows))


@router.get("/runs/{run_id}", response_class=HTMLResponse)
def run_detail(request: Request, run_id: str, db: Session = Depends(db_session), user: User = Depends(get_current_user)):
    run = db.get(ExecutionRun, run_id)
    if not run:
        return templates.TemplateResponse(request, "error.html", _ctx(request, user, code=404, message="run not found"))
    pb = db.get(Playbook, run.playbook_id)
    return templates.TemplateResponse(request, "run_detail.html", _ctx(request, user, run=run, playbook=pb))


@router.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request, db: Session = Depends(db_session), user: User = Depends(get_current_user)):
    if user.role != "admin":
        from fastapi import HTTPException, status

        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin only")
    rows = db.query(AuditEvent).order_by(desc(AuditEvent.seq)).limit(300).all()
    return templates.TemplateResponse(request, "audit.html", _ctx(request, user, events=rows))


@router.get("/connectors", response_class=HTMLResponse)
def connectors_page(request: Request, db: Session = Depends(db_session), user: User = Depends(get_current_user)):
    if user.role != "admin":
        from fastapi import HTTPException, status

        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin only")
    rows = db.query(Connector).order_by(asc(Connector.name)).all()
    return templates.TemplateResponse(request, "connectors.html", _ctx(request, user, connectors=rows))


@router.get("/users", response_class=HTMLResponse)
def users_page(request: Request, db: Session = Depends(db_session), user: User = Depends(get_current_user)):
    if user.role != "admin":
        from fastapi import HTTPException, status

        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin only")
    rows = db.query(User).order_by(asc(User.username)).all()
    return templates.TemplateResponse(request, "users.html", _ctx(request, user, the_users=rows))


@router.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request, db: Session = Depends(db_session), user: User = Depends(get_current_user)):
    top = db.query(Alert.source, func.count(Alert.id).label("n")).group_by(Alert.source).order_by(desc("n")).limit(12).all()
    severity = db.query(Alert.severity, func.count(Alert.id).label("n")).group_by(Alert.severity).order_by(desc("n")).all()
    phase = db.query(Case.nist_phase, func.count(Case.id).label("n")).group_by(Case.nist_phase).all()
    runs = db.query(ExecutionRun.status, func.count(ExecutionRun.id).label("n")).group_by(ExecutionRun.status).all()
    return templates.TemplateResponse(request, "reports.html", _ctx(
        request, user, top=top, severity=severity, phase=phase, runs=runs,
    ))


@router.get("/healthz", response_class=HTMLResponse)
def healthz():
    return HTMLResponse("ok")


@router.get("/ingest-demo", response_class=HTMLResponse, include_in_schema=False)
def webhook_demo_page(request: Request, user: User = Depends(get_current_user)):
    return templates.TemplateResponse(request, "webhook_demo.html", _ctx(request, user))