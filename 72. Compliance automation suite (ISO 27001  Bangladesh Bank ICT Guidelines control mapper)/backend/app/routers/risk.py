"""Risk register & remediation endpoints."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..database import naive_utcnow

from ..database import get_db
from ..engines.risk import auto_escalate, risk_register_summary, sla_metrics, score_risk
from ..models import Control, RemediationTicket, RiskPoint, User
from ..security import audit, client_ip, require

router = APIRouter(prefix="/risk", tags=["risk"])


@router.get("")
def register(db: Session = Depends(get_db), _: User = Depends(require("dashboard:read"))):
    return risk_register_summary(db)


@router.post("")
def create_risk(payload: dict, request: Request, db: Session = Depends(get_db),
                user: User = Depends(require("risk:write"))):
    control = db.query(Control).filter(Control.id == payload.get("control_id")).first()
    risk = RiskPoint(
        control_id=payload.get("control_id"),
        asset_id=payload.get("asset_id"),
        title=payload.get("title", control.title if control else "Risk"),
        likelihood=float(payload.get("likelihood", 3)),
        impact=float(payload.get("impact", 3)),
        cvss=float(payload.get("cvss", 0)),
        tier=payload.get("tier", "MEDIUM"),
        status="OPEN",
    )
    db.add(risk)
    db.commit()
    db.refresh(risk)
    audit(db, user.username, user.role, "RISK_CREATE", "RISK_POINT", risk.id,
          {"title": risk.title, "tier": risk.tier}, client_ip(request))
    return {"id": risk.id, "tier": risk.tier, "raw_score": risk.raw_score}


@router.post("/{risk_id}/score")
def update_score(risk_id: int, payload: dict, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require("risk:write"))):
    scored = score_risk(db, risk_id, payload.get("likelihood", 3),
                        payload.get("impact", 3), payload.get("cvss", 0))
    audit(db, user.username, user.role, "RISK_RESCORE", "RISK_POINT", risk_id,
          {"tier": scored.tier, "raw": scored.raw_score}, client_ip(request))
    return {"id": scored.id, "tier": scored.tier, "raw_score": scored.raw_score,
            "residual_score": scored.residual_score}


@router.post("/escalate")
def escalate(request: Request, db: Session = Depends(get_db),
             user: User = Depends(require("risk:write"))):
    created = auto_escalate(db)
    audit(db, user.username, user.role, "RISK_ESCALATION", "REMEDIATION_TICKET", None,
          {"tickets_created": len(created)}, client_ip(request))
    return {"tickets_created": created}


@router.get("/tickets")
def tickets(db: Session = Depends(get_db), _: User = Depends(require("dashboard:read"))):
    rows = []
    for t in db.query(RemediationTicket).order_by(RemediationTicket.id.desc()).all():
        rows.append({
            "id": t.id, "title": t.title, "priority": t.priority, "status": t.status,
            "sla_hours": t.sla_hours, "due_at": t.due_at.isoformat() if t.due_at else None,
            "assignee": t.assignee.username if t.assignee else None,
            "external_ticket": t.external_ticket, "risk_id": t.risk_id,
            "created_at": t.created_at.isoformat(),
            "resolved_at": t.resolved_at.isoformat() if t.resolved_at else None,
        })
    return rows


@router.post("/tickets/{ticket_id}/status")
def ticket_status(ticket_id: int, payload: dict, request: Request, db: Session = Depends(get_db),
                  user: User = Depends(require("remediation:write"))):
    t = db.query(RemediationTicket).filter(RemediationTicket.id == ticket_id).first()
    if not t:
        return {"error": "not found"}
    t.status = payload["status"]
    if payload["status"] == "RESOLVED":
        t.resolved_at = naive_utcnow()
    if payload.get("external_ticket"):
        t.external_ticket = payload["external_ticket"]
    db.commit()
    audit(db, user.username, user.role, "TICKET_STATUS", "REMEDIATION_TICKET", t.id,
          {"status": t.status}, client_ip(request))
    return {"id": t.id, "status": t.status}


@router.get("/sla")
def sla(db: Session = Depends(get_db), _: User = Depends(require("dashboard:read"))):
    return sla_metrics(db)