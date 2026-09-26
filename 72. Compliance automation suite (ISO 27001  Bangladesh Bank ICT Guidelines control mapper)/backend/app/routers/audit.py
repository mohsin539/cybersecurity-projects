"""Audit trail endpoints — tamper-evident log queries + chain verification."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from ..engines.evidence import audit_chain_verify
from ..models import AuditLog, User
from ..security import require

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
def audit_logs(limit: int = 200, actor: str = None, action: str = None,
               db: Session = Depends(get_db), _: User = Depends(require("audit:read"))):
    q = db.query(AuditLog).order_by(AuditLog.id.desc())
    if actor:
        q = q.filter(AuditLog.actor == actor)
    if action:
        q = q.filter(AuditLog.action == action)
    rows = q.limit(min(limit, 500)).all()
    return [{
        "id": r.id, "actor": r.actor, "actor_role": r.actor_role, "action": r.action,
        "entity_type": r.entity_type, "entity_id": r.entity_id, "detail": r.detail,
        "ip_address": r.ip_address, "row_hash": r.row_hash, "prev_hash": r.prev_hash,
        "created_at": r.created_at.isoformat(),
    } for r in rows]


@router.get("/verify")
def verify(db: Session = Depends(get_db), _: User = Depends(require("audit:read"))):
    return audit_chain_verify(db)