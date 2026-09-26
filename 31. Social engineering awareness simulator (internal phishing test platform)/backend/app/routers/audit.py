from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models, schemas
from ..db import get_db
from ..deps import require_roles

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])

ALLOWED = ("admin", "security", "auditor")


@router.get("", response_model=list[schemas.AuditLogOut])
def list_audit(
    limit: int = 200,
    action: str | None = None,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles(*ALLOWED)),
) -> list[models.AuditLog]:
    query = select(models.AuditLog).order_by(models.AuditLog.id.desc())
    if action:
        query = query.where(models.AuditLog.action == action)
    query = query.limit(min(limit, 1000))
    return db.scalars(query).all()