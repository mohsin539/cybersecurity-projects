import json

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models
from ..security import audit_hash


class AuditService:
    def __init__(self, db: Session, actor: str, ip: str = "unknown"):
        self.db = db
        self.actor = actor
        self.ip = ip

    def _last_hash(self) -> str:
        row = self.db.execute(
            select(models.AuditLog).order_by(models.AuditLog.id.desc()).limit(1)
        ).scalars().first()
        return row.hash if row else "GENESIS"

    def log(
        self,
        action: str,
        target_type: str = "",
        target_id: int | None = None,
        detail: str = "",
    ) -> models.AuditLog:
        payload = json.dumps(
            {
                "actor": self.actor,
                "action": action,
                "target_type": target_type,
                "target_id": target_id,
                "detail": detail,
                "ip": self.ip,
            },
            sort_keys=True,
        )
        prev = self._last_hash()
        entry = models.AuditLog(
            actor=self.actor,
            action=action,
            target_type=target_type,
            target_id=target_id,
            detail=detail,
            ip=self.ip,
            prev_hash=prev,
            hash=audit_hash(prev, payload),
        )
        self.db.add(entry)
        return entry