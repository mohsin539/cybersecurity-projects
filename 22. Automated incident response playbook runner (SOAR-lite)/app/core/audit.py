"""Immutable, hash-chained audit logging (tamper-evident WORM-style record).

Each event links to the previous event via a SHA-256 digest. Rotation of any
row breaks the chain and is detectable via `verify_chain()`.

ISO 27001 Annex A.12.4 / A.16, NIST SP 800-53 AU-3..AU-11.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.db.models import AuditEvent


def _canonical(event_fields: dict, prev_hash: str | None) -> str:
    blob = {
        "ts": (event_fields.get("ts") or dt.datetime.utcnow()).isoformat(),
        "actor": event_fields.get("actor"),
        "action": event_fields.get("action"),
        "resource_type": event_fields.get("resource_type"),
        "resource_id": event_fields.get("resource_id"),
        "ip": event_fields.get("ip"),
        "detail": event_fields.get("detail") or {},
        "prev_hash": prev_hash,
    }
    return hashlib.sha256(json.dumps(blob, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def append_audit(
    db: Session,
    *,
    action: str,
    actor: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    ip: str | None = None,
    detail: dict | None = None,
) -> AuditEvent:
    last = db.execute(
        select(AuditEvent).order_by(desc(AuditEvent.seq)).limit(1)
    ).scalar_one_or_none()
    prev_hash = last.hash if last else None
    seq = (last.seq + 1) if last else 1

    event = AuditEvent(
        seq=seq,
        actor=actor,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        ip=ip,
        detail=detail or {},
        prev_hash=prev_hash,
    )
    event.hash = _canonical(
        {"ts": event.ts, "actor": actor, "action": action, "resource_type": event.resource_type,
         "resource_id": event.resource_id, "ip": ip, "detail": detail or {}},
        prev_hash,
    )
    db.add(event)
    return event


def verify_chain(db: Session) -> tuple[bool, int, str]:
    """Recomputed hash chain; returns (ok, checked_count, first_broken_id)."""
    rows = db.execute(select(AuditEvent).order_by(AuditEvent.seq)).scalars().all()
    prev: str | None = None
    for row in rows:
        recomputed = _canonical(
            {"ts": row.ts, "actor": row.actor, "action": row.action, "resource_type": row.resource_type,
             "resource_id": row.resource_id, "ip": row.ip, "detail": row.detail},
            prev,
        )
        if recomputed != row.hash:
            return False, len(rows), row.id
        prev = row.hash
    return True, len(rows), ""