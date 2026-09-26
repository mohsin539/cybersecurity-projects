"""Case management: incident records, immutable timeline, evidence custody.

NIST SP 800-61 lifecycle is tracked with `nist_phase`. Timeline events are
append-only and attributed; evidence is hashed (SHA-256) at collection time to
preserve chain of custody.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy.orm import Session

from app.db.models import Case, CaseTimeline, Evidence, NIST_PHASES


def phase_index(phase: str) -> int:
    return NIST_PHASES.index(phase) if phase in NIST_PHASES else 0


def advance_case_phase(db: Session, case: Case, new_phase: str) -> bool:
    if new_phase not in NIST_PHASES:
        return False
    if phase_index(new_phase) < phase_index(case.nist_phase):
        return False  # never go backwards automatically
    case.nist_phase = new_phase
    now = dt.datetime.utcnow()
    if new_phase == "containment" and case.contained_at is None:
        case.contained_at = now
    if new_phase == "eradication" and case.eradicated_at is None:
        case.eradicated_at = now
    if new_phase == "recovery" and case.recovered_at is None:
        case.recovered_at = now
    add_timeline(db, case.id, actor="system", event_type="nist_phase",
                 message=f"NIST phase transitioned to {new_phase}", detail={"phase": new_phase})
    return True


def add_timeline(db: Session, case_id: int, *, actor: str, event_type: str, message: str,
                 detail: dict | None = None) -> CaseTimeline:
    entry = CaseTimeline(case_id=case_id, actor=actor, event_type=event_type,
                         message=message, detail=detail or {})
    db.add(entry)
    db.commit()
    return entry


def add_evidence(db: Session, case_id: int, *, filename: str, content: bytes, collector: str, metadata: dict | None = None) -> Evidence:
    import hashlib
    import os

    from app.config import settings

    evidence_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "evidence")
    os.makedirs(evidence_dir, exist_ok=True)
    sha = hashlib.sha256(content).hexdigest()
    object_key = os.path.join(evidence_dir, f"case-{case_id}-{sha[:16]}-{os.path.basename(filename)}")
    with open(object_key, "wb") as fh:
        fh.write(content)

    ev = Evidence(
        case_id=case_id,
        filename=filename,
        object_key=object_key,
        size=len(content),
        sha256=sha,
        collector=collector,
        metadata=metadata or {},
    )
    db.add(ev)
    add_timeline(db, case_id, actor=collector, event_type="evidence",
                 message=f"Evidence collected: {filename} (sha256={sha[:12]}…)", detail={"sha256": sha, "size": len(content)})
    return ev


def check_sla(db: Session, case: Case, initial_response_minutes: int = 15, containment_minutes: int = 60) -> None:
    """Flag SLA breaches for open cases (escalation signal, not enforcement)."""
    now = dt.datetime.utcnow()
    if case.closed_at:
        return
    if case.nist_phase == "detection" and case.opened_at and (now - case.opened_at).total_seconds() / 60 > initial_response_minutes:
        _mark_sla(db, case, "initial response exceeded 15m")
    if case.contained_at is None and case.opened_at and (now - case.opened_at).total_seconds() / 60 > containment_minutes:
        _mark_sla(db, case, "containment not achieved within 60m")


def _mark_sla(db: Session, case: Case, why: str):
    if not case.sla_breached:
        case.sla_breached = True
        add_timeline(db, case.id, actor="system", event_type="sla_breach", message=f"SLA breached: {why}")
    db.commit()