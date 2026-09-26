"""Assessment Engine — runs AUTO/HYBRID assessments across frameworks."""
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from ..database import naive_utcnow

from ..models import (
    Assessment, AssessmentDecision, Control, EvidenceLink, ScanResult, Framework,
)


def _auto_decide(control: Control, db: Session) -> str:
    """Heuristic AUTO decision driven by evidence links + open scanner findings."""
    has_evidence = db.query(EvidenceLink).filter(EvidenceLink.control_id == control.id).first() is not None
    open_critical = (
        db.query(ScanResult)
        .filter(ScanResult.status == "OPEN", ScanResult.severity.in_(["CRITICAL", "HIGH"]))
        .count()
    ) > 0
    if control.category in ("VULNERABILITY", "SECURE_CODING", "NETWORK") and open_critical:
        return "PARTIAL"
    return "COMPLIANT" if has_evidence else "NOT_ASSESSED"


def run_assessment(db: Session, name: str, framework_code: str, method: str,
                   scope: str, actor: str) -> Assessment:
    fw = db.query(Framework).filter(Framework.code == framework_code).first()
    if not fw:
        raise ValueError(f"Unknown framework {framework_code}")
    assessment = Assessment(
        name=name, framework_code=fw.code, method=method, scope=scope,
        status="IN_PROGRESS", created_by=actor,
    )
    db.add(assessment)
    db.commit()
    db.refresh(assessment)

    controls = db.query(Control).filter(Control.framework_id == fw.id).all()
    decided = 0
    for ctrl in controls:
        if method == "AUTO" or method == "HYBRID":
            status = _auto_decide(ctrl, db)
        else:
            status = "NOT_ASSESSED"
        decision = AssessmentDecision(
            assessment_id=assessment.id,
            control_id=ctrl.id,
            status=status,
            scored_by=actor,
            note="Auto-scored from scanner + evidence heuristics" if method in ("AUTO", "HYBRID") else "Awaiting human decision",
        )
        db.add(decision)
        if status not in ("NOT_APPLICABLE", "NOT_ASSESSED"):
            decided += 1
    db.commit()

    total = len(controls)
    assessment.progress = 100.0 if total else 0.0
    assessment.status = "COMPLETED"
    assessment.findings_count = db.query(AssessmentDecision).filter(
        AssessmentDecision.assessment_id == assessment.id,
        AssessmentDecision.status.in_(["NON_COMPLIANT", "PARTIAL"]),
    ).count()
    weight = {"COMPLIANT": 1.0, "PARTIAL": 0.5, "NON_COMPLIANT": 0.0}
    assessed = db.query(AssessmentDecision).filter(
        AssessmentDecision.assessment_id == assessment.id,
        AssessmentDecision.status.in_(["COMPLIANT", "PARTIAL", "NON_COMPLIANT"]),
    ).all()
    if assessed:
        score = sum(weight[d.status] for d in assessed) / len(assessed) * 100
        assessment.result_score = round(score, 1)
    assessment.completed_at = naive_utcnow()
    db.commit()
    db.refresh(assessment)
    return assessment


def update_decision(db: Session, assessment_id: int, control_id: int, status: str,
                    note: str, evidence_ref: str, actor: str) -> AssessmentDecision:
    decision = db.query(AssessmentDecision).filter(
        AssessmentDecision.assessment_id == assessment_id,
        AssessmentDecision.control_id == control_id,
    ).first()
    if not decision:
        raise ValueError("Decision not found")
    old = decision.status
    decision.status = status
    if note:
        decision.note = note
    if evidence_ref:
        decision.evidence_ref = evidence_ref
    decision.scored_by = actor
    db.commit()
    return decision


def assessment_detail(db: Session, assessment_id: int) -> dict:
    a = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not a:
        raise ValueError("Assessment not found")
    decisions = db.query(AssessmentDecision).filter(
        AssessmentDecision.assessment_id == assessment_id).all()
    rows = []
    for d in decisions:
        ctrl = db.query(Control).filter(Control.id == d.control_id).first()
        if not ctrl:
            continue
        evidence_count = db.query(EvidenceLink).filter(
            EvidenceLink.control_id == ctrl.id).count()
        rows.append({
            "control_id": ctrl.id, "code": ctrl.code, "title": ctrl.title,
            "category": ctrl.category, "decision": d.status, "note": d.note,
            "evidence_ref": d.evidence_ref, "evidence_count": evidence_count,
            "scored_by": d.scored_by, "decided_at": d.decided_at.isoformat(),
        })
    return {
        "id": a.id, "name": a.name, "framework_code": a.framework_code,
        "method": a.method, "scope": a.scope, "status": a.status,
        "progress": a.progress, "result_score": a.result_score,
        "findings_count": a.findings_count, "created_by": a.created_by,
        "completed_at": a.completed_at.isoformat() if a.completed_at else None,
        "decisions": rows,
    }


def summarize_assessments(db: Session) -> dict:
    assessments = db.query(Assessment).order_by(Assessment.id.desc()).all()
    out = {
        "total": len(assessments),
        "completed": 0,
        "in_progress": 0,
        "best_score": 0.0,
        "recent": [],
    }
    for a in assessments:
        if a.status == "COMPLETED" and a.result_score is not None:
            out["completed"] += 1
            out["best_score"] = max(out["best_score"], a.result_score)
        if a.status == "IN_PROGRESS":
            out["in_progress"] += 1
        out["recent"].append({
            "id": a.id, "name": a.name, "framework_code": a.framework_code,
            "status": a.status, "score": a.result_score,
            "findings": a.findings_count, "completed_at": a.completed_at.isoformat() if a.completed_at else None,
        })
    out["recent"] = out["recent"][:6]
    return out