"""Assessment lifecycle endpoints (auto-run, update decisions, detail)."""
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..database import get_db
from ..engines.assessment import (
    assessment_detail, run_assessment, summarize_assessments, update_decision,
)
from ..models import User
from ..security import audit, client_ip, require

router = APIRouter(prefix="/assessments", tags=["assessments"])


@router.get("")
def list_assessments(db: Session = Depends(get_db), _: User = Depends(require("dashboard:read"))):
    return summarize_assessments(db)


@router.post("")
def create_assessment(payload: dict, request: Request, db: Session = Depends(get_db),
                      user: User = Depends(require("assess:write"))):
    assessment = run_assessment(
        db,
        name=payload.get("name", f"{payload['framework_code']} assessment"),
        framework_code=payload["framework_code"],
        method=payload.get("method", "AUTO"),
        scope=payload.get("scope", "ANNUAL"),
        actor=user.username,
    )
    audit(db, user.username, user.role, "ASSESSMENT_RUN", "ASSESSMENT", assessment.id,
          {"framework": assessment.framework_code, "method": assessment.method,
           "score": assessment.result_score, "findings": assessment.findings_count},
          client_ip(request))
    return {"id": assessment.id, "name": assessment.name,
            "status": assessment.status, "score": assessment.result_score,
            "findings_count": assessment.findings_count}


@router.get("/{assessment_id}")
def get_assessment(assessment_id: int, db: Session = Depends(get_db),
                   _: User = Depends(require("dashboard:read"))):
    return assessment_detail(db, assessment_id)


@router.post("/{assessment_id}/decisions/{control_id}")
def set_decision(assessment_id: int, control_id: int, payload: dict, request: Request,
                 db: Session = Depends(get_db), user: User = Depends(require("assess:write"))):
    d = update_decision(db, assessment_id, control_id,
                        payload["status"], payload.get("note", ""),
                        payload.get("evidence_ref", ""), user.username)
    audit(db, user.username, user.role, "DECISION_UPDATE", "ASSESSMENT_DECISION", d.id,
          {"assessment": assessment_id, "control": control_id, "status": d.status},
          client_ip(request))
    return {"id": d.id, "status": d.status}