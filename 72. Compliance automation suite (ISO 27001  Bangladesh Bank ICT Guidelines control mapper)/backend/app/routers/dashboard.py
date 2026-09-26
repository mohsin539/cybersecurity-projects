"""Dashboard KPIs, framework compliance matrix, risk register summary (arch §14)."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from ..engines.assessment import summarize_assessments
from ..engines.mapper import compliance_matrix, dedupe_overlaps
from ..engines.risk import risk_register_summary, sla_metrics
from ..models import Asset, Control, Evidence, Framework, RemediationTicket, ScanResult, User
from ..security import require

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary")
def summary(db: Session = Depends(get_db), _: User = Depends(require("dashboard:read"))):
    matrix = compliance_matrix(db)
    risk = risk_register_summary(db)
    sla = sla_metrics(db)
    overlaps = dedupe_overlaps(db)
    assessments = summarize_assessments(db)

    assets_total = db.query(Asset).count()
    critical_findings = db.query(ScanResult).filter(
        ScanResult.status == "OPEN", ScanResult.severity.in_(["CRITICAL", "HIGH"])).count()
    controls_total = db.query(Control).count()
    evidence_total = db.query(Evidence).count()
    frameworks = db.query(Framework).filter(Framework.is_active.is_(True)).count()
    open_tickets = db.query(RemediationTicket).filter(
        RemediationTicket.status.in_(["OPEN", "IN_PROGRESS"])).count()

    return {
        "kpis": {
            "overall_compliance": matrix["overall"],
            "controls_total": controls_total,
            "assets_total": assets_total,
            "evidence_total": evidence_total,
            "critical_findings": critical_findings,
            "open_tickets": open_tickets,
            "frameworks": frameworks,
            "assessments": assessments,
            "risk": risk,
            "sla": sla,
            "overlap_savings": overlaps["overlap_savings"],
            "max_frameworks_per_evidence": overlaps["max_frameworks_per_evidence"],
        },
        "matrix": matrix,
        "risk": risk,
        "sla": sla,
        "assessments": assessments,
        "overlaps": overlaps,
    }


@router.get("/compliance/{framework_code}")
def framework_compliance(framework_code: str, db: Session = Depends(get_db),
                         _: User = Depends(require("dashboard:read"))):
    return compliance_matrix(db, framework_code)