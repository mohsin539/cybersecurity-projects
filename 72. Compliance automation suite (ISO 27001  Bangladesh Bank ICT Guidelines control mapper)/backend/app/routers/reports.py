"""Report download endpoints — PDF/DOCX/XLSX/CSV/JSON + evidence ZIP (arch §9)."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User
from ..reports.generator import build_csv, build_report
from ..security import require, audit as audit_fn

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/formats")
def formats(_: User = Depends(require("dashboard:read"))):
    return {
        "formats": ["pdf", "docx", "xlsx", "csv", "json", "zip"],
        "types": ["controls", "risk", "evidence", "scans", "mapping", "assessments"],
        "report_catalogue": [
            {"name": "Executive Scorecard", "scope": "all", "cadence": "Quarterly", "formats": ["pdf", "xlsx"]},
            {"name": "SoA (Statement of Applicability)", "scope": "iso", "cadence": "Annual", "formats": ["docx", "xlsx"]},
            {"name": "BB ICT F&R Return", "scope": "bb_fr", "cadence": "Quarterly", "formats": ["xlsx", "csv", "pdf"]},
            {"name": "NIST CSF Tier Profile", "scope": "nist", "cadence": "Continuous", "formats": ["pdf", "json"]},
            {"name": "Gap Analysis Heatmap", "scope": "gaps", "cadence": "On-demand", "formats": ["pdf", "xlsx"]},
            {"name": "Risk Register & Treatment Plan", "scope": "risk", "cadence": "Monthly", "formats": ["xlsx", "pdf"]},
            {"name": "Remediation SLA Dashboard", "scope": "sla", "cadence": "Weekly", "formats": ["csv", "json"]},
            {"name": "OWASP AppSec / SBOM Report", "scope": "owasp", "cadence": "Per release", "formats": ["pdf", "json", "csv"]},
            {"name": "Evidence Pack (isometric mapping)", "scope": "evidence", "cadence": "On-demand", "formats": ["zip", "pdf"]},
        ],
    }


@router.get("/download")
def download(
    report: str = Query("controls"),
    fmt: str = Query("pdf"),
    framework: str = Query(None),
    period: str = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require("report:read")),
):
    return build_report(db, report, fmt, framework, actor=user.display_name, period=period)


@router.get("/csv")
def download_csv(
    report: str = Query("controls"),
    framework: str = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require("report:read")),
):
    return build_csv(db, report, framework)