import os
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import models, schemas
from ..config import get_settings
from ..db import get_db
from ..deps import client_ip, require_roles
from ..security import new_token
from ..services.audit import AuditService
from ..services.exporters import build_export
from ..services.scoring import campaign_stats, top_risk_rows

router = APIRouter(prefix="/api/v1", tags=["reports"])

ALLOWED = ("admin", "security", "hr", "analyst", "auditor")

FORMAT_TO_EXT = {"xlsx": "xlsx", "csv": "csv", "html": "html"}


@router.get("/reports", response_model=list[schemas.ReportOut])
def list_reports(
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles(*ALLOWED)),
) -> list[models.ReportBundle]:
    return db.scalars(
        select(models.ReportBundle).order_by(models.ReportBundle.id.desc())
    ).all()


def _collect_report_data(db: Session, campaign_id: int | None) -> dict:
    campaigns = db.scalars(select(models.Campaign)).all()
    campaign_rows = []
    for c in campaigns:
        if campaign_id and c.id != campaign_id:
            continue
        stats = campaign_stats(db, c)
        campaign_rows.append(
            {
                "name": c.name,
                "vector": c.vector,
                "status": c.status,
                "sent": stats["sent"],
                "opened": stats["opened"],
                "clicked": stats["clicked"],
                "submitted": stats["submitted"],
                "reported": stats["reported"],
            }
        )

    risk = top_risk_rows(db, 10)
    summary = {
        "campaigns": len(campaign_rows),
        "sent": sum(c["sent"] for c in campaign_rows),
        "opened": sum(c["opened"] for c in campaign_rows),
        "clicked": sum(c["clicked"] for c in campaign_rows),
        "submitted": sum(c["submitted"] for c in campaign_rows),
        "reported": sum(c["reported"] for c in campaign_rows),
        "avg_se_index": round(
            sum(r["se_index"] for r in risk) / len(risk), 1
        )
        if risk
        else 0.0,
    }

    deliveries = db.scalars(
        select(models.Delivery).order_by(models.Delivery.id.desc()).limit(5000)
    ).all()
    events = []
    for d in deliveries:
        emp = db.get(models.Employee, d.employee_id)
        camp = db.get(models.Campaign, d.campaign_id)
        state = "pending"
        if d.submitted_at:
            state = "submitted"
        elif d.clicked_at:
            state = "clicked"
        elif d.opened_at:
            state = "opened"
        elif d.sent_at:
            state = "sent"
        when = (
            d.submitted_at
            or d.clicked_at
            or d.opened_at
            or d.sent_at
        )
        if when is None:
            when = camp.created_at if camp else None
        events.append(
            [
                when.strftime("%Y-%m-%d %H:%M:%S") if when else "",
                emp.full_name if emp else "",
                camp.name if camp else "",
                state,
            ]
        )

    return {
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "summary": summary,
        "campaigns": campaign_rows,
        "risk_rows": risk,
        "events": events,
    }


@router.post("/reports", response_model=schemas.ReportOut, status_code=201)
def create_report(
    body: schemas.ReportRequest,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles(*ALLOWED)),
) -> models.ReportBundle:
    settings = get_settings()
    os.makedirs(settings.reports_dir, exist_ok=True)

    data = _collect_report_data(db, body.campaign_id)
    ext = FORMAT_TO_EXT[body.fmt]
    stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    filename = "seas-report-%s.%s" % (stamp, ext)
    filepath = os.path.join(settings.reports_dir, filename)

    size = build_export(data, body.fmt, filepath)

    bundle = models.ReportBundle(
        name=filename,
        fmt=body.fmt,
        path=filepath,
        size=size,
        status="ready",
        created_by=user.id,
        url_token=new_token(),
    )
    db.add(bundle)
    db.commit()

    AuditService(db, user.username, client_ip(request)).log(
        "report.generated", "report", bundle.id, "%s (%d bytes)" % (filename, size)
    )
    db.commit()
    return bundle


@router.get("/reports/{url_token}/download")
def download_report(
    url_token: str,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles(*ALLOWED)),
) -> FileResponse:
    bundle = db.scalar(
        select(models.ReportBundle).where(
            models.ReportBundle.url_token == url_token
        )
    )
    if bundle is None or not os.path.exists(bundle.path):
        raise HTTPException(status_code=404, detail="Report not found")

    AuditService(db, user.username, client_ip(request)).log(
        "report.downloaded", "report", bundle.id, bundle.name
    )
    db.commit()
    return FileResponse(
        bundle.path,
        filename=bundle.name,
        media_type=_media_type(bundle.fmt),
    )


def _media_type(fmt: str) -> str:
    return {
        "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "csv": "text/csv",
        "html": "text/html",
    }[fmt]