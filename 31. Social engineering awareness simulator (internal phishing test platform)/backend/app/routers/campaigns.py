import json

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import models, schemas
from ..db import get_db
from ..deps import client_ip, get_current_user, require_roles
from ..services import delivery
from ..services.audit import AuditService
from ..services.scoring import campaign_stats, top_risk_rows

router = APIRouter(prefix="/api/v1", tags=["campaigns"])


def _campaign_out(db: Session, campaign: models.Campaign) -> schemas.CampaignOut:
    stats = campaign_stats(db, campaign)
    return schemas.CampaignOut(
        id=campaign.id,
        name=campaign.name,
        vector=campaign.vector,
        status=campaign.status,
        schedule_at=campaign.schedule_at,
        created_at=campaign.created_at,
        **stats,
    )


@router.get("/dashboard", response_model=schemas.DashboardOut)
def dashboard(
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "security", "hr", "analyst", "auditor")),
) -> schemas.DashboardOut:
    campaigns = db.scalars(select(models.Campaign)).all()
    outs = [_campaign_out(db, c) for c in campaigns]

    total_employees = db.scalar(select(func.count(models.Employee.id))) or 0
    sent = db.scalar(select(func.count(models.Delivery.id)).where(models.Delivery.status != "pending")) or 0
    opened = db.scalar(select(func.count(models.Delivery.id)).where(models.Delivery.opened_at.is_not(None))) or 0
    clicked = db.scalar(select(func.count(models.Delivery.id)).where(models.Delivery.clicked_at.is_not(None))) or 0
    submitted = db.scalar(select(func.count(models.Delivery.id)).where(models.Delivery.submitted_at.is_not(None))) or 0
    reported = db.scalar(select(func.count(models.Delivery.id)).where(models.Delivery.reported_at.is_not(None))) or 0

    risk = top_risk_rows(db, 10)
    avg = round(sum(r["se_index"] for r in risk) / len(risk), 1) if risk else 0.0

    return schemas.DashboardOut(
        total_employees=total_employees,
        total_campaigns=len(campaigns),
        total_sent=sent,
        total_opened=opened,
        total_clicked=clicked,
        total_submitted=submitted,
        total_reported=reported,
        avg_se_index=avg,
        campaigns=outs,
        top_risk=risk,
    )


@router.get("/campaigns", response_model=list[schemas.CampaignOut])
def list_campaigns(
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "security", "hr", "analyst", "auditor")),
) -> list[schemas.CampaignOut]:
    campaigns = db.scalars(select(models.Campaign).order_by(models.Campaign.id.desc())).all()
    return [_campaign_out(db, c) for c in campaigns]


@router.get("/campaigns/{campaign_id}", response_model=schemas.CampaignOut)
def get_campaign(
    campaign_id: int,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "security", "hr", "analyst", "auditor")),
) -> schemas.CampaignOut:
    campaign = db.get(models.Campaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return _campaign_out(db, campaign)


@router.post("/campaigns", response_model=schemas.CampaignOut, status_code=201)
def create_campaign(
    body: schemas.CampaignIn,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "security")),
) -> schemas.CampaignOut:
    campaign = models.Campaign(
        name=body.name.strip(),
        vector=body.vector,
        status="draft",
        branches=json.dumps(body.branches),
        divisions=json.dumps(body.divisions),
        schedule_at=body.schedule_at,
        created_by=user.id,
    )
    db.add(campaign)
    db.flush()

    if body.templates:
        for idx, template_id in enumerate(body.templates):
            landing = None
            if body.landing_pages:
                landing = body.landing_pages[min(idx, len(body.landing_pages) - 1)]
            db.add(
                models.CampaignVariant(
                    campaign_id=campaign.id,
                    name="variant-%d" % (idx + 1),
                    weight=1,
                    email_template_id=template_id,
                    landing_page_id=landing,
                )
            )
    else:
        db.add(
            models.CampaignVariant(
                campaign_id=campaign.id,
                name="default",
                weight=1,
                landing_page_id=body.landing_pages[0] if body.landing_pages else None,
            )
        )
    db.commit()

    AuditService(db, user.username, client_ip(request)).log(
        "campaign.created", "campaign", campaign.id, campaign.name
    )
    db.commit()
    return _campaign_out(db, campaign)


@router.post("/campaigns/{campaign_id}/approve", response_model=schemas.CampaignOut)
def approve_campaign(
    campaign_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "security", "hr")),
) -> schemas.CampaignOut:
    campaign = db.get(models.Campaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if campaign.status == "approved":
        raise HTTPException(status_code=400, detail="Campaign already approved")
    if campaign.status not in ("draft", "review"):
        raise HTTPException(status_code=400, detail="Only draft/review campaigns can be approved")

    prior = db.scalars(
        select(models.AuditLog).where(
            models.AuditLog.target_type == "campaign",
            models.AuditLog.target_id == campaign_id,
            models.AuditLog.action == "campaign.approved",
        )
    ).all()
    if any(entry.actor == user.username for entry in prior):
        raise HTTPException(status_code=400, detail="This user already approved the campaign")

    if len(prior) >= 1:
        campaign.status = "approved"
        campaign.approved_by = user.id
        AuditService(db, user.username, client_ip(request)).log(
            "campaign.dual-approved", "campaign", campaign.id,
            "approvers=%d" % (len(prior) + 1),
        )
    else:
        campaign.status = "review"
        campaign.approved_by = user.id
        AuditService(db, user.username, client_ip(request)).log(
            "campaign.approved", "campaign", campaign.id
        )
    db.commit()
    return _campaign_out(db, campaign)


@router.post("/campaigns/{campaign_id}/launch", response_model=schemas.CampaignOut)
def launch_campaign(
    campaign_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "security")),
) -> schemas.CampaignOut:
    campaign = db.get(models.Campaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if campaign.status not in ("approved", "scheduled", "running"):
        raise HTTPException(
            status_code=400,
            detail="Campaign must be approved before launch",
        )

    count = delivery.build_deliveries(db, campaign)
    campaign.status = "scheduled"
    db.commit()
    delivery.launch_campaign(campaign_id)

    AuditService(db, user.username, client_ip(request)).log(
        "campaign.launched", "campaign", campaign.id,
        "deliveries=%d" % count,
    )
    db.commit()
    return _campaign_out(db, db.get(models.Campaign, campaign_id))


@router.get("/campaigns/{campaign_id}/deliveries", response_model=list[schemas.DeliveryOut])
def list_deliveries(
    campaign_id: int,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "security", "hr", "analyst", "auditor")),
) -> list[schemas.DeliveryOut]:
    campaign = db.get(models.Campaign, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")

    deliveries = db.scalars(
        select(models.Delivery).where(models.Delivery.campaign_id == campaign_id)
    ).all()
    outs = []
    for d in deliveries:
        emp = db.get(models.Employee, d.employee_id)
        outs.append(
            schemas.DeliveryOut(
                id=d.id,
                employee_code=emp.employee_code if emp else "",
                full_name=emp.full_name if emp else "",
                branch=emp.branch if emp else "",
                status=d.status,
                open_url="/t/o/%s.png" % d.token,
                click_url="/t/c/%s" % d.token,
                sent_at=d.sent_at,
                opened_at=d.opened_at,
                clicked_at=d.clicked_at,
                submitted_at=d.submitted_at,
                reported_at=d.reported_at,
            )
        )
    return outs