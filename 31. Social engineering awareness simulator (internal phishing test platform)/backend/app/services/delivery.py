import json
import random
import threading
import time
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models
from ..db import SessionLocal
from ..security import new_token

DELIVERY_RAMP_SECONDS = 2


def _pick_variant(campaign: models.Campaign) -> models.CampaignVariant:
    weights = [v.weight for v in campaign.variants]
    return random.choices(campaign.variants, weights=weights, k=1)[0]


def build_deliveries(db: Session, campaign: models.Campaign) -> int:
    query = select(models.Employee).where(models.Employee.opt_out == False)
    branches = json.loads(campaign.branches or "[]")
    divisions = json.loads(campaign.divisions or "[]")
    if branches:
        query = query.where(models.Employee.branch.in_(branches))
    if divisions:
        query = query.where(models.Employee.division.in_(divisions))
    employees = db.scalars(query).all()

    if not campaign.variants:
        first_template = db.scalar(select(models.EmailTemplate).limit(1))
        variant = models.CampaignVariant(
            campaign_id=campaign.id,
            name="default",
            weight=1,
            email_template_id=first_template.id if first_template else None,
        )
        db.add(variant)
        db.flush()
    else:
        variant = _pick_variant(campaign)

    tokens = set()
    for employee in employees:
        token = new_token()
        while token in tokens:
            token = new_token()
        tokens.add(token)
        delivery = models.Delivery(
            campaign_id=campaign.id,
            variant_id=variant.id,
            employee_id=employee.id,
            token=token,
            status="pending",
        )
        db.add(delivery)
    return len(employees)


def _mark_sent(delivery_id: int) -> None:
    with SessionLocal() as db:
        delivery = db.get(models.Delivery, delivery_id)
        if delivery is None or delivery.status != "pending":
            return
        delivery.status = "sent"
        delivery.sent_at = datetime.utcnow()
        db.add(
            models.Event(
                delivery_id=delivery.id,
                employee_id=delivery.employee_id,
                campaign_id=delivery.campaign_id,
                event_type="sent",
            )
        )
        db.commit()


def _dispatch_deliveries(pending: list[tuple[int, float]]) -> None:
    for delivery_id, delay in pending:
        time.sleep(delay)
        _mark_sent(delivery_id)


def launch_campaign(campaign_id: int) -> None:
    with SessionLocal() as db:
        campaign = db.get(models.Campaign, campaign_id)
        if campaign is None or campaign.status not in ("approved", "scheduled", "running"):
            return
        campaign.status = "running"
        db.commit()

        pending = [
            (
                d.id,
                index * DELIVERY_RAMP_SECONDS + random.uniform(0, DELIVERY_RAMP_SECONDS),
            )
            for index, d in enumerate(campaign.deliveries)
            if d.status == "pending"
        ]
    if pending:
        thread = threading.Thread(
            target=_dispatch_deliveries, args=(pending,), daemon=True
        )
        thread.start()