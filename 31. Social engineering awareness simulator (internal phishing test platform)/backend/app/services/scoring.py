from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import models


def delivery_counts(db: Session, campaign_id: int) -> dict:
    rows = (
        db.execute(
            select(
                models.Delivery.status,
                func.count(models.Delivery.id),
            )
            .where(models.Delivery.campaign_id == campaign_id)
            .group_by(models.Delivery.status)
        )
        .all()
    )
    return {status: count for status, count in rows}


def compute_se_index(db: Session, employee_id: int) -> float:
    deliveries = db.scalars(
        select(models.Delivery).where(
            models.Delivery.employee_id == employee_id
        )
    ).all()
    if not deliveries:
        return 0.0

    weight = 1.0
    first = db.get(models.Employee, employee_id)
    if first:
        weight = first.risk_weight

    clicks = sum(1 for d in deliveries if d.clicked_at)
    submits = sum(1 for d in deliveries if d.submitted_at)
    opened = sum(1 for d in deliveries if d.opened_at)
    total = len(deliveries)

    open_rate = opened / total if total else 0
    click_rate = clicks / total if total else 0
    submit_rate = submits / total if total else 0

    base = (open_rate * 20) + (click_rate * 40) + (submit_rate * 60)
    se_index = min(100.0, base * weight)
    return round(se_index, 1)


def top_risk_rows(db: Session, limit: int = 10) -> list[dict]:
    employees = db.scalars(select(models.Employee)).all()
    rows = []
    for emp in employees:
        if emp.opt_out:
            continue
        deliveries = db.scalars(
            select(models.Delivery).where(
                models.Delivery.employee_id == emp.id
            )
        ).all()
        clicks = sum(1 for d in deliveries if d.clicked_at)
        submits = sum(1 for d in deliveries if d.submitted_at)
        score = compute_se_index(db, emp.id)
        trainings = db.scalars(
            select(models.Training).where(
                models.Training.employee_id == emp.id
            )
        ).all()
        rows.append(
            {
                "employee_id": emp.id,
                "employee_code": emp.employee_code,
                "full_name": emp.full_name,
                "branch": emp.branch,
                "se_index": score,
                "clicks": clicks,
                "submissions": submits,
                "trainings_ok": any(t.completed for t in trainings),
            }
        )
    rows.sort(key=lambda r: r["se_index"], reverse=True)
    return rows[:limit]


def campaign_stats(db: Session, campaign: models.Campaign) -> dict:
    counts = delivery_counts(db, campaign.id)
    return {
        "sent": counts.get("sent", 0),
        "opened": counts.get("opened", 0),
        "clicked": counts.get("clicked", 0),
        "submitted": counts.get("submitted", 0),
        "reported": counts.get("reported", 0),
    }


def record_risk_snapshot(db: Session, employee_id: int) -> None:
    snapshot = db.get(
        models.RiskScore,
        db.scalars(
            select(models.RiskScore.id)
            .where(models.RiskScore.employee_id == employee_id)
            .order_by(models.RiskScore.id.desc())
            .limit(1)
        ).first()
        or 0,
    )
    if snapshot and (datetime.utcnow() - snapshot.created_at).days < 1:
        return
    score = compute_se_index(db, employee_id)
    db.add(models.RiskScore(employee_id=employee_id, score=score))
    db.commit()