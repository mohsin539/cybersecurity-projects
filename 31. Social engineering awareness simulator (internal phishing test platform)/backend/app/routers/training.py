from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models, schemas
from ..db import get_db
from ..deps import client_ip, require_roles
from ..services.audit import AuditService
from ..services.scoring import top_risk_rows

router = APIRouter(prefix="/api/v1/training", tags=["training"])

ALLOWED = ("admin", "security", "hr", "analyst", "auditor")
WRITE = ("admin", "security", "hr")

DEFAULT_MODULES = [
    "Phishing101 - Spot the Lure",
    "Indicators of Compromise",
    "OTP & Credential Hygiene",
    "Vishing & Social Engineering Calls",
    "Reporting to SOC",
]


@router.get("", response_model=list[schemas.TrainingOut])
def list_trainings(
    employee_id: int | None = None,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles(*ALLOWED)),
) -> list[models.Training]:
    query = select(models.Training).order_by(models.Training.id.desc())
    if employee_id:
        query = query.where(models.Training.employee_id == employee_id)
    return db.scalars(query).all()


@router.post("/enroll", response_model=list[schemas.TrainingOut], status_code=201)
def enroll(
    body: schemas.TrainingIn,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles(*WRITE)),
) -> list[models.Training]:
    emp = db.get(models.Employee, body.employee_id)
    if emp is None:
        raise HTTPException(status_code=404, detail="Employee not found")

    existing = {
        t.title
        for t in db.scalars(
            select(models.Training).where(
                models.Training.employee_id == body.employee_id
            )
        )
    }
    created = []
    for module in DEFAULT_MODULES:
        if module in existing:
            continue
        training = models.Training(
            employee_id=body.employee_id,
            title=module,
            completed=False,
            score=0,
        )
        db.add(training)
        created.append(training)
    db.commit()

    AuditService(db, user.username, client_ip(request)).log(
        "training.enrolled", "employee", emp.id,
        "modules=%d full_name=%s" % (len(created), emp.full_name),
    )
    db.commit()
    return db.scalars(
        select(models.Training).where(
            models.Training.employee_id == body.employee_id
        )
    ).all()


@router.post("/{training_id}/complete", response_model=schemas.TrainingOut)
def complete_training(
    training_id: int,
    body: schemas.TrainingIn,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles(*WRITE)),
) -> models.Training:
    training = db.get(models.Training, training_id)
    if training is None:
        raise HTTPException(status_code=404, detail="Training not found")
    training.completed = True
    training.score = body.score
    db.commit()

    AuditService(db, user.username, client_ip(request)).log(
        "training.completed", "training", training.id,
        "employee=%d score=%d" % (training.employee_id, training.score),
    )
    db.commit()
    return training


@router.post("/auto-assign", response_model=dict)
def auto_assign_at_risk(
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles(*WRITE)),
) -> dict:
    assigned = 0
    for row in top_risk_rows(db, 9999):
        if row["clicks"] == 0 and row["submissions"] == 0:
            continue
        existing = {
            t.title
            for t in db.scalars(
                select(models.Training).where(
                    models.Training.employee_id == row["employee_id"]
                )
            )
        }
        for module in DEFAULT_MODULES[:2]:
            if module not in existing:
                db.add(
                    models.Training(
                        employee_id=row["employee_id"],
                        title=module,
                        completed=False,
                        score=0,
                    )
                )
                assigned += 1
    db.commit()

    AuditService(db, user.username, client_ip(request)).log(
        "training.auto-assigned", "training", None, "assigned=%d" % assigned
    )
    db.commit()
    return {"ok": True, "assigned": assigned}