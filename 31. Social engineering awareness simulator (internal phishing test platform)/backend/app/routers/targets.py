from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import models, schemas
from ..db import get_db
from ..deps import client_ip, require_roles
from ..services.audit import AuditService
from ..services.scoring import compute_se_index, record_risk_snapshot

router = APIRouter(prefix="/api/v1", tags=["targets"])

ALLOWED = ("admin", "security", "hr", "analyst", "auditor")


@router.get("/targets", response_model=list[schemas.EmployeeOut])
def list_targets(
    branch: str | None = None,
    q: str | None = None,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles(*ALLOWED)),
) -> list[schemas.EmployeeOut]:
    query = select(models.Employee)
    if branch:
        query = query.where(models.Employee.branch == branch)
    if q:
        like = f"%{q}%"
        query = query.where(
            (models.Employee.full_name.ilike(like))
            | (models.Employee.employee_code.ilike(like))
            | (models.Employee.email.ilike(like))
        )
    return db.scalars(query.order_by(models.Employee.full_name)).all()


@router.post("/targets", response_model=schemas.EmployeeOut, status_code=201)
def create_target(
    body: schemas.EmployeeIn,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "hr")),
) -> models.Employee:
    existing = db.scalar(
        select(models.Employee).where(
            models.Employee.employee_code == body.employee_code.strip().upper()
        )
    )
    if existing:
        raise HTTPException(status_code=409, detail="Employee code already exists")

    emp = models.Employee(
        employee_code=body.employee_code.strip().upper(),
        full_name=body.full_name.strip(),
        email=body.email.lower(),
        phone=body.phone,
        branch=body.branch.strip(),
        division=body.division.strip(),
        job_grade=body.job_grade,
        risk_weight=body.risk_weight,
        opt_out=body.opt_out,
    )
    db.add(emp)
    db.commit()
    if not emp.opt_out:
        db.add(models.ConsentRecord(employee_id=emp.id))
    db.commit()

    AuditService(db, user.username, client_ip(request)).log(
        "target.created", "employee", emp.id,
        "%s %s" % (emp.employee_code, emp.full_name),
    )
    db.commit()
    return emp


@router.post("/targets/{target_id}/optout", response_model=schemas.EmployeeOut)
def toggle_optout(
    target_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "hr")),
) -> models.Employee:
    emp = db.get(models.Employee, target_id)
    if emp is None:
        raise HTTPException(status_code=404, detail="Target not found")
    emp.opt_out = not emp.opt_out
    db.commit()

    AuditService(db, user.username, client_ip(request)).log(
        "target.optout", "employee", emp.id, "opt_out=%s" % emp.opt_out
    )
    db.commit()
    return emp


@router.post("/targets/sync", response_model=dict)
def sync_targets(
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles("admin", "hr")),
) -> dict:
    total = db.scalar(select(func.count(models.Employee.id))) or 0
    AuditService(db, user.username, client_ip(request)).log(
        "targets.sync", "employee", None, "current_count=%d" % total
    )
    db.commit()
    return {"ok": True, "current_count": total, "adapter": "scim-stub"}


@router.get("/targets/{target_id}/risk", response_model=schemas.RiskRow)
def target_risk(
    target_id: int,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles(*ALLOWED)),
) -> dict:
    emp = db.get(models.Employee, target_id)
    if emp is None:
        raise HTTPException(status_code=404, detail="Target not found")
    record_risk_snapshot(db, target_id)

    from ..services.scoring import top_risk_rows

    rows = top_risk_rows(db, 9999)
    row = next((r for r in rows if r["employee_id"] == target_id), None)
    if row is None:
        row = {
            "employee_code": emp.employee_code,
            "full_name": emp.full_name,
            "branch": emp.branch,
            "se_index": 0.0,
            "clicks": 0,
            "submissions": 0,
            "trainings_ok": True,
        }
    return row