from fastapi import APIRouter, Depends, HTTPException, Request, status
from html import escape
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models, schemas
from ..db import get_db
from ..deps import client_ip, require_roles
from ..services.audit import AuditService

router = APIRouter(prefix="/api/v1", tags=["templates"])

ALLOWED = ("admin", "security", "hr", "analyst", "auditor")
WRITE = ("admin", "security")


@router.get("/templates", response_model=list[schemas.TemplateOut])
def list_templates(
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles(*ALLOWED)),
) -> list[models.EmailTemplate]:
    return db.scalars(select(models.EmailTemplate).order_by(models.EmailTemplate.id.desc())).all()


@router.post("/templates", response_model=schemas.TemplateOut, status_code=201)
def create_template(
    body: schemas.TemplateIn,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles(*WRITE)),
) -> models.EmailTemplate:
    tmpl = models.EmailTemplate(
        name=body.name.strip(),
        language=body.language,
        subject=escape(body.subject),
        body_html=_sanitize_html(body.body_html),
    )
    db.add(tmpl)
    db.commit()
    AuditService(db, user.username, client_ip(request)).log(
        "template.created", "template", tmpl.id, tmpl.name
    )
    db.commit()
    return tmpl


@router.get("/landing-pages", response_model=list[schemas.LandingPageOut])
def list_landing_pages(
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles(*ALLOWED)),
) -> list[models.LandingPage]:
    return db.scalars(
        select(models.LandingPage).order_by(models.LandingPage.id.desc())
    ).all()


@router.post("/landing-pages", response_model=schemas.LandingPageOut, status_code=201)
def create_landing_page(
    body: schemas.LandingPageIn,
    request: Request,
    db: Session = Depends(get_db),
    user: models.User = Depends(require_roles(*WRITE)),
) -> models.LandingPage:
    page = models.LandingPage(
        name=body.name.strip(),
        title=escape(body.title),
        body_html=_sanitize_html(body.body_html),
    )
    db.add(page)
    db.commit()
    AuditService(db, user.username, client_ip(request)).log(
        "landing.created", "landing_page", page.id, page.name
    )
    db.commit()
    return page


def _sanitize_html(html_body: str) -> str:
    return escape(html_body, quote=True)