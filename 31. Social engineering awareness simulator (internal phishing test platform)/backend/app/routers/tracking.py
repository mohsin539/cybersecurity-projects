import base64
from datetime import datetime
from html import escape

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import models
from ..db import get_db
from ..deps import client_ip, is_internal, parse_target_ip
from ..security import hash_value, mask_username
from ..services.scoring import record_risk_snapshot

router = APIRouter(tags=["tracking"])

TRANSPARENT_1PX_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
    "YAAAAAYAAjCB0C8AAAAASUVORK5CYII="
)

OTT = 2


def _delivery_from_token(db: Session, token: str) -> models.Delivery:
    delivery = db.scalar(
        select(models.Delivery).where(models.Delivery.token == token)
    )
    if delivery is None:
        raise HTTPException(status_code=404, detail="Unknown tracking token")
    return delivery


def _render_landing(db: Session, delivery: models.Delivery) -> str:
    title = "Bank Portal Login"
    body = "<p>You were redirected to verify your account. Please sign in.</p>"

    variant = db.get(models.CampaignVariant, delivery.variant_id)
    if variant:
        if variant.landing_page_id:
            page = db.get(models.LandingPage, variant.landing_page_id)
            if page:
                title = escape(page.title)
                body = page.body_html
        elif variant.email_template_id:
            tmpl = db.get(models.EmailTemplate, variant.email_template_id)
            if tmpl:
                body = tmpl.body_html

    form = f"""
    <div style="max-width:460px;margin:40px auto;background:#fff;border:1px solid #dbe4f0;
                border-radius:14px;padding:28px;box-shadow:0 8px 24px rgba(11,31,58,.10);">
      <h2 style="margin:0 0 14px;color:#0b1f3a;">{title}</h2>
      <div style="background:#fff7ed;border-left:4px solid #f59e0b;padding:10px 14px;border-radius:8px;
                  font-size:13px;color:#92400e;margin-bottom:16px;">
        <b>Security Notice:</b> You attempted to sign in to a site that is part of the bank's
        authorised <b>Social Engineering Awareness Simulation</b>. No real credentials were required
        or captured. Please use the button below to continue to secure awareness training.
      </div>
      <form action="/t/s/{delivery.token}" method="post" style="display:flex;flex-direction:column;gap:10px;">
        <input name="username" placeholder="User ID" autocomplete="off"
               style="padding:12px;border:1px solid #cbd5e1;border-radius:8px;" required>
        <input name="password" type="password" placeholder="Password" autocomplete="off"
               style="padding:12px;border:1px solid #cbd5e1;border-radius:8px;" required>
        <button style="padding:13px;background:#0e7490;color:#fff;border:0;border-radius:8px;
                       font-weight:700;cursor:pointer;">Sign in</button>
      </form>
      <p style="font-size:12px;color:#5b6b80;margin-top:16px;">
        This is an internal training exercise. {body[:120]}
      </p>
    </div>
    """
    audit = f"""
    <div style="max-width:560px;margin:40px auto;background:#fff;border:1px solid #dbe4f0;
                border-radius:14px;padding:28px;">
      <h2 style="margin:0 0 10px;color:#0b1f3a;">You have been reported</h2>
      <p style="color:#334155;">This page is part of the bank's phishing-awareness simulation.
         Clicking through and entering details into simulated logins can happen to anyone, once.
         The important thing is that you now recognise the indicators of a phishing attempt.</p>
      <ul>
        <li>Suspicious sender address / urgent wording</li>
        <li>Generic greeting instead of your name</li>
        <li>Links to unfamiliar domains</li>
        <li>Requests for credentials or OTP</li>
      </ul>
      <a href="/t/e/{delivery.token}"
         style="display:inline-block;background:#16a34a;color:#fff;padding:12px 18px;
                border-radius:8px;text-decoration:none;font-weight:700;">Start Awareness Training &#8594;</a>
    </div>
    """
    if delivery.reported_at:
        return audit

    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>{title}</title>
<style>
  body{{margin:0;font-family:'Segoe UI',Arial,sans-serif;background:#f1f5f9;color:#1a2433;}}
  input:focus{{outline:2px solid #0ea5e9;}}
</style></head><body>
<div style="background:#0b1f3a;color:#fff;padding:14px 24px;font-size:13px;">
  AUTHENTICATED SESSION TEST — {title} (simulated)
</div>
{form}
</body></html>"""


@router.get("/t/o/{token}.png", response_class=Response)
def track_open(token: str, request: Request, db: Session = Depends(get_db)) -> Response:
    delivery = _delivery_from_token(db, token)
    if delivery.opened_at is None:
        delivery.opened_at = datetime.utcnow()
        if delivery.status in ("pending", "sent", "clicked"):
            delivery.status = "opened"
        db.add(
            models.Event(
                delivery_id=delivery.id,
                employee_id=delivery.employee_id,
                campaign_id=delivery.campaign_id,
                event_type="open",
                payload="ua=%s ip=%s" % (
                    request.headers.get("user-agent", "")[:80],
                    client_ip(request),
                ),
            )
        )
        db.commit()
    return Response(content=TRANSPARENT_1PX_PNG, media_type="image/png")


@router.get("/t/c/{token}")
def track_click(token: str, request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    delivery = _delivery_from_token(db, token)
    now = datetime.utcnow()
    if delivery.clicked_at is None:
        delivery.clicked_at = now
        if delivery.opened_at is None:
            delivery.opened_at = now
        delivery.status = "clicked"
        ip = parse_target_ip(request)
        payload = "ua=%s ip=%s internal=%s" % (
            request.headers.get("user-agent", "")[:80],
            client_ip(request),
            is_internal(ip) if ip else "unknown",
        )
        db.add(
            models.Event(
                delivery_id=delivery.id,
                employee_id=delivery.employee_id,
                campaign_id=delivery.campaign_id,
                event_type="click",
                payload=payload,
            )
        )
        db.commit()
    return RedirectResponse(url="/l/%s" % delivery.token)


@router.get("/l/{token}", response_class=HTMLResponse)
def landing_page(token: str, db: Session = Depends(get_db)) -> str:
    delivery = _delivery_from_token(db, token)
    return _render_landing(db, delivery)


@router.post("/t/s/{token}")
async def track_submit(token: str, request: Request, db: Session = Depends(get_db)):
    delivery = _delivery_from_token(db, token)
    data = await request.form()
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    now = datetime.utcnow()
    if delivery.submitted_at is None:
        delivery.submitted_at = now
        delivery.status = "submitted"
        db.add(
            models.Submission(
                delivery_id=delivery.id,
                submitted_username=mask_username(username),
                password_hash=hash_value(password) if password else hash_value("empty"),
            )
        )
        db.add(
            models.Event(
                delivery_id=delivery.id,
                employee_id=delivery.employee_id,
                campaign_id=delivery.campaign_id,
                event_type="submit",
                payload="username=%s" % mask_username(username),
            )
        )
        db.commit()
        record_risk_snapshot(db, delivery.employee_id)

    return RedirectResponse(url="/t/r/%s" % delivery.token, status_code=303)


@router.get("/t/r/{token}")
def track_report(token: str, request: Request, db: Session = Depends(get_db)):
    delivery = _delivery_from_token(db, token)
    now = datetime.utcnow()
    if delivery.reported_at is None:
        delivery.reported_at = now
        delivery.status = "reported"
        db.add(
            models.Event(
                delivery_id=delivery.id,
                employee_id=delivery.employee_id,
                campaign_id=delivery.campaign_id,
                event_type="report",
                payload="soc-ticket-simulated",
            )
        )
        db.commit()
    return RedirectResponse(url="/t/e/%s" % delivery.token)


@router.get("/t/e/{token}", response_class=HTMLResponse)
def training_page(token: str, db: Session = Depends(get_db)) -> str:
    delivery = _delivery_from_token(db, token)
    emp = db.get(models.Employee, delivery.employee_id)
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Awareness Training</title>
<style>
  body{{margin:0;font-family:'Segoe UI',Arial,sans-serif;background:#f4f7fb;color:#1a2433;}}
  .card{{max-width:640px;margin:48px auto;background:#fff;border:1px solid #dbe4f0;border-radius:16px;padding:30px;}}
  .tip{{background:#eff6ff;border-left:4px solid #0ea5e9;padding:12px 16px;border-radius:8px;margin:12px 0;}}
</style></head><body>
<div class="card">
  <h2>Well done, {escape(emp.full_name) if emp else 'colleague'} &#10004;</h2>
  <p>You recognised and reported a simulated phishing attempt. Your response has been logged for the
     bank's continuous awareness programme and your personal SE-Index risk score was recalculated.</p>
  <div class="tip"><b>Indicators to remember:</b> urgency, unknown sender domains, generic greetings,
     requests for credentials/OTPs, mismatched link domains.</div>
  <p style="font-size:13px;color:#5b6b80;">This page completes the simulated scenario.
     Your SOC ticket (simulated) has been recorded.</p>
</div>
</body></html>"""