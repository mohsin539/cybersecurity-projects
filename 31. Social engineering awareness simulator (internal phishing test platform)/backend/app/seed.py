import json
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import models
from .config import get_settings
from .db import SessionLocal, engine, Base
from .security import new_token, hash_password

EMPLOYEES = [
    ("BD001", "Rahim Uddin", "rahim.uddin@bank.example.com", "01711-000001", "Motijheel", "Retail", "G12", 1.4),
    ("BD002", "Karim Hossain", "karim.hossain@bank.example.com", "01711-000002", "Motijheel", "Retail", "G11", 1.3),
    ("BD003", "Fatema Begum", "fatema.begum@bank.example.com", "01811-000003", "Gulshan", "Digital", "G13", 1.2),
    ("BD004", "Nusrat Jahan", "nusrat.jahan@bank.example.com", "01711-000004", "Gulshan", "Digital", "G14", 1.1),
    ("BD005", "Mahmud Hasan", "mahmud.hasan@bank.example.com", "01811-000005", "Dhanmondi", "Operations", "G11", 1.5),
    ("BD006", "Sabrina Khan", "sabrina.khan@bank.example.com", "01711-000006", "Dhanmondi", "Operations", "G12", 1.2),
    ("BD007", "Tanvir Ahmed", "tanvir.ahmed@bank.example.com", "01911-000007", "Uttara", "Treasury", "G15", 1.0),
    ("BD008", "Mitu Rahman", "mitu.rahman@bank.example.com", "01711-000008", "Uttara", "Treasury", "G11", 1.4),
    ("BD009", "Sajid Mahmud", "sajid.mahmud@bank.example.com", "01911-000009", "Banani", "Finance", "G16", 0.9),
    ("BD010", "Farhana Akter", "farhana.akter@bank.example.com", "01811-000010", "Banani", "Finance", "G13", 1.1),
    ("BD011", "Rafiqul Islam", "rafiqul.islam@bank.example.com", "01711-000011", "Badda", "HR", "G12", 1.0),
    ("BD012", "Sharmin Sultana", "sharmin.sultana@bank.example.com", "01911-000012", "Badda", "HR", "G11", 1.1),
]

EMAIL_TEMPLATES = [
    {
        "name": "Password Expiry (EN)",
        "language": "en",
        "subject": "Action Required: Your Bank Password Expires Today",
        "body_html": (
            "<p>Dear {full_name},</p>"
            "<p>Your corporate account password expires today. Verify now to keep your account active.</p>"
            "<p><a href='{click_url}'>Secure Portal &gt;</a></p>"
        ),
    },
    {
        "name": "Meeting Invite (EN)",
        "language": "en",
        "subject": "Invitation: Executive Committee Meeting",
        "body_html": (
            "<p>Dear {full_name},</p>"
            "<p>The monthly Executive Committee meeting has been rescheduled. Review the updated agenda.</p>"
            "<p><a href='{click_url}'>View Agenda</a></p>"
        ),
    },
    {
        "name": "Bonus Slip (BN)",
        "language": "bn",
        "subject": "পারিতোষিক স্লিপ ডাউনলোড করুন",
        "body_html": (
            "<p>প্রিয় {full_name},</p>"
            "<p>আপনার সাম্প্রতিক পারিতোষিক স্লিপ দেখতে সুরক্ষিত লগইনে প্রবেশ করুন।</p>"
            "<p><a href='{click_url}'>লগইন করুন</a></p>"
        ),
    },
]

LANDING_PAGES = [
    {
        "name": "Generic Bank Login",
        "title": "Corporate Secure Portal",
        "body_html": "<p>Sign in with your corporate credentials to continue.</p>",
    },
    {
        "name": "IMPS Bonus Portal",
        "title": "Bonus & Payslip Portal",
        "body_html": "<p>Enter your credentials to download the authorised payslip.</p>",
    },
]


def seed(db: Session) -> None:
    settings = get_settings()

    existing_admin = db.scalar(
        select(models.User).where(models.User.username == settings.seed_admin_username)
    )
    if existing_admin is None:
        db.add_all(
            [
                models.User(
                    username="admin",
                    email=settings.seed_admin_email,
                    full_name="Platform Administrator",
                    hashed_password=hash_password(settings.seed_admin_password),
                    role="admin",
                ),
                models.User(
                    username="security",
                    email="security.officer@bank.example.com",
                    full_name="CISO Office",
                    hashed_password=hash_password("Security@12345"),
                    role="security",
                ),
                models.User(
                    username="hr",
                    email="hr.admin@bank.example.com",
                    full_name="HR Compliance",
                    hashed_password=hash_password("HR@12345678"),
                    role="hr",
                ),
                models.User(
                    username="auditor",
                    email="internal.audit@bank.example.com",
                    full_name="Internal Audit",
                    hashed_password=hash_password("Audit@12345"),
                    role="auditor",
                ),
            ]
        )
        db.flush()

    if db.scalar(select(models.Employee).limit(1)) is None:
        for code, name, email, phone, branch, division, grade, weight in EMPLOYEES:
            emp = models.Employee(
                employee_code=code,
                full_name=name,
                email=email,
                phone=phone,
                branch=branch,
                division=division,
                job_grade=grade,
                risk_weight=weight,
            )
            db.add(emp)
            db.flush()
            db.add(models.ConsentRecord(employee_id=emp.id))
        db.flush()

    if db.scalar(select(models.EmailTemplate).limit(1)) is None:
        for t in EMAIL_TEMPLATES:
            db.add(models.EmailTemplate(**t))
        for p in LANDING_PAGES:
            db.add(models.LandingPage(**p))
        db.flush()

    if db.scalar(select(models.Campaign).limit(1)) is None:
        admin = db.scalar(select(models.User).where(models.User.username == "admin"))
        temp_en = db.scalar(
            select(models.EmailTemplate).where(
                models.EmailTemplate.language == "en"
            )
        )
        landing = db.scalar(select(models.LandingPage).limit(1))

        campaign = models.Campaign(
            name="Q3 Password-Expiry Simulation",
            vector="email",
            status="approved",
            branches=json.dumps([]),
            divisions=json.dumps([]),
            created_by=admin.id if admin else 1,
        )
        db.add(campaign)
        db.flush()
        db.add(
            models.CampaignVariant(
                campaign_id=campaign.id,
                name="en-banked",
                weight=1,
                email_template_id=temp_en.id if temp_en else None,
                landing_page_id=landing.id if landing else None,
            )
        )
        db.flush()

        employees = db.scalars(select(models.Employee)).all()
        for emp in employees:
            token = new_token()
            db.add(
                models.Delivery(
                    campaign_id=campaign.id,
                    variant_id=1,
                    employee_id=emp.id,
                    token=token,
                    status="sent",
                    sent_at=datetime.utcnow(),
                )
            )
            db.add(
                models.Event(
                    delivery_id=0,
                    employee_id=emp.id,
                    campaign_id=campaign.id,
                    event_type="sent",
                    payload="seeded",
                )
            )
        db.commit()

    if db.scalar(select(models.Training).limit(1)) is None:
        employees = db.scalars(select(models.Employee)).all()
        for emp in employees[:5]:
            db.add(
                models.Training(
                    employee_id=emp.id,
                    title="Phishing101 - Spot the Lure",
                    completed=True,
                    score=85,
                )
            )
        db.commit()

    # Fix seeded event delivery references
    ok_deliveries = {
        d.employee_id: d.id
        for d in db.scalars(select(models.Delivery)).all()
    }
    for event in db.scalars(
        select(models.Event).where(models.Event.delivery_id == 0)
    ).all():
        delivery_id = ok_deliveries.get(event.employee_id)
        if delivery_id:
            event.delivery_id = delivery_id
    db.commit()


def init_db() -> None:
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed(db)
