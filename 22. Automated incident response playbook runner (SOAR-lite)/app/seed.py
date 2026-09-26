"""Seed initial data: admin user, sample playbooks, sample connectors.

Runs once at startup if the `users` table is empty.
"""
from __future__ import annotations

import datetime as dt
import logging
import uuid

from app.config import settings
from app.core.security import hash_password
from app.db.base import SessionLocal
from app.db.models import Connector, Playbook, User

log = logging.getLogger("soarlite.seed")


DEFAULT_PLAYBOOKS = [
    {
        "key": "pb-phishing-generic",
        "name": "Generic Phishing Email Response",
        "description": "Standard playbook for phishing reports. Enriches sender, quarantines, notifies victims, opens ticket.",
        "trigger": ["category == 'phishing'"],
        "spec": {
            "steps": [
                {"id": "enrich", "type": "enrichment", "action": "simulator.enrich_ip",
                 "args": {"value": "sender_ip"}, "retries": 2},
                {"id": "contain", "type": "containment", "action": "simulator.block_sender",
                 "args": {"value": "sender_email"}, "run_after": ["enrich"],
                 "retries": 1},
                {"id": "notify_soc", "type": "notification", "action": "simulator.notify",
                 "args": {"message": "Phishing alert auto-contained", "channel": "#soc"}},
                {"id": "approval_keep", "type": "approval",
                 "reason": "Confirm long-term containment for this sender (4-eyes principle)",
                 "run_after": ["contain"]},
                {"id": "open_ticket", "type": "ticket", "action": "simulator.open_ticket",
                 "args": {"message": "Phishing incident auto-filed"},
                 "run_after": ["notify_soc"]},
                {"id": "evidence_collect", "type": "evidence",
                 "args": {"source": "raw_alert"},
                 "run_after": ["open_ticket"]},
            ]
        },
        "compensations": [
            {"when_step": "contain", "action": "simulator.unblock_sender", "args": {"value": "sender_email"}}
        ],
        "risk": "medium",
        "status": "published",
    },
    {
        "key": "pb-brute-force",
        "name": "Brute Force / Account Lockout Response",
        "description": "Contain compromised accounts, revoke sessions, enforce password reset.",
        "trigger": ["category == 'auth' and severity >= 4"],
        "spec": {
            "steps": [
                {"id": "disable_user", "type": "containment", "action": "simulator.disable_user",
                 "args": {"value": "compromised_user"}, "retries": 1},
                {"id": "revoke_session", "type": "remediation", "action": "simulator.revoke_session",
                 "args": {"value": "compromised_user"}, "run_after": ["disable_user"]},
                {"id": "reset_password", "type": "remediation", "action": "simulator.reset_password",
                 "args": {"value": "compromised_user"}, "run_after": ["revoke_session"]},
                {"id": "notify_user", "type": "notification", "action": "simulator.notify",
                 "args": {"message": "Your account has been temporarily disabled due to suspicious login activity.",
                          "channel": "email"}},
                {"id": "approval_restore", "type": "approval",
                 "reason": "Confirm re-enabling the compromised account",
                 "run_after": ["reset_password"]},
                {"id": "restore", "type": "remediation", "action": "simulator.restore",
                 "args": {"value": "compromised_user"},
                 "run_after": ["approval_restore", "reset_password"]},
            ]
        },
        "risk": "high",
        "status": "published",
    },
    {
        "key": "pb-malware-detected",
        "name": "Malware / EDR Alert",
        "description": "Isolate endpoint, collect memory, reset password, open SOC ticket.",
        "trigger": ["category == 'malware' and severity >= 3"],
        "spec": {
            "steps": [
                {"id": "isolate", "type": "containment", "action": "simulator.isolate",
                 "args": {"value": "endpoint_host"}},
                {"id": "enrich_hash", "type": "enrichment", "action": "simulator.enrich_hash",
                 "args": {"value": "file_hash"}, "retries": 1},
                {"id": "evidence_memory", "type": "evidence", "run_after": ["isolate"]},
                {"id": "notify", "type": "notification", "action": "simulator.notify",
                 "args": {"message": "Malware alert - endpoint isolated", "channel": "#soc"}},
                {"id": "open_ticket", "type": "ticket", "action": "simulator.open_ticket",
                 "args": {"message": "Malware incident auto-filed"}, "run_after": ["notify"]},
            ]
        },
        "risk": "critical",
        "status": "published",
    },
]


DEFAULT_CONNECTORS = [
    {
        "name": "simulator",
        "conn_type": "simulator",
        "description": "Built-in simulation connector for demos, testing and dry-runs",
        "enabled": True,
    },
    {
        "name": "crowdstrike",
        "conn_type": "generic_http",
        "base_url": "https://api.crowdstrike.com",
        "auth_type": "header_token",
        "auth_secret_ref": "",
        "enabled": False,
        "description": "CrowdStrike Falcon API (configure base_url and vault secret before enabling)",
    },
    {
        "name": "virustotal",
        "conn_type": "generic_http",
        "base_url": "https://www.virustotal.com/api/v3",
        "auth_type": "header_token",
        "auth_secret_ref": "",
        "enabled": False,
        "description": "VirusTotal enrichment (configure API key in vault as virustotal_apikey)",
    },
    {
        "name": "ms_defender",
        "conn_type": "generic_http",
        "base_url": "https://security.microsoft.com/api/v1.0",
        "auth_type": "header_token",
        "auth_secret_ref": "",
        "enabled": False,
        "description": "Microsoft Defender for Endpoint",
    },
    {
        "name": "slack_soc",
        "conn_type": "slack",
        "base_url": "",
        "auth_type": "header_token",
        "auth_secret_ref": "",
        "enabled": False,
        "description": "Slack webhook (set base_url to your webhook URL)",
    },
]


def seed() -> None:
    db = SessionLocal()
    try:
        if db.query(User).first() is None:
            admin_user = User(
                username=settings.admin_username,
                email=settings.admin_email,
                password_hash=hash_password(settings.admin_password),
                role="admin",
                must_change_password=settings.admin_must_change_password,
                is_active=True,
            )
            db.add(admin_user)
            db.commit()
            log.info("seeded admin user: %s", settings.admin_username)

            # default read-only viewer for API demo

            demo = User(
                username="analyst1",
                email="analyst1@soarlite.local",
                password_hash=hash_password("analyst1Pass!"),
                role="analyst",
                must_change_password=False,
                is_active=True,
            )
            db.add(demo)
            db.commit()
            log.info("seeded analyst user: analyst1")

        for pb_data in DEFAULT_PLAYBOOKS:
            exists = db.query(Playbook).filter(
                Playbook.key == pb_data["key"], Playbook.version == 1
            ).first()
            if not exists:
                db.add(Playbook(**pb_data, version=1))
        db.commit()
        log.info("seeded sample playbooks")

        for conn_data in DEFAULT_CONNECTORS:
            name = conn_data["name"]
            exists = db.query(Connector).filter(Connector.name == name).first()
            if not exists:
                conn_cols = {c.name for c in Connector.__table__.columns}
                safe = {k: v for k, v in conn_data.items() if k in conn_cols}
                safe.setdefault("extra", dict.__getitem__(conn_data, "description") if "description" in conn_data else {})
                db.add(Connector(**safe))
        db.commit()
        log.info("seeded sample connectors")

    finally:
        db.close()

