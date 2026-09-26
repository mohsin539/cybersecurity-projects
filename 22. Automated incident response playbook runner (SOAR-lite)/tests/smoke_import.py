"""Import smoke test — verifies the whole package graph loads and the worker
loop can boot against a throwaway in-memory DB. Run:  python tests/smoke_import.py
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.environ.setdefault("DATABASE_URL", "sqlite://")
os.environ.setdefault("SECRET_KEY", "smoke-test-secret")
os.environ.setdefault("ADMIN_PASSWORD", "Sm0keTest!Pass")
os.environ.setdefault("ENABLE_EMBEDDED_WORKER", "false")
os.environ.setdefault("CONNECTOR_EGRESS_ALLOWLIST", "0.0.0.0/0")
os.environ.setdefault("SECRETS_MASTER_KEY", "")
sys.path.insert(0, str(ROOT))

import app.main as main_mod  # noqa: E402
from app.db.base import init_db, db_session  # noqa: E402
from app.db.models import Base, User, Alert, Case  # noqa: E402
from app.core.security import hash_password, verify_password, create_access_token, decode_token  # noqa: E402
from app.core.audit import append_audit, verify_chain  # noqa: E402
from app.core.cipher import encrypt_secret, decrypt_secret  # noqa: E402
from app.core.rate_limit import check_rate_limit  # noqa: E402
from app.core.redact import redact_payload  # noqa: E402
from app.services import engine, connector_runtime, cases, ingestion, playbook_validator, expressions  # noqa: E402

app = main_mod.create_app()  # build FastAPI (no startup side effects until serve)

    from app.db.base import SessionLocal, init_db

    init_db()
    db = SessionLocal()
    from app.services.engine import start_run, tick
    from app.services.ingestion import create_alert
    from app.services.cases import open_case_for_alert

    payload = {
        "source": "e2e", "category": "phishing", "title": "smoke test alert",
        "severity": 9, "indicators": [{"type": "ipv4", "value": "198.51.100.20"}],
        "sender_email": "attacker@evil.example", "asset_id": "ws-001", "raw": {"alpha": 1},
    }
    alert = create_alert(db, payload)
    print("alert_id", alert.id, "severity", alert.severity, "redacted", alert.redacted)

    case = open_case_for_alert(db, alert)
    print("case_id", case.id, "phase", case.nist_phase, "status", case.status)

    from app.services.engine import start_playbook

    run = start_playbook(db, case.alert, case)
    print("run", run.id, "status", run.status)

    for i in range(10):
        stats = tick(db)
        if stats["completed"] or stats["awaiting"] or stats["failed"]:
            break

    print("final run status:", run.status)

print("SMOKE-OK")
