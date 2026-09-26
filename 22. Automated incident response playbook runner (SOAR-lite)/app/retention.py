"""Data retention / evidence purger.

Run via:  python -m app.retention [--alert-days 90] [--case-days 90] [--dry-run]
"""
from __future__ import annotations

import argparse
import datetime as dt
import logging
import os

from app.config import settings
from app.db.base import SessionLocal, init_db
from app.db.models import Alert, AuditEvent, Case

log = logging.getLogger("soarlite.retention")


def purge(db, *, alert_days: int = 0, case_days: int = 0, dry_run: bool = True) -> dict:
    stats = {"alerts": 0, "cases": 0, "evidence": 0}
    now = dt.datetime.utcnow()

    if alert_days > 0:
        cutoff = now - dt.timedelta(days=alert_days)
        rows = db.query(Alert).filter(Alert.created_at < cutoff, Alert.status.in_(["closed", "suppressed"])).all()
        log.info("matched %d old alerts (dry=%s)", len(rows), dry_run)
        stats["alerts"] = len(rows)
        if not dry_run:
            for r in rows:
                db.delete(r)
            db.commit()

    if case_days > 0:
        cutoff = now - dt.timedelta(days=case_days)
        cases = db.query(Case).filter(Case.closed_at.isnot(None), Case.closed_at < cutoff).all()
        log.info("matched %d old cases (dry=%s)", len(cases), dry_run)
        stats["cases"] = len(cases)
        if not dry_run:
            for c in cases:
                db.delete(c)
            db.commit()
    return stats


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOAR-Lite data retention purger")
    parser.add_argument("--alert-days", type=int, default=settings.alert_retention_days)
    parser.add_argument("--case-days", type=int, default=settings.case_retention_days)
    parser.add_argument("--dry-run", action="store_true", default=False)
    args = parser.parse_args()
    init_db()
    db = SessionLocal()
    result = purge(db, alert_days=args.alert_days, case_days=args.case_days, dry_run=args.dry_run)
    log.info("result=%s", result)
    print(result)