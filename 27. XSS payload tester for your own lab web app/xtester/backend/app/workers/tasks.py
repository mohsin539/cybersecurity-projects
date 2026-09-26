"""Celery task(s) that run scans off the API process."""

from __future__ import annotations

import logging

from app.db.session import SessionLocal
from app.db.models import Scan, ScanStatus
from app.services.scanner_service import ScanPolicyError, run_scan_sync
from app.security.audit import audit
from app.workers.celery_app import celery_app

logger = logging.getLogger("xtester.tasks")


@celery_app.task(name="xtester.process_scan", bind=True, serializer="json")
def process_scan(self, scan_id: str) -> dict:
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            audit.record("scan.process", actor="system", outcome="failure", resource=scan_id,
                         details={"reason": "scan not found"})
            return {"ok": False, "scan_id": scan_id, "error": "not found"}
        run_scan_sync(scan, db)
        audit.record("scan.process", actor="system", outcome="success", resource=scan_id,
                     details={"url": scan.scan_url})
        return {"ok": True, "scan_id": scan_id}
    except ScanPolicyError as exc:
        db.rollback()
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = ScanStatus.failed
            scan.error = str(exc)
            scan.finished_at = None
            db.add(scan)
            db.commit()
        audit.record("scan.process", actor="system", outcome="failure", resource=scan_id,
                     details={"reason": str(exc)}, severity="warning")
        return {"ok": False, "scan_id": scan_id, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        logger.exception("scan %s failed", scan_id)
        scan = db.get(Scan, scan_id)
        if scan:
            scan.status = ScanStatus.failed
            scan.error = f"{type(exc).__name__}: {exc}"
            scan.finished_at = None
            db.add(scan)
            db.commit()
        audit.record("scan.process", actor="system", outcome="failure", resource=scan_id,
                     details={"reason": type(exc).__name__}, severity="critical")
        return {"ok": False, "scan_id": scan_id, "error": type(exc).__name__}
    finally:
        db.close()