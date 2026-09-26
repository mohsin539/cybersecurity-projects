"""Scan lifecycle API: create, list, detail, report download."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.api.schemas import CreateScanRequest, FindingOut, ScanDetail, ScanOut
from app.config import settings
from app.db.models import Finding, Report, Scan, ScanStatus, Target
from app.db.session import get_db
from app.security.audit import audit
from app.security.dependencies import Principal, client_ip, get_current_user
from app.security.ratelimit import enforce_scan_quota
from app.services.scanner_service import ScanPolicyError, validate_scan_url

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _dispatch(scan_id: str) -> None:
    if settings.celery_task_always_eager:
        import threading

        from app.workers.tasks import process_scan

        def _run() -> None:
            process_scan(scan_id)

        threading.Thread(target=_run, daemon=True).start()
        return
    from app.workers.tasks import process_scan

    process_scan.delay(scan_id)


@router.post("", status_code=status.HTTP_201_CREATED, response_model=ScanOut)
def create_scan(
    body: CreateScanRequest,
    request: Request,
    principal: Principal = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    principal.require("engineer", "admin")
    enforce_scan_quota(principal.username)

    try:
        validate_scan_url(body.url)
    except ScanPolicyError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))

    target = db.query(Target).filter(Target.base_url == body.url).first()
    scan = Scan(
        owner_id=principal.user.id,
        target_id=target.id if target else None,
        scan_url=body.url,
        context=body.context if body.context != "auto" else "auto",
        status=ScanStatus.queued,
    )
    db.add(scan)
    db.commit()

    audit.record(
        "scan.create",
        actor=principal.username,
        outcome="success",
        resource=scan.id,
        ip=client_ip(request),
        details={"url": body.url},
    )

    _dispatch(scan.id)
    return ScanOut.model_validate(scan)


@router.get("", response_model=list[ScanOut])
def list_scans(
    limit: int = 50,
    offset: int = 0,
    principal: Principal = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(Scan).order_by(Scan.created_at.desc())
    if principal.role == "viewer":
        q = q.filter(Scan.owner_id == principal.user.id)
    rows = q.limit(min(limit, 200)).offset(max(offset, 0)).all()
    return [ScanOut.model_validate(s) for s in rows]


@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan(
    scan_id: str,
    principal: Principal = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    if principal.role == "viewer" and scan.owner_id != principal.user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id)
        .order_by(Finding.cvss_score.desc())
        .all()
    )
    out = ScanDetail.model_validate(scan)
    out.owner = scan.owner.username if scan.owner else None
    out.findings = [FindingOut.model_validate(f) for f in findings]
    return out


@router.get("/{scan_id}/report", response_class=JSONResponse)
def download_report(
    scan_id: str,
    principal: Principal = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    if principal.role == "viewer" and scan.owner_id != principal.user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
    report = db.query(Report).filter(Report.scan_id == scan_id).first()
    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id)
        .order_by(Finding.cvss_score.desc())
        .all()
    )
    body = {
        "scan_id": scan.id,
        "scan_url": scan.scan_url,
        "context": scan.context,
        "status": scan.status,
        "summary": json.loads(report.summary) if report and report.summary else {},
        "csp_recommendation": report.csp_recommendation if report else None,
        "findings_count": len(findings),
        "findings": [
            {
                "vector": f.vector_name,
                "category": f.vector_category,
                "context": f.context,
                "evasion": f.evasion,
                "severity": f.severity,
                "cvss_score": f.cvss_score,
                "verdict": f.verdict,
                "repro_url": f.url,
                "payload": f.payload,
                "evidence": f.evidence,
                "remediation": f.remediation,
            }
            for f in findings
        ],
    }
    return JSONResponse(
        content=body,
        headers={"Content-Disposition": f'attachment; filename="scan-{scan.id}.json"'},
    )