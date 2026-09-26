"""Assets & scanner ingestion endpoints."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..database import naive_utcnow

from ..database import get_db
from ..models import Asset, ScanResult, User
from ..security import audit, client_ip, require

router = APIRouter(prefix="/assets", tags=["assets"])


@router.get("")
def list_assets(db: Session = Depends(get_db), _: User = Depends(require("dashboard:read"))):
    assets = []
    for a in db.query(Asset).order_by(Asset.name).all():
        open_findings = db.query(ScanResult).filter(
            ScanResult.asset_id == a.id, ScanResult.status == "OPEN").count()
        assets.append({
            "id": a.id, "name": a.name, "asset_type": a.asset_type,
            "environment": a.environment, "classification": a.classification,
            "owner": a.owner, "criticality": a.criticality,
            "discovered_by": a.discovered_by, "open_findings": open_findings,
        })
    return assets


@router.post("")
def create_asset(payload: dict, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require("asset:write"))):
    asset = Asset(
        name=payload["name"], asset_type=payload.get("asset_type", "WEB_APP"),
        environment=payload.get("environment", "PRODUCTION"),
        classification=payload.get("classification", "INTERNAL"),
        owner=payload.get("owner"), criticality=float(payload.get("criticality", 3)),
        discovered_by=payload.get("discovered_by", "MANUAL"),
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    audit(db, user.username, user.role, "ASSET_CREATE", "ASSET", asset.id,
          {"name": asset.name, "classification": asset.classification}, client_ip(request))
    return {"id": asset.id, "name": asset.name}


@router.post("/scans/ingest")
def ingest_scans(payload: dict, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require("assess:write"))):
    """Batch ingestion from scanners (ZAP/Nessus/Trivy/Checkov...)."""
    count = 0
    for item in payload.get("findings", []):
        asset = None
        if item.get("asset_id"):
            asset = db.query(Asset).filter(Asset.id == item["asset_id"]).first()
        if not asset and item.get("asset_name"):
            asset = (db.query(Asset).filter(Asset.name == item["asset_name"]).first()
                     or Asset(name=item["asset_name"], discovered_by=item.get("scanner", "MANUAL")))
            db.add(asset)
            db.flush()
        finding = ScanResult(
            asset_id=asset.id if asset else None,
            scanner=item.get("scanner", "MANUAL"),
            finding_type=item.get("finding_type", "DAST"),
            title=item.get("title", "Finding"),
            severity=item.get("severity", "LOW"),
            cvss=float(item.get("cvss", 0)),
            status=item.get("status", "OPEN"),
            raw=item.get("raw", {}),
            scanned_at=naive_utcnow(),
        )
        db.add(finding)
        count += 1
    db.commit()
    audit(db, user.username, user.role, "SCANS_INGEST", "SCAN_RESULT", None,
          {"count": count, "scanner": payload.get("source", "batch")}, client_ip(request))
    return {"ingested": count}


@router.get("/findings")
def list_findings(severity: str = None, status: str = None, db: Session = Depends(get_db),
                  _: User = Depends(require("dashboard:read"))):
    q = db.query(ScanResult)
    if severity:
        q = q.filter(ScanResult.severity == severity)
    if status:
        q = q.filter(ScanResult.status == status)
    out = []
    for s in q.order_by(ScanResult.scanned_at.desc()).limit(300).all():
        out.append({
            "id": s.id, "asset": s.asset.name if s.asset else "", "scanner": s.scanner,
            "finding_type": s.finding_type, "title": s.title, "severity": s.severity,
            "cvss": s.cvss, "status": s.status, "scanned_at": s.scanned_at.isoformat(),
        })
    return out