"""Beacon collector for payloads.

Purpose: a payload that reached an executing script beacons back to
`/api/collect/<scan_id>/<candidate_id>` (as an Image GET or fetch POST,
cross-origin on purpose). Recording a hit is what lets the scanner
definitively classify a vector as EXECUTED.

Exposure note: this endpoint is intentionally unauthenticated (the lab
page carries no credentials). The blast radius is controlled by the
host allowlist at scan time plus network segmentation in the deployment
(see docker-compose). It is still rate-limited and audited.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status

from app.engine.detection import memory_registry
from app.security.audit import audit
from app.security.ratelimit import enforce_api_limit

router = APIRouter(prefix="/api/collect", tags=["collector"])


def _record(scan_id: str, candidate_id: str, request: Request) -> dict:
    if len(scan_id) > 80 or len(candidate_id) > 80:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="bad id")
    try:
        from app.config import settings

        if settings.celery_task_always_eager or settings.app_env != "production":
            registry: object = memory_registry
        else:
            from redis import Redis

            from app.engine.detection import RedisBeaconRegistry

            registry = RedisBeaconRegistry(Redis.from_url(settings.celery_broker_url))
    except Exception:  # noqa: BLE001
        registry = memory_registry
    registry.record(scan_id, candidate_id)
    audit.record("collect.hit", actor="lab-page", actor_type="system", resource=scan_id,
                 ip=request.client.host if request.client else None, severity="info")
    return {"ok": True}


@router.get("/{scan_id}/{candidate_id}")
def collect_get(scan_id: str, candidate_id: str, request: Request):
    enforce_api_limit(request, f"collect:{scan_id}")
    return _record(scan_id, candidate_id, request)


@router.post("/{scan_id}/{candidate_id}")
async def collect_post(scan_id: str, candidate_id: str, request: Request):
    enforce_api_limit(request, f"collect:{scan_id}")
    return _record(scan_id, candidate_id, request)