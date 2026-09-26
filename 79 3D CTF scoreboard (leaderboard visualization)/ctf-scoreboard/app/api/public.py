"""Public read-only API: board, stream, teams, challenges, reports, health."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse

from ..eventlog import iso, utcnow
from ..realtime import sse_encode
from ..service import ScoreboardService, ServiceError, get_service
from ..security import get_db_conn

router = APIRouter(tags=["public"])


def service_of(request: Request) -> ScoreboardService:
    return request.app.state.service


def hub_of(request: Request):
    return request.app.state.hub


@router.get("/api/health")
def health(request: Request) -> dict[str, Any]:
    service = service_of(request)
    with service.db.read() as conn:
        try:
            slug = service.event_slug(conn)
        except ServiceError:
            return {"status": "starting", "event": None}
        report = service.integrity_report(conn, slug)
    return {
        "status": "ok" if report["event_chain"].get("ok") else "degraded",
        "event": slug,
        "head_seq": report["event_chain"].get("checked"),
        "chain_ok": report["event_chain"].get("ok"),
        "audit_chain_ok": report["audit_chain"].get("ok"),
        "seals": report["seal_count"],
        "stream": hub_of(request).status(),
    }


@router.get("/api/leaderboard")
def leaderboard(
    request: Request,
    event: str | None = Query(default=None, description="Event slug; defaults to the current event"),
    as_of: str | None = Query(default=None, description="ISO timestamp for deterministic replay"),
    conn=Depends(get_db_conn),
) -> dict[str, Any]:
    service = service_of(request)
    try:
        slug = event or service.event_slug(conn)
        parsed = datetime.fromisoformat(as_of.replace("Z", "+00:00")) if as_of else None
        return service.leaderboard(conn, slug, as_of=parsed)
    except ServiceError as exc:
        raise


@router.get("/api/leaderboard.csv", response_class=PlainTextResponse)
def leaderboard_csv(request: Request, event: str | None = None, conn=Depends(get_db_conn)) -> Response:
    service = service_of(request)
    try:
        slug = event or service.event_slug(conn)
        body = service.leaderboard_csv(conn, slug)
    except ServiceError as exc:
        raise
    return PlainTextResponse(
        body,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{slug}-leaderboard.csv"'},
    )


@router.get("/api/report.json")
def report_json(request: Request, event: str | None = None, conn=Depends(get_db_conn)) -> Response:
    service = service_of(request)
    try:
        slug = event or service.event_slug(conn)
        manifest = service.report_manifest(conn, slug)
    except ServiceError as exc:
        raise
    return Response(
        manifest["body"],
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{manifest["filename"]}"',
            "X-Content-SHA256": manifest["sha256"],
        },
    )


@router.get("/api/teams/{team_slug}")
def team_detail(team_slug: str, request: Request, event: str | None = None, conn=Depends(get_db_conn)) -> dict[str, Any]:
    service = service_of(request)
    try:
        slug = event or service.event_slug(conn)
        return service.team_history(conn, slug, team_slug)
    except ServiceError as exc:
        raise


@router.get("/api/invariants")
def invariants(request: Request, event: str | None = None, conn=Depends(get_db_conn)) -> dict[str, Any]:
    service = service_of(request)
    try:
        slug = event or service.event_slug(conn)
        return service.evaluate_invariants(conn, slug)
    except ServiceError as exc:
        raise


@router.get("/api/integrity")
def integrity(request: Request, event: str | None = None, conn=Depends(get_db_conn)) -> dict[str, Any]:
    service = service_of(request)
    try:
        slug = event or service.event_slug(conn)
        report = service.integrity_report(conn, slug)
        report["stream"] = hub_of(request).status()
        return report
    except ServiceError as exc:
        raise


@router.get("/api/audit")
def audit(
    request: Request,
    event: str | None = None,
    action: str | None = None,
    actor: str | None = None,
    outcome: str | None = None,
    limit: int = Query(default=50, le=500),
    conn=Depends(get_db_conn),
) -> dict[str, Any]:
    service = service_of(request)
    with service.db.read() as conn2:
        try:
            slug = event or service.event_slug(conn2)
        except ServiceError:
            slug = None
        rows = service.auditlog.search(
            conn2, action=action, actor_id=actor, outcome=outcome, event_slug=slug, limit=limit
        )
    return {"records": rows, "count": len(rows)}


@router.get("/api/stream")
async def stream(request: Request) -> StreamingResponse:
    """Live leaderboard stream.

    Resume with the standard ``Last-Event-ID`` header. If the requested frame is
    older than the replay buffer, the stream opens with a ``resync`` frame so the
    client refetches a snapshot instead of silently showing stale data.
    """
    service = service_of(request)
    hub = hub_of(request)

    last_event_id: int | None = request.headers.get("last-event-id")
    header = request.headers.get("last-event-id")
    if header is None and request.query_params.get("last_event_id"):
        header = request.query_params["last_event_id"]
    if header is not None:
        try:
            last_event_id = int(header)
        except ValueError:
            last_event_id = None

    async def generator():
        oldest = hub.replay[0].get("id") if hub.replay else None
        if last_event_id is not None and oldest is not None and last_event_id < oldest - 1:
            yield sse_encode({"type": "resync", "reason": "last_event_id outside the replay buffer"})
        else:
            with service.db.read() as conn:
                try:
                    slug = service.event_slug(conn)
                except ServiceError:
                    slug = None
                if slug:
                    yield sse_encode(
                        {
                            "type": "snapshot",
                            "id": service.eventlog.head(conn)[0],
                            "board": service.leaderboard(conn, slug),
                        }
                    )
        async for frame in hub.subscribe(last_event_id):
            yield sse_encode(frame)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/api/config")
def public_config(request: Request) -> dict[str, Any]:
    service = service_of(request)
    s = service.settings
    return {
        "app": s.app_name,
        "version": s.version,
        "scoring_model": service.model.describe(),
        "purifier_window_seconds": s.purifier_window_seconds,
        "sse_heartbeat_seconds": s.sse_heartbeat_seconds,
        "simulator_enabled": s.simulator_enabled,
        "server_time": iso(utcnow()),
    }
