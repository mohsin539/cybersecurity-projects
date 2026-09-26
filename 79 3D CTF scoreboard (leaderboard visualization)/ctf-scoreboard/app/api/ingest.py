"""Platform webhook ingest.

The signature is computed over the raw request bytes exactly as received. The
body is never re-serialised before verification, because a single byte of
re-encoding difference would silently invalidate every signature (SEC-EXT-02).
Replays outside the window and duplicate deliveries are handled explicitly, and
anything that fails validation is quarantined rather than dropped.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ..eventlog import iso, utcnow
from ..security import WebhookError, resolve_webhook_client, verify_webhook_signature
from ..service import SYSTEM, ServiceError

router = APIRouter(prefix="/api/webhooks", tags=["ingest"])

ALLOWED_FIELDS = {"type", "team", "challenge", "occurred_at", "event", "id", "value"}
VALID_TYPES = {"solve.recorded", "ping"}


@router.post("/ctf")
async def receive(request: Request) -> JSONResponse:
    service = request.app.state.service
    hub = request.app.state.hub
    raw = await request.body()

    client_id = request.headers.get("x-client-id", "")
    timestamp = request.headers.get("x-timestamp", "")
    signature = request.headers.get("x-signature", "")

    with service.db.read() as conn:
        client = resolve_webhook_client(conn, client_id)

    if not client:
        return _reject(
            service,
            "webhook.rejected",
            "unknown or inactive client",
            {"client_id": client_id},
            status_code=401,
        )

    try:
        verify_webhook_signature(
            raw,
            client_id=client_id,
            timestamp=timestamp,
            signature=signature,
            secret=client["key_secret"],
            window_seconds=service.settings.webhook_replay_window_seconds,
        )
    except WebhookError as exc:
        action = "webhook.replay.detected" if exc.code == "replay_window" else "webhook.rejected"
        return _reject(service, action, exc.detail, {"client_id": client_id, "code": exc.code}, exc.status_code)

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _quarantine(service, "malformed JSON body", raw.decode("utf-8", "replace"), client_id)

    if not isinstance(payload, dict):
        return _quarantine(service, "body must be a JSON object", json.dumps(payload)[:2000], client_id)

    unknown = set(payload) - ALLOWED_FIELDS
    if unknown:
        return _quarantine(
            service, f"unknown properties rejected: {sorted(unknown)}", json.dumps(payload)[:2000], client_id
        )

    event_type = str(payload.get("type", ""))
    if event_type not in VALID_TYPES:
        return _quarantine(service, f"unsupported event type '{event_type}'", json.dumps(payload)[:2000], client_id)

    if event_type == "ping":
        with service.db.write() as conn:
            service.auditlog.record(
                conn,
                action="webhook.received",
                actor_type="service",
                actor_id=client_id,
                resource_type="webhook",
                severity="info",
                context={"type": "ping"},
            )
        return JSONResponse({"status": "pong", "server_time": iso(utcnow())})

    team = str(payload.get("team", ""))
    challenge = str(payload.get("challenge", ""))
    if not team or not challenge:
        return _quarantine(service, "team and challenge are required", json.dumps(payload)[:2000], client_id)

    idempotency_key = str(payload.get("id") or "") or None
    try:
        with service.db.write() as conn:
            slug = payload.get("event") or service.event_slug(conn)
            result = service.record_solve(
                conn,
                team=team,
                challenge=challenge,
                event_slug=slug,
                source=f"webhook:{client_id}",
                idempotency_key=idempotency_key,
            )
            board = service.leaderboard(conn, service.event_slug(conn))
    except ServiceError as exc:
        if exc.code in {"already_solved", "unknown_team", "unknown_challenge", "challenge_retired", "event_ended", "after_freeze"}:
            with service.db.write() as conn:
                service.auditlog.record(
                    conn,
                    action="webhook.received",
                    actor_type="service",
                    actor_id=client_id,
                    resource_type="webhook",
                    outcome="failure",
                    severity="warning",
                    context={"error": exc.code, "team": team, "challenge": challenge},
                )
            status_code = 200 if exc.code == "already_solved" else 422
            return JSONResponse({"status": "rejected", "error": exc.code, "detail": exc.message}, status_code=status_code)
        return _quarantine(service, exc.message, json.dumps(payload)[:2000], client_id)

    hub.publish({"type": "board", "id": board["last_seq"], "board": board, "reason": "solve"})
    hub.publish(
        {
            "type": "solve",
            "id": result["seq"],
            "team": result["team"],
            "challenge": result["challenge"],
            "points": result["points"],
            "first_blood": result["first_blood"],
            "by": f"webhook:{client_id}",
        }
    )
    return JSONResponse(
        {
            "status": "accepted",
            "seq": result["seq"],
            "points": result["points"],
            "first_blood": result["first_blood"],
            # A redelivery of an id the platform has already applied is
            # acknowledged, not re-applied; the sender is told which it was.
            "idempotent_replay": bool(result.get("idempotent_replay")),
        },
        status_code=202,
    )


def _reject(service, action: str, detail: str, context: dict[str, Any], status_code: int = 401) -> JSONResponse:
    with service.db.write() as conn:
        try:
            slug = service.event_slug(conn)
        except ServiceError:
            slug = None
        service.auditlog.record(
            conn,
            action=action,
            actor_type="service",
            actor_id=str(context.get("client_id", "unknown"))[:64],
            resource_type="webhook",
            outcome="denied",
            severity="warning",
            event_slug=slug,
            context=context,
        )
    return JSONResponse({"status": "rejected", "detail": detail}, status_code=status_code)


def _quarantine(service, reason: str, raw: str, client_id: str) -> JSONResponse:
    """Dead-letter a poison event: never silently dropped, always owned (T-DER-12)."""
    with service.db.write() as conn:
        conn.execute(
            "INSERT INTO dead_letters (received_at, source, reason, payload, owner) VALUES (?,?,?,?,?)",
            (iso(utcnow()), f"webhook:{client_id}", reason, raw[:8000], "backend-oncall"),
        )
        try:
            slug = service.event_slug(conn)
        except ServiceError:
            slug = None
        service.auditlog.record(
            conn,
            action="webhook.rejected",
            actor_type="service",
            actor_id=client_id[:64] or "unknown",
            resource_type="webhook",
            outcome="failure",
            severity="critical",
            event_slug=slug,
            context={"reason": reason, "quarantined": True},
        )
    return JSONResponse({"status": "quarantined", "reason": reason}, status_code=422)
