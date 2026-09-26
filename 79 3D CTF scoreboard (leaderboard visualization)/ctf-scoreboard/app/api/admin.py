"""Administrative API: authentication, referee operations, two-person adjustments.

Every mutating route writes an event *and* an audit record in the same
transaction, and every route refuses a client-computed score. Referees adjust
points through a propose/approve pair because a single human must never be able
to move a leaderboard on their own.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from ..security import (
    SESSION_COOKIE,
    authenticate,
    clear_session_cookie,
    cookie_token,
    create_session,
    destroy_session,
    ensure_user,
    mark_step_up,
    principal_for_token,
    require_admin,
    require_staff,
    require_step_up,
    require_user,
    set_session_cookie,
)
from ..service import Principal, ScoreboardService, ServiceError, get_service

router = APIRouter(prefix="/api", tags=["admin"])


def service_of(request: Request) -> ScoreboardService:
    return request.app.state.service


class LoginRequest(BaseModel):
    handle: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class StepUpRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class AdjustmentRequest(BaseModel):
    team: str = Field(min_length=1, max_length=120)
    delta: int
    reason: str = Field(min_length=10, max_length=500)


class DecisionRequest(BaseModel):
    approve: bool


class PhaseRequest(BaseModel):
    phase: str = Field(pattern="^(setup|live|frozen|ended)$")


class ChallengeToggle(BaseModel):
    active: bool


# ------------------------------------------------------------------ identity --
def _event_slug_or_none(service: ScoreboardService) -> str | None:
    """The current event slug, if the board already has one.

    Auth and audit-export records are not inherently event-scoped, but an
    operator looking at the trail for the live event must still be able to see
    them, so they are tagged with the current event when one exists.
    """
    try:
        with service.db.read() as conn:
            return service.event_slug(conn)
    except ServiceError:
        return None


def record_denial(
    service: ScoreboardService,
    *,
    action: str,
    actor_id: str,
    resource_type: str,
    context: dict[str, Any] | None = None,
    severity: str = "warning",
) -> None:
    """Commit a denial audit in its own transaction.

    Writing the record inside the same transaction that then raises would roll
    the evidence back with it, leaving a failed login or a rejected adjustment
    invisible to the audit trail (SEC-AUD-01). Denials are therefore always
    committed by a separate write, and the caller raises afterwards.
    """
    with service.db.write() as conn:
        service.auditlog.record(
            conn,
            action=action,
            actor_type="human",
            actor_id=actor_id,
            resource_type=resource_type,
            outcome="denied",
            severity=severity,
            event_slug=_event_slug_or_none(service),
            context=context or {},
        )


@router.post("/auth/login")
def login(payload: LoginRequest, request: Request, response: Response) -> dict[str, Any]:
    service = service_of(request)
    settings = service.settings
    handle = payload.handle.strip().lower()[:64]
    with service.db.write() as conn:
        principal, outcome = authenticate(conn, handle, payload.password)
        if principal is not None:
            token = create_session(
                conn, _user_row(conn, principal.id), settings, request.headers.get("user-agent", "")
            )
            service.auditlog.record(
                conn,
                action="security.login",
                actor_type="human",
                actor_id=principal.id,
                resource_type="session",
                severity="info",
                event_slug=_event_slug_or_none(service),
                context={"role": principal.role},
            )
    if principal is None:
        # A failed login proves nothing about who the caller is, so the record
        # must not claim a human identity: the attempted handle is
        # attacker-controlled input and is kept as context, not as an actor id
        # (INV-15).
        record_denial(
            service,
            action="security.login",
            actor_id="unauthenticated",
            resource_type="session",
            context={"attempted_handle": handle, "reason": outcome},
        )
        raise HTTPException(401, {"error": "invalid_credentials", "detail": "Invalid handle or password"})
    set_session_cookie(response, token, settings)
    return {"handle": principal.handle, "role": principal.role, "expires_in": settings.session_ttl_seconds}


def _user_row(conn, user_id: str):
    return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


@router.post("/auth/logout")
def logout(request: Request, response: Response) -> dict[str, Any]:
    service = service_of(request)
    token = cookie_token(request, service.settings)
    with service.db.write() as conn:
        if token:
            principal = principal_for_token(conn, token)
            destroy_session(conn, token)
            if principal:
                service.auditlog.record(
                    conn,
                    action="security.logout",
                    actor_type="human",
                    actor_id=principal.id,
                    resource_type="session",
                    event_slug=_event_slug_or_none(service),
                )
    clear_session_cookie(response, service.settings)
    return {"ok": True}


@router.get("/auth/me")
def me(request: Request) -> dict[str, Any]:
    service = service_of(request)
    token = cookie_token(request, service.settings)
    with service.db.read() as conn:
        principal = principal_for_token(conn, token)
        display_name = None
        if principal is not None:
            row = conn.execute("SELECT display_name FROM users WHERE id = ?", (principal.id,)).fetchone()
            display_name = row["display_name"] if row else principal.handle
    if principal is None:
        return {"authenticated": False}
    return {
        "authenticated": True,
        "handle": principal.handle,
        "display_name": display_name,
        "role": principal.role,
        "is_staff": principal.is_staff,
        "is_admin": principal.is_admin,
        "step_up": has_step_up_flag(request, service),
    }


def has_step_up_flag(request: Request, service: ScoreboardService) -> bool:
    from ..security import has_step_up

    with service.db.read() as conn:
        return has_step_up(conn, cookie_token(request, service.settings))


@router.post("/auth/step-up")
def step_up(payload: StepUpRequest, request: Request, response: Response, principal: Principal = Depends(require_staff)) -> dict[str, Any]:
    service = service_of(request)
    token = cookie_token(request, service.settings)
    with service.db.write() as conn:
        row = _user_row(conn, principal.id)
        verified, _ = authenticate(conn, row["handle"], payload.password)
        if verified is not None:
            mark_step_up(conn, token or "")
            service.auditlog.record(
                conn,
                action="security.step_up",
                actor_type="human",
                actor_id=principal.id,
                resource_type="session",
                event_slug=_event_slug_or_none(service),
                context={"window_minutes": 10},
            )
    if verified is None:
        record_denial(
            service,
            action="security.step_up",
            actor_id=principal.id,
            resource_type="session",
            context={"reason": "password_mismatch"},
        )
        raise HTTPException(401, {"error": "invalid_credentials", "detail": "Password verification failed"})
    return {"ok": True, "step_up_until": "10 minutes"}


# ---------------------------------------------------------------- operations --
@router.get("/admin/state")
def admin_state(request: Request, principal: Principal = Depends(require_staff)) -> dict[str, Any]:
    service = service_of(request)
    with service.db.read() as conn:
        slug = service.event_slug(conn)
        return {
            "event": service.event_meta(conn, slug),
            "pending_adjustments": service.pending_adjustments(conn, slug),
            "chain": service.integrity_report(conn, slug)["event_chain"],
            "invariants": service.evaluate_invariants(conn, slug)["invariants"],
        }


@router.post("/admin/phase")
def set_phase(payload: PhaseRequest, request: Request, principal: Principal = Depends(require_staff)) -> dict[str, Any]:
    service = service_of(request)
    hub = request.app.state.hub
    with service.db.write() as conn:
        try:
            result = service.set_phase(conn, phase=payload.phase, actor=principal)
            board = service.leaderboard(conn, service.event_slug(conn))
        except ServiceError as exc:
            failure = exc
            board = None
        else:
            failure = None
    if failure is not None:
        record_denial(
            service,
            action=f"event.{payload.phase}",
            actor_id=principal.id,
            resource_type="event",
            context={"error": failure.code},
        )
        raise failure
    hub.publish({"type": "board", "id": board["last_seq"], "board": board, "reason": "phase_change"})
    hub.publish({"type": "notice", "level": "info", "message": f"Event is now {payload.phase}"})
    return result


@router.post("/admin/challenges/{slug}/active")
def toggle_challenge(
    slug: str, payload: ChallengeToggle, request: Request, principal: Principal = Depends(require_step_up)
) -> dict[str, Any]:
    service = service_of(request)
    hub = request.app.state.hub
    with service.db.write() as conn:
        result = service.set_challenge_active(conn, slug=slug, active=payload.active, actor=principal)
        board = service.leaderboard(conn, service.event_slug(conn))
    hub.publish({"type": "board", "id": board["last_seq"], "board": board, "reason": "challenge_toggle"})
    return result


@router.post("/admin/adjustments")
def propose_adjustment(
    payload: AdjustmentRequest, request: Request, principal: Principal = Depends(require_staff)
) -> dict[str, Any]:
    service = service_of(request)
    hub = request.app.state.hub
    with service.db.write() as conn:
        try:
            result = service.propose_adjustment(
                conn, team=payload.team, delta=payload.delta, reason=payload.reason, actor=principal
            )
        except ServiceError as exc:
            failure = exc
            result = None
        else:
            failure = None
    if failure is not None:
        record_denial(
            service,
            action="score.adjust.propose",
            actor_id=principal.id,
            resource_type="score_adjustment",
            context={"team": payload.team, "delta": payload.delta, "error": failure.code},
        )
        raise failure
    hub.publish(
        {
            "type": "notice",
            "level": "warning",
            "message": f"Adjustment #{result['id']} proposed ({payload.delta:+d} for {payload.team}) — awaiting second approval",
        }
    )
    return result


@router.post("/admin/adjustments/{adjustment_id}/decision")
def decide_adjustment(
    adjustment_id: int, payload: DecisionRequest, request: Request, principal: Principal = Depends(require_staff)
) -> dict[str, Any]:
    service = service_of(request)
    hub = request.app.state.hub
    with service.db.write() as conn:
        try:
            result = service.decide_adjustment(
                conn, adjustment_id=adjustment_id, approve=payload.approve, actor=principal
            )
        except ServiceError as exc:
            failure = exc
            result = None
            board = None
        else:
            failure = None
    if failure is not None:
        record_denial(
            service,
            action="score.adjust.approve" if payload.approve else "score.adjust.reject",
            actor_id=principal.id,
            resource_type="score_adjustment",
            context={"adjustment_id": adjustment_id, "error": failure.code},
        )
        raise failure
    with service.db.read() as conn:
        board = service.leaderboard(conn, service.event_slug(conn))
    if payload.approve:
        hub.publish({"type": "board", "id": board["last_seq"], "board": board, "reason": "score_adjusted"})
    hub.publish(
        {
            "type": "notice",
            "level": "info" if payload.approve else "warning",
            "message": f"Adjustment #{adjustment_id} {'applied' if payload.approve else 'rejected'} by {principal.handle}",
        }
    )
    return result


@router.post("/admin/solves")
async def manual_solve(request: Request, principal: Principal = Depends(require_staff)) -> dict[str, Any]:
    """Record a solve from the referee console.

    The body is read as a raw dict and validated here rather than trusting a
    client-supplied score: points are always recomputed on the server
    (SEC-APP-03).
    """
    service = service_of(request)
    hub = request.app.state.hub
    payload = await await_json(request)
    team = str(payload.get("team", "")).strip()
    challenge = str(payload.get("challenge", "")).strip()
    if not team or not challenge:
        raise HTTPException(422, {"error": "invalid_request", "detail": "team and challenge are required"})
    with service.db.write() as conn:
        try:
            result = service.record_solve(
                conn,
                team=team,
                challenge=challenge,
                actor=principal,
                source="referee_console",
                idempotency_key=payload.get("idempotency_key"),
            )
        except ServiceError as exc:
            failure = exc
            result = None
            board = None
        else:
            failure = None
    if failure is not None:
        record_denial(
            service,
            action="solve.record",
            actor_id=principal.id,
            resource_type="solve",
            context={"team": team, "challenge": challenge, "error": failure.code},
        )
        raise failure
    with service.db.read() as conn:
        board = service.leaderboard(conn, service.event_slug(conn))
    hub.publish({"type": "board", "id": board["last_seq"], "board": board, "reason": "solve"})
    hub.publish(
        {
            "type": "solve",
            "id": result["seq"],
            "team": result["team"],
            "challenge": result["challenge"],
            "points": result["points"],
            "first_blood": result["first_blood"],
            "by": principal.handle,
        }
    )
    return result


async def await_json(request: Request) -> dict[str, Any]:
    try:
        body = await request.json()
    except Exception:
        return {}
    return body if isinstance(body, dict) else {}


@router.post("/admin/seal")
def force_seal(request: Request, principal: Principal = Depends(require_staff)) -> dict[str, Any]:
    service = service_of(request)
    with service.db.write() as conn:
        slug = service.event_slug(conn)
        result = service.force_seal(conn, slug)
    if not result:
        raise HTTPException(409, {"error": "nothing_to_seal", "detail": "All events are already sealed"})
    return result


@router.get("/admin/audit/export.csv", response_class=Response)
def export_audit(request: Request, principal: Principal = Depends(require_step_up)) -> Response:
    service = service_of(request)
    with service.db.read() as conn:
        slug = service.event_slug(conn)
        body = service.audit_csv(conn, slug)
    return Response(
        body,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{slug}-audit.csv"'},
    )
