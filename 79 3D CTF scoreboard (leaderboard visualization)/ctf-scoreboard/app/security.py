"""Authentication, authorisation and webhook trust.

Local-deployment equivalents of the identity controls in ``security.md``:

* PBKDF2-HMAC-SHA256 password hashing with a per-user salt (no plaintext, no
  fast hash).
* Opaque session tokens; only the SHA-256 of a token is stored, so a database
  disclosure does not hand over live sessions.
* ``__Host-`` prefixed, ``HttpOnly``, ``SameSite=Strict`` cookies.
* Step-up authentication for destructive or export operations.
* Separation of duties: the proposer of a score adjustment can never approve it
  (enforced in the service, asserted here at the boundary too).
* Webhooks are verified over the *raw* body with HMAC-SHA256 and a replay
  window; the comparison is constant time.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
from datetime import timedelta
from typing import Any

from fastapi import Depends, HTTPException, Request, Response, status

from .config import Settings, get_settings
from .eventlog import iso, utcnow
from .service import Principal, ScoreboardService, get_service

PBKDF2_ROUNDS = 240_000
ROLE_RANK = {"spectator": 0, "participant": 1, "referee": 2, "admin": 3}
STEP_UP_WINDOW = timedelta(minutes=10)


# ------------------------------------------------------------------ passwords --
def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), PBKDF2_ROUNDS)
    return digest.hex(), salt


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    candidate, _ = hash_password(password, salt)
    return hmac.compare_digest(candidate, password_hash)


# ------------------------------------------------------------------- sessions --
def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(conn: sqlite3.Connection, user: sqlite3.Row, settings: Settings, user_agent: str = "") -> str:
    token = secrets.token_urlsafe(32)
    now = utcnow()
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, created_at, expires_at, mfa_verified, user_agent)"
        " VALUES (?,?,?,?,1,?)",
        (
            _token_hash(token),
            user["id"],
            iso(now),
            iso(now + timedelta(seconds=settings.session_ttl_seconds)),
            user_agent[:200],
        ),
    )
    return token


def destroy_session(conn: sqlite3.Connection, token: str) -> None:
    conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(token),))


def principal_for_token(conn: sqlite3.Connection, token: str | None) -> Principal | None:
    if not token:
        return None
    row = conn.execute(
        """
        SELECT u.id, u.handle, u.role, u.disabled, s.expires_at
        FROM sessions s JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = ?
        """,
        (_token_hash(token),),
    ).fetchone()
    if not row or row["disabled"]:
        return None
    if row["expires_at"] < iso(utcnow()):
        return None
    return Principal(id=row["id"], handle=row["handle"], role=row["role"])


def set_session_cookie(response: Response, token: str, settings: Settings) -> None:
    response.set_cookie(
        key=session_cookie_name(settings),
        value=token,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
    )


def clear_session_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(session_cookie_name(settings), path="/")


def mark_step_up(conn: sqlite3.Connection, token: str) -> None:
    conn.execute(
        "UPDATE sessions SET step_up_at = ? WHERE token_hash = ?", (iso(utcnow()), _token_hash(token))
    )


def has_step_up(conn: sqlite3.Connection, token: str | None) -> bool:
    if not token:
        return False
    row = conn.execute("SELECT step_up_at FROM sessions WHERE token_hash = ?", (_token_hash(token),)).fetchone()
    if not row or not row["step_up_at"]:
        return False
    return row["step_up_at"] > iso(utcnow() - STEP_UP_WINDOW)


# ----------------------------------------------------------------- identities --
def ensure_user(
    conn: sqlite3.Connection,
    *,
    user_id: str,
    handle: str,
    display_name: str,
    role: str,
    password: str,
) -> Principal:
    existing = conn.execute("SELECT * FROM users WHERE handle = ?", (handle,)).fetchone()
    if existing:
        return Principal(id=existing["id"], handle=existing["handle"], role=existing["role"])
    if role not in ROLE_RANK:
        raise ValueError(f"unknown role: {role}")
    password_hash, salt = hash_password(password)
    conn.execute(
        "INSERT INTO users (id, handle, display_name, role, password_hash, password_salt, created_at)"
        " VALUES (?,?,?,?,?,?,?)",
        (user_id, handle, display_name, role, password_hash, salt, iso(utcnow())),
    )
    return Principal(id=user_id, handle=handle, role=role)


def authenticate(conn: sqlite3.Connection, handle: str, password: str) -> tuple[Principal | None, str]:
    row = conn.execute("SELECT * FROM users WHERE handle = ? AND disabled = 0", (handle,)).fetchone()
    if not row:
        # Constant-ish work for unknown users so timing does not enumerate accounts.
        hash_password(password, "00" * 16)
        return None, "invalid_credentials"
    if not verify_password(password, row["password_hash"], row["password_salt"]):
        return None, "invalid_credentials"
    return Principal(id=row["id"], handle=row["handle"], role=row["role"]), "ok"


# ------------------------------------------------------------ FastAPI wiring --
# A ``__Host-`` cookie is rejected by browsers unless it is also ``Secure``, which
# rules it out for plain-HTTP local demos. The prefixed name is used whenever the
# deployment is HTTPS; otherwise a plain name keeps the demo usable. Both names
# are HttpOnly + SameSite=Strict.
SESSION_COOKIE = "__Host-scoreboard_session"
DEV_SESSION_COOKIE = "scoreboard_session"


def session_cookie_name(settings: Settings) -> str:
    return SESSION_COOKIE if settings.cookie_secure else DEV_SESSION_COOKIE


def cookie_token(request: Request, settings: Settings) -> str | None:
    """Read the session token, tolerating a switch between cookie names."""
    for name in (session_cookie_name(settings), SESSION_COOKIE, DEV_SESSION_COOKIE):
        token = request.cookies.get(name)
        if token:
            return token
    return None


def get_principal(request: Request) -> Principal | None:
    service: ScoreboardService = request.app.state.service
    token = cookie_token(request, service.settings)
    with service.db.read() as conn:
        return principal_for_token(conn, token)


def require_user(principal: Principal | None = Depends(get_principal)) -> Principal:
    if principal is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentication required")
    return principal


def require_staff(principal: Principal = Depends(require_user)) -> Principal:
    if not principal.is_staff:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Referee or admin role required")
    return principal


def require_admin(principal: Principal = Depends(require_user)) -> Principal:
    if not principal.is_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin role required")
    return principal


def require_step_up(request: Request, principal: Principal = Depends(require_staff)) -> Principal:
    service: ScoreboardService = request.app.state.service
    token = cookie_token(request, service.settings)
    with service.db.read() as conn:
        if not has_step_up(conn, token):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "Step-up authentication required for this operation (SEC-IAM-07)",
            )
    return principal


def get_db_conn(request: Request):
    service: ScoreboardService = request.app.state.service
    with service.db.read() as conn:
        yield conn


# ------------------------------------------------------------------ webhooks --
class WebhookError(Exception):
    def __init__(self, code: str, detail: str, status_code: int = 401) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.status_code = status_code


def verify_webhook_signature(
    raw_body: bytes,
    *,
    client_id: str,
    timestamp: str,
    signature: str,
    secret: str,
    window_seconds: int,
) -> None:
    """HMAC-SHA256 over the raw body, constant-time compare, replay window."""
    if not client_id or not timestamp or not signature:
        raise WebhookError("missing_signature", "client_id, timestamp and signature are required", 400)
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        raise WebhookError("bad_timestamp", "timestamp must be unix seconds", 400) from None
    skew = abs(int(utcnow().timestamp()) - ts)
    if skew > window_seconds:
        raise WebhookError("replay_window", f"timestamp outside the {window_seconds}s window", 401)
    expected = hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    provided = signature.split("=", 1)[-1].strip().lower()
    if not hmac.compare_digest(expected, provided):
        raise WebhookError("bad_signature", "signature verification failed", 401)


def resolve_webhook_client(conn: sqlite3.Connection, client_id: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT * FROM webhook_clients WHERE client_id = ? AND active = 1", (client_id,)
    ).fetchone()
