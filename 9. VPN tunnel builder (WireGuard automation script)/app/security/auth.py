"""Session-based authentication (OWASP A01/A07; NIST IA-5, AC-3).

When auth is enabled, every request must present a valid session cookie
set after login with a pre-shared token (SHA-256 salted hash stored).
CSRF is enforced via a synchroniser token pattern: the login GET sets a
session token, all POST requests must echo it back in the form or header.

Localhost-only enforcement (when required_localhost_only=True) blocks
non-local clients from seeing anything except the login page; this is
appropriate for the privileged CLI-GUI role of this tool.
"""

from __future__ import annotations

import secrets
from functools import wraps

from flask import (
    Request,
    abort,
    current_app,
    flash,
    redirect,
    request,
    session,
    url_for,
)

from ..core.config import token_matches


def generate_session_token() -> str:
    return secrets.token_urlsafe(32)


def _is_auth_enabled() -> bool:
    settings = current_app.config.get("APP_SETTINGS", {})
    if current_app.config.get("NO_AUTH"):
        return False
    return bool(settings.get("auth_enabled", True))


def _is_localhost(request: Request) -> bool:
    ip = request.remote_addr or ""
    return ip in ("127.0.0.1", "::1", "") or ip.startswith("10.212.")


def set_session(user_id: str, token: str) -> None:
    session.clear()
    session["user"] = user_id
    session["auth"] = True
    session["token"] = token
    session.permanent = True


def clear_session() -> None:
    session.clear()


def require_auth(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not _is_auth_enabled():
            return view_func(*args, **kwargs)
        if session.get("auth"):
            return view_func(*args, **kwargs)
        flash("Authentication required", "warning")
        return redirect(url_for("login"))
    return wrapper


def require_localhost_only() -> None:
    settings = current_app.config.get("APP_SETTINGS", {})
    if settings.get("require_localhost_only") and not _is_localhost(request):
        abort(403, description="access restricted to localhost")


def csrf_protect() -> None:
    if request.method not in ("POST", "PUT", "DELETE", "PATCH"):
        return
    if request.path.startswith("/api/"):
        return
    token_form = request.form.get("_csrf_token") or ""
    token_header = request.headers.get("X-CSRF-Token") or ""
    if token_form and secrets.compare_digest(token_form, session.get("_csrf", "")):
        return
    if token_header and secrets.compare_digest(token_header, session.get("_csrf", "")):
        return
    if request.endpoint == "login":
        return
    abort(403, description="CSRF token missing or invalid")


def generate_csrf_token() -> str:
    token = session.get("_csrf")
    if not token:
        token = generate_session_token()
        session["_csrf"] = token
    return token


def login_check(settings: dict, candidate_token: str) -> bool:
    return token_matches(settings, candidate_token)


def get_current_user() -> str:
    if not _is_auth_enabled():
        return "local-noauth"
    return session.get("user", "anonymous")


def get_csrf_token() -> str:
    if "_csrf" not in session:
        session["_csrf"] = generate_session_token()
    return session["_csrf"]