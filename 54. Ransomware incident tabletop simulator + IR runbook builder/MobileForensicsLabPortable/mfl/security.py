"""Security middleware: session auth, RBAC, CSRF, protective headers, rate limiting.

Implements (executive summaries):
- OWASP A01 broken access control  -> RBAC decorators + deny-by-default
- OWASP A07 auth failures          -> hashed passwords (pbkdf2), HttpOnly/SameSite cookies
- OWASP A05 misconfiguration       -> default-deny headers, no debug info leakage
- NIST SP 800-53 AC-2/AC-3/AC-6    -> account mgmt, least privilege
- NIST AU-2..AU-12 linkage recorded via audit.audit()
"""

import hashlib
import time
from functools import wraps

from flask import (
    g, redirect, render_template, request, session, url_for, current_app
)

from werkzeug.security import check_password_hash

from .db import get_db, query_one
from .audit import audit

LOGIN_FAIL_LIMIT = int(__import__("os").environ.get("MFL_LOGIN_FAIL_LIMIT", "5"))
_fail_tracker = {}


def _client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()


def g_user_id():
    return session.get("uid")


def g_user_role():
    if "uid" not in session:
        return ""
    row = query_one("SELECT role FROM users WHERE id=?", (session["uid"],))
    return row["role"] if row else ""


# ---------------------------------------------------------------------------
# Session auth helpers
# ---------------------------------------------------------------------------

def current_user():
    if "uid" not in session:
        return None
    return query_one("SELECT id,username,display_name,role,active FROM users WHERE id=?", (session["uid"],))


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "uid" not in session:
            return redirect(url_for("main.login"))
        g.user = current_user()
        if not g.user or not g.user["active"]:
            session.clear()
            return redirect(url_for("main.login"))
        return view(*args, **kwargs)
    return wrapped


def role_required(*roles):
    def deco(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "uid" not in session:
                return redirect(url_for("main.login"))
            g.user = current_user()
            if not g.user or g.user["role"] not in roles:
                audit(current_app, g.user["id"], g.user["role"], "COMPLIANCE_VIEW",
                      "security", None, {"blocked_action": request.endpoint, "required_roles": list(roles)}, "high")
                from flask import abort
                return abort(403)
            return view(*args, **kwargs)
        return wrapped
    return deco


def attempt_login(username, password):
    """Login with in-memory brute-force throttling (ISO A.8.2, OWASP A07)."""
    ip = _client_ip()
    if _fail_tracker.get(ip, 0) >= LOGIN_FAIL_LIMIT:
        audit(current_app, username or "-", "unknown", "LOGIN_FAILED", "auth", ip,
              {"reason": "rate-limited"}, "high")
        return None, "Too many failed attempts. Wait a few minutes and retry."

    user = query_one("SELECT * FROM users WHERE username=?", (username,))
    if not user or not check_password_hash(user["password_hash"], password or ""):
        _fail_tracker[ip] = _fail_tracker.get(ip, 0) + 1
        audit(current_app, username or "-", "unknown", "LOGIN_FAILED", "auth", ip,
              {"remaining_allowed": max(0, LOGIN_FAIL_LIMIT - _fail_tracker[ip])}, "medium")
        return None, "Invalid credentials."

    _fail_tracker[ip] = 0
    session.clear()
    session.permanent = True
    session["uid"] = user["id"]
    get_db().execute("UPDATE users SET last_login=datetime('now') WHERE id=?", (user["id"],))
    get_db().commit()
    audit(current_app, user["id"], user["role"], "LOGIN", "auth", user["id"], {"ip": ip}, "info")
    return user, None


# ---------------------------------------------------------------------------
# CSRF (OWASP A08/A01; no external dependency)
# ---------------------------------------------------------------------------

def generate_csrf():
    if "_csrf" not in session:
        session["_csrf"] = hashlib.sha256(
            (current_app.secret_key + str(time.time())).encode()
        ).hexdigest()
    return session["_csrf"]


def csrf_protect(app):
    @app.before_request
    def _csrf_check():
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            token = request.form.get("_csrf") or request.headers.get("X-CSRF-Token")
            if not token or token != session.get("_csrf"):
                return "CSRF validation failed (403)", 403
        g.csrf = generate_csrf()


def apply_security_middleware(app):
    @app.after_request
    def _secure_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-XSS-Protection"] = "1; mode=block"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return resp

    @app.context_processor
    def _inject():
        user = g.get("user")
        return {"current_user": user, "csrf_token": g.get("csrf", "")}

    @app.errorhandler(403)
    def _forbidden(e):
        return render_template("error.html", code=403, message="Forbidden - you lack the required role for this action."), 403

    @app.errorhandler(404)
    def _not_found(e):
        return render_template("error.html", code=404, message="Resource not found."), 404

    @app.errorhandler(405)
    def _method(e):
        return render_template("error.html", code=405, message="Method not allowed."), 405

    @app.errorhandler(500)
    def _server(e):
        return render_template("error.html", code=500, message="Internal server error."), 500