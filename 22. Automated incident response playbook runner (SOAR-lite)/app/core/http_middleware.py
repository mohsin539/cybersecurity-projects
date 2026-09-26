"""Central HTTP middleware: security headers, request ID, ingress rate limit.

OWASP A9 + NIST AU / ISO 27001 A.12.4: every request is logged with a request ID.
"""
from __future__ import annotations

import logging
import time
import uuid

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.config import settings
from app.core.rate_limit import check_rate_limit

log = logging.getLogger("soarlite.http")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(self)",
    "Cache-Control": "no-store",
}
CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
)

INGRESS_RATE_MAX = 240
INGRESS_RATE_WINDOW = 60
AUTH_API_RATE_MAX = 20
AUTH_API_WINDOW = 60


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = uuid.uuid4().hex
        request.state.request_id = request_id
        start = time.monotonic()

        # Ingress limiting for unauthenticated-yet-hostile paths
        path = request.url.path
        allow = True
        retry_after = 0
        if path.startswith("/api/v1/ingest"):
            allow, _, retry_after = check_rate_limit(f"ingress:{request.client.host}", 120, 60)
        elif path.startswith("/api/v1/auth/login") or path.startswith("/api/v1/auth/refresh"):
            allow, _, retry_after = check_rate_limit(f"auth:{request.client.host}", AUTH_API_RATE_MAX, AUTH_API_WINDOW)

        if not allow:
            response = JSONResponse(
                {"detail": "Rate limit exceeded. Slow down."},
                status_code=429,
                headers={"Retry-After": str(retry_after), "X-Request-ID": request_id},
            )
            return response

        try:
            response = await call_next(request)
        except Exception as exc:  # do not leak internals (OWASP A9/A5)
            log.exception("unhandled error request_id=%s", request_id)
            response = JSONResponse({"detail": "Internal server error", "request_id": request_id}, status_code=500)
            return response

        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        response.headers.setdefault("Content-Security-Policy", CSP)
        response.headers.setdefault("X-Request-ID", request_id)
        if settings.hsts_seconds > 0:
            response.headers.setdefault("Strict-Transport-Security", f"max-age={settings.hsts_seconds}; includeSubDomains")
        if settings.is_production:
            response.headers.setdefault("X-Frame-Options", "DENY")

        status_code = getattr(response, "status_code", 0)
        log.info(
            "req=%s method=%s path=%s status=%s ms=%.1f ip=%s",
            request_id, request.method, path, status_code, (time.monotonic() - start) * 1000, request.client.host if request.client else "?",
        )
        return response


class CORSMiddlewareWrapper:
    """No CORS by default — cross-origin browser access is denied (OWASP A5).
    Enable only for trusted SPA origins via settings if ever needed.
    """