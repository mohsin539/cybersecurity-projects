"""Hardened HTTP response headers middleware.

Implements:
  - OWASP Top 10 A05 (misconfiguration) / A07 (security headers)
  - NIST SP 800-53 SC-8 / SI-11
  - ISO 27001 A.13.1 (network security: transport + UI protections)
The dashboard is tuned with a security-relevant CSP that is still usable,
and every API response gets anti-sniffing / framing / referrer controls.
"""

from __future__ import annotations

import logging

from app.config import settings
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("xtester.mw")

CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "   # bootstrap inline styles only
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "object-src 'none'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if settings.app_env == "production":
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
            # CSP headers are set by the static/cache layer in production nginx,
            # but we keep them here as defense-in-depth.
        if request.url.path.startswith("/api"):
            response.headers["Content-Security-Policy"] = CSP
        elif request.url.path == "/":
            response.headers["Content-Security-Policy"] = CSP
        return response