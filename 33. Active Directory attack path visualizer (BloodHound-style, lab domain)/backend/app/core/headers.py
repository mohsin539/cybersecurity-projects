"""Strict security headers on every response (OWASP Secure Headers Project,
ISO 27001 A.8.24 use of cryptography-in-transit posture)."""
from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "  # Tailwind requires inline styles
    "img-src 'self' data:; "
    "font-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        h = response.headers
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Referrer-Policy", "no-referrer")
        h.setdefault(
            "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
        )
        h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        h.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        h.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        # CSP only for browser-visible responses; API JSON is unaffected.
        if response.media_type and "text/html" in response.media_type:
            h.setdefault("Content-Security-Policy", CSP)
        return response
