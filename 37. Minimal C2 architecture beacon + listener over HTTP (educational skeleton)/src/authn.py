"""Authentication and rate limiting (OWASP A01, A02, A05, A07; ISO A.9, A.12.4).

- Bearer token authentication with constant-time comparison.
- Separate principal tokens: BEACON (agent identity) and CONSOLE (operator).
- Per-IP sliding-window rate limiting to blunt brute force / DoS.
- Failed-authorization events are written to the audit log.
"""
import hmac
import time
from collections import defaultdict, deque

from .util import now_iso


class AuthService:
    def __init__(self, beacon_token: str, console_token: str, audit=None):
        self.tokens = {"beacon": beacon_token, "console": console_token}
        self.audit = audit
        self._hits: dict[str, deque] = defaultdict(deque)

    def verify(self, authorization_header: str | None, principal: str) -> bool:
        """Return True if the bearer token matches the principal's token."""
        expected = self.tokens.get(principal, "")
        if not authorization_header:
            return False
        try:
            scheme, _, token = authorization_header.partition(" ")
        except (AttributeError, ValueError):
            return False
        if scheme.strip().lower() != "bearer" or not token.strip():
            return False
        return hmac.compare_digest(token.strip().encode(), expected.encode())

    def rate_allowed(self, client_ip: str | None) -> bool:
        """Sliding-window rate limiting keyed by client IP."""
        from .config import RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW_SEC

        ip = client_ip or "unknown"
        now = time.monotonic()
        window = self._hits[ip]
        while window and now - window[0] > RATE_LIMIT_WINDOW_SEC:
            window.popleft()
        if len(window) >= RATE_LIMIT_MAX_REQUESTS:
            return False
        window.append(now)
        return True

    def failure(self, ip: str | None, endpoint: str, reason: str = "bad token"):
        if self.audit:
            self.audit.record(
                event="auth.failure",
                actor="anonymous",
                subject=endpoint,
                severity="warn",
                detail={"ip": ip, "reason": reason, "at": now_iso()},
            )