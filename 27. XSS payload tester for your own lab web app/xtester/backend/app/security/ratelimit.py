"""In-process sliding window rate limiter.

Default deployment is single-writer; for horizontal scaling replace the
store with Redis (the interface is a plain MutableMapping). Limits:
  - API rate (requests/min per identity+ip)
  - scan quota (scans/day per user)
Enforcement fails closed with 429 + Retry-After.

ISO 27001 A.12.6.1 / A.13.1.1, NIST SC-7/CM-6 (bound resource usage),
OWASP Top 10 A05 (misconfiguration) — automated anti-abuse control.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Deque

from fastapi import HTTPException, Request, status


class _RateWindow:
    __slots__ = ("deque_series", "window_start")

    def __init__(self, start: float):
        self.window_start: float = start
        self.deque_series: Deque[float] = deque()


class TokenBucket:
    """Sliding-window counter with per-key buckets, GC'd lazily."""

    def __init__(self, limit: int, window_seconds: int = 60):
        self.limit = limit
        self.window = window_seconds
        self._buckets: dict[str, _RateWindow] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> tuple[bool, int]:
        """Returns (allowed, retry_after_seconds)."""
        now = time.monotonic()
        with self._lock:
            w = self._buckets.get(key)
            if w is None or (now - w.window_start) >= self.window:
                self._gc(now)
                w = _RateWindow(now)
                self._buckets[key] = w
            w.deque_series.append(now)
            while w.deque_series and w.deque_series[0] <= now - self.window:
                w.deque_series.popleft()
            count = len(w.deque_series)
            if count > self.limit:
                retry = int(self.window - (now - w.window_start))
                return (False, max(retry, 1))
            return (True, 0)

    def _gc(self, now: float) -> None:
        stale = [k for k, v in self._buckets.items() if now - v.window_start >= 2 * self.window]
        for k in stale:
            del self._buckets[k]

    @property
    def bucket_count(self) -> int:
        return len(self._buckets)


_api_bucket = TokenBucket(limit=60, window_seconds=60)
_scan_bucket = TokenBucket(limit=50, window_seconds=86400)


def client_key(request: Request, identity: str) -> str:
    ip = request.headers.get("x-forwarded-for", (request.client.host if request.client else "?"))
    return f"{identity}|{ip}"


def enforce_api_limit(request: Request, identity: str) -> None:
    allowed, retry_after = _api_bucket.allow(client_key(request, identity))
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="rate limit exceeded",
            headers={"Retry-After": str(retry_after)},
        )


def enforce_scan_quota(identity: str) -> None:
    allowed, retry_after = _scan_bucket.allow(identity)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="daily scan quota exceeded",
            headers={"Retry-After": str(retry_after)},
        )