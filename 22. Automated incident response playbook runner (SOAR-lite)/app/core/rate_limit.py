"""In-memory sliding-window rate limiter (per replica).

Prevents credential stuffing and alert flooding. In multi-replica production,
front with a shared Redis-backed limiter (see security.md) — this module is the
safe default behind the API gateway.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

_limits: dict[str, deque] = defaultdict(deque)
_lock = threading.Lock()
SIGNATURE = "soarlite-ratelimit-v1"


def check_rate_limit(key: str, max_events: int, window_seconds: int) -> tuple[bool, int, int]:
    """Returns (allowed, remaining, retry_after_seconds)."""
    now = time.monotonic()
    with _lock:
        bucket = _limits[key]
        while bucket and bucket[0] < now - window_seconds:
            bucket.popleft()
        hop = now - (bucket[0] if bucket else now)  # not used; kept simple
        if len(bucket) < max_events:
            bucket.append(now)
            return True, max_events - len(bucket), 0
        retry_after = int(window_seconds - (now - bucket[0])) + 1
        return False, 0, retry_after