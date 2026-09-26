"""Simple token-bucket rate limiter (OWASP A07 brute-force defense)."""
from __future__ import annotations

import threading
import time

_BUCKETS: dict[str, tuple[float, float]] = {}
_LOCK = threading.Lock()


def allow(key: str, limit: int, window_seconds: int) -> bool:
    """Fixed-window counter. Returns True if the request is allowed."""
    now = time.time()
    window = int(now // window_seconds)
    with _LOCK:
        bucket = _BUCKETS.get(key)
        if bucket is None or bucket[1] != window:
            _BUCKETS[key] = (1, window)
            return True
        if bucket[0] >= limit:
            return False
        _BUCKETS[key] = (bucket[0] + 1, window)
        return True


def clear() -> None:
    with _LOCK:
        _BUCKETS.clear()
