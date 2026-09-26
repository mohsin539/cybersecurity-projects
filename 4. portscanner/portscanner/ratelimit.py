"""Rate limiting + retry/backoff policy (architecture.md §9).

Token bucket with jitter and exponential backoff for inconclusive results.
"""
from __future__ import annotations

import random
import threading
import time


class TokenBucket:
    """Global rate limiter. rate=0 means 'unbounded' (still capped by workers)."""

    def __init__(self, rate: float, burst: int = 64) -> None:
        self.rate = rate
        self.capacity = float(burst)
        self.tokens = float(burst)
        self.updated = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        if self.rate <= 0:
            return
        while True:
            with self._lock:
                now = time.monotonic()
                self.tokens = min(
                    self.capacity,
                    self.tokens + (now - self.updated) * self.rate,
                )
                self.updated = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                wait = (1.0 - self.tokens) / self.rate
            time.sleep(min(wait, 0.25))


class BackoffPolicy:
    """Exponential backoff: timeout * 2**attempt, with optional jitter (§9)."""

    def __init__(self, base_timeout_s: float, jitter_ms: int = 0) -> None:
        self.base = base_timeout_s
        self.jitter_ms = jitter_ms

    def delay(self, attempt: int) -> float:
        d = self.base * (2 ** attempt)
        if self.jitter_ms:
            d += random.uniform(0, self.jitter_ms / 1000.0)
        return min(d, 60.0)


class RateController:
    """Closed-loop adaptation: halves rate when loss on closed ports suggests
    rate-triggered filtering (architecture.md §9)."""

    def __init__(self, bus, base_rate: float) -> None:
        self.bus = bus
        self.current_rate = base_rate
        self._loss_window: list[bool] = []
        self._lock = threading.Lock()

    def sample(self, state: str) -> None:
        if self.current_rate <= 0:
            return
        with self._lock:
            self._loss_window.append(state == "open|filtered")
            if len(self._loss_window) >= 200:
                loss = sum(self._loss_window) / len(self._loss_window)
                self._loss_window.clear()
                if loss > 0.6:
                    self.current_rate = max(10.0, self.current_rate / 2)
                    self.bus.publish(
                        f"rate adjusted to {self.current_rate:.0f}/s (loss={loss:.0%})"
                    )
