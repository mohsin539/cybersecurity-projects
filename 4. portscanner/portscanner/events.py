"""Thread-safe in-process event bus (architecture.md §4.6).

Subscribers: store, progress UI (GUI queue), JSONL stream writer, rate controller.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Callable


@dataclass
class ScanStarted:
    targets: int
    ports: int
    engine: str


@dataclass
class PortResultEvent:
    host: str
    port: int
    proto: str
    state: str
    rtt_ms: float


@dataclass
class ServiceFoundEvent:
    host: str
    port: int
    service: str


@dataclass
class RateAdjusted:
    new_rate: float
    reason: str


@dataclass
class WarningEvent:
    message: str


@dataclass
class ScanFinished:
    duration_s: float
    counts: dict = field(default_factory=dict)
    warnings: int = 0


EventHandler = Callable[[object], None]


class EventBus:
    """Fan-out broadcast with per-subscriber error isolation."""

    def __init__(self) -> None:
        self._subs: list[EventHandler] = []
        self._lock = threading.Lock()

    def subscribe(self, handler: EventHandler) -> None:
        with self._lock:
            self._subs.append(handler)

    def publish(self, event: object) -> None:
        with self._lock:
            subs = list(self._subs)
        for h in subs:
            try:
                h(event)
            except Exception:  # noqa: BLE001 — a broken UI must not kill the scan
                pass
