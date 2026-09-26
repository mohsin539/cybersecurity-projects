"""Thread-safe in-process event bus acting as the lab "pcap".

Each packet/connection produced by the C2 simulator or the benign traffic
generator is appended here. Zeek and Suricata matchers consume this stream
exactly as they would consume a real pcap.
"""

from __future__ import annotations

import threading
import time


class EventBus:
    def __init__(self, max_events: int = 200_000):
        self._events: list[dict] = []
        self._lock = threading.RLock()
        self._max = max_events
        self.started = time.time()

    def push(self, event: dict) -> None:
        event["ts"] = event.get("ts", time.time())
        with self._lock:
            if len(self._events) >= self._max:
                return  # drop oldest tail to stay bounded (defensive cap)
            self._events.append(event)

    def snapshot(self) -> list[dict]:
        with self._lock:
            return list(self._events)

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            self.started = time.time()

    def count(self) -> int:
        with self._lock:
            return len(self._events)