"""memory.py - working-memory layer for the suite.

A lightweight LRU cache (process-scoped) ahead of SQLite so hot sessions/stories
are served without re-querying, plus a bounded in-memory event buffer used by the
audit dashboard. Mirrors the 'WORKING MEMORY' of security.md/state.md docs.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from threading import RLock


class LRUCache:
    """Thread-safe, capacity-bounded LRU keyed by str."""

    def __init__(self, capacity: int = 1024):
        self.capacity = capacity
        self._data: OrderedDict = OrderedDict()
        self._lock = RLock()

    def get(self, key):
        with self._lock:
            if key not in self._data:
                return None
            self._data.move_to_end(key)
            return self._data[key]

    def put(self, key, value):
        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
            self._data[key] = value
            while len(self._data) > self.capacity:
                self._data.popitem(last=False)

    def stats(self):
        with self._lock:
            return {"size": len(self._data), "capacity": self.capacity}


class WorkingMemory:
    """Process-scoped memory: LRU + recent-event ring buffer."""

    def __init__(self, capacity=1024, event_ring=500):
        self.cache = LRUCache(capacity)
        self._events = []
        self._event_cap = event_ring
        self._clock = 0.0
        self._lock = RLock()

    def store(self, key, value):
        self.cache.put(key, value)

    def recall(self, key):
        return self.cache.get(key)

    def note(self, kind: str, detail: str, ts: str):
        """Record a working-memory event (non-persistent telemetry)."""
        with self._lock:
            self._events.append({"kind": kind, "detail": detail, "ts": ts})
            if len(self._events) > self._event_cap:
                self._events = self._events[-self._event_cap:]

    def recent_events(self, limit=50):
        with self._lock:
            return list(self._events[-limit:])

    def snapshot(self):
        return {
            "lru": self.cache.stats(),
            "events_buffered": len(self._events),
        }


WORKING_MEMORY = WorkingMemory()