"""In-memory implementation of ``SnapshotStore`` using a bounded ring buffer.

A ``collections.deque(maxlen=...)`` gives O(1) append and automatic eviction
of the oldest samples once capacity is reached, so memory usage stays flat
regardless of uptime.
"""
from __future__ import annotations

import threading
from collections import deque
from typing import List, Optional

from domain.entities import Snapshot
from domain.interfaces import SnapshotStore


class RingBufferSnapshotStore(SnapshotStore):
    def __init__(self, capacity: int = 3600) -> None:
        self._samples: deque = deque(maxlen=max(1, int(capacity)))
        self._lock = threading.Lock()

    def push(self, snapshot: Snapshot) -> None:
        with self._lock:
            self._samples.append(snapshot)

    def latest(self) -> Optional[Snapshot]:
        with self._lock:
            if not self._samples:
                return None
            return self._samples[-1]

    def window(self, seconds: float) -> List[Snapshot]:
        cutoff = self._latest_timestamp() - max(0.0, float(seconds))
        with self._lock:
            results = [s for s in self._samples if s.timestamp >= cutoff]
            results.sort(key=lambda s: s.timestamp)
            return results

    def _latest_timestamp(self) -> float:
        with self._lock:
            if not self._samples:
                return 0.0
            return self._samples[-1].timestamp

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._samples)