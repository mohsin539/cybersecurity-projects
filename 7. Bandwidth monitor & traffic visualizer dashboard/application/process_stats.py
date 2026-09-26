"""Per-process traffic attribution service.

Consumes ``ProcessTrafficDelta`` batches from the port, keeps a short
sliding average so the UI numbers move smoothly, and exposes a ranked
"top talkers" view for the dashboard.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from domain.process_traffic import ProcessTrafficDelta, ProcessTrafficPort

logger = logging.getLogger(__name__)


@dataclass
class ProcessStats:
    """One process row in the top-talkers table."""

    pid: int
    name: str
    bytes_recv: int  # last interval ingress (bytes)
    bytes_sent: int  # last interval egress (bytes)
    rate_recv: float  # smoothed bytes/s
    rate_sent: float  # smoothed bytes/s
    total_recv: float  # session totals since service start
    total_sent: float


@dataclass
class ProcessStatsSnapshot:
    """Ranked view handed to the DTO layer."""

    rows: List[ProcessStats]
    total_recv_rate: float
    total_sent_rate: float
    sample_count: int
    timestamp: float


class _RateWindow:
    """Bounded FIFO of (recv, sent) rate readings averaged for smoothing."""

    def __init__(self, size: int) -> None:
        self._values: deque = deque(maxlen=max(1, int(size)))

    def append(self, recv: float, sent: float) -> None:
        self._values.append((recv, sent))

    @property
    def recv(self) -> float:
        return sum(v[0] for v in self._values) / len(self._values)

    @property
    def sent(self) -> float:
        return sum(v[1] for v in self._values) / len(self._values)

    def __len__(self) -> int:
        return len(self._values)


class ProcessTrafficService:
    """Accumulates and smooths per-process deltas from the port."""

    def __init__(
        self,
        source: ProcessTrafficPort,
        *,
        smooth_window: int = 3,
        max_tracked: int = 400,
    ) -> None:
        self._source = source
        self._smooth_window = max(1, int(smooth_window))
        self._max_tracked = max(1, int(max_tracked))
        self._lock = threading.Lock()
        self._rates: Dict[int, _RateWindow] = {}
        self._totals: Dict[int, Tuple[float, float]] = {}
        self._names: Dict[int, str] = {}
        self._last_batch: Dict[int, ProcessTrafficDelta] = {}
        self._last_update_at: Optional[float] = None
        self._sample_count = 0
        self._started_at = time.time()

    # ------------------------------------------------------------------ #
    # Ingest (called from the telemetry sampling thread)
    # ------------------------------------------------------------------ #
    def update(
        self,
        deltas: Dict[int, ProcessTrafficDelta],
        now: Optional[float] = None,
    ) -> None:
        """Ingest one delta batch.

        ``now`` (monotonic seconds) is optional and exists for tests; the
        elapsed time between non-empty batches converts byte deltas into
        rates, so throttled scans (every ~3s) are handled correctly.
        """
        if not deltas:
            return
        tick = time.monotonic() if now is None else now
        with self._lock:
            elapsed = 1.0
            if self._last_update_at is not None:
                elapsed = max(0.05, tick - self._last_update_at)
            self._last_update_at = tick

            for pid, delta in deltas.items():
                window = self._rates.get(pid)
                if window is None:
                    window = _RateWindow(self._smooth_window)
                    self._rates[pid] = window
                window.append(delta.bytes_recv / elapsed, delta.bytes_sent / elapsed)

                total = self._totals.get(pid, (0.0, 0.0))
                self._totals[pid] = (
                    total[0] + delta.bytes_recv,
                    total[1] + delta.bytes_sent,
                )
                self._names[pid] = delta.name
                self._last_batch[pid] = delta

            self._sample_count += 1
            self._prune_locked()

    def _prune_locked(self) -> None:
        """Keep memory bounded: retain the busiest ``max_tracked`` pids."""
        if len(self._totals) <= self._max_tracked:
            return
        ranked = sorted(
            self._totals.items(), key=lambda kv: kv[1][0] + kv[1][1], reverse=True
        )
        keep = {pid for pid, _ in ranked[: self._max_tracked]}
        for table in (self._rates, self._totals, self._names, self._last_batch):
            for pid in [p for p in table if p not in keep]:
                table.pop(pid, None)

    # ------------------------------------------------------------------ #
    # Query (called from HTTP threads)
    # ------------------------------------------------------------------ #
    def snapshot(self, limit: int = 10) -> ProcessStatsSnapshot:
        """Return the current ranked view (by smoothed combined rate)."""
        with self._lock:
            rows = self._build_rows_locked(limit)
            total_recv = sum(w.recv for w in self._rates.values())
            total_sent = sum(w.sent for w in self._rates.values())
            return ProcessStatsSnapshot(
                rows=rows,
                total_recv_rate=total_recv,
                total_sent_rate=total_sent,
                sample_count=self._sample_count,
                timestamp=time.time(),
            )

    def _build_rows_locked(self, limit: int) -> List[ProcessStats]:
        rows: List[ProcessStats] = []
        for pid, window in self._rates.items():
            delta = self._last_batch.get(pid)
            total = self._totals.get(pid, (0.0, 0.0))
            rows.append(
                ProcessStats(
                    pid=pid,
                    name=self._names.get(pid, f"pid {pid}"),
                    bytes_recv=delta.bytes_recv if delta else 0,
                    bytes_sent=delta.bytes_sent if delta else 0,
                    rate_recv=window.recv,
                    rate_sent=window.sent,
                    total_recv=total[0],
                    total_sent=total[1],
                )
            )
        rows.sort(key=lambda r: r.rate_recv + r.rate_sent, reverse=True)
        return rows[: max(1, int(limit))]

    @property
    def sample_count(self) -> int:
        with self._lock:
            return self._sample_count
