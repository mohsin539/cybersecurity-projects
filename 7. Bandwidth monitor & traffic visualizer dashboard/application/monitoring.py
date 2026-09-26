"""Core use case: sampling network counters and deriving throughput rates.

The service owns the timing loop, computes byte/second rates from consecutive
cumulative counter reads and pushes snapshots into a ``SnapshotStore``.  It
runs on a dedicated background thread so the web server stays responsive.
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Callable, Dict, List, Optional

from domain.entities import InterfaceTraffic, RateSample, Snapshot
from domain.interfaces import SnapshotStore, SystemNetworkSource

logger = logging.getLogger(__name__)

# Snapshot subscriber signature: receive a fresh Snapshot.
SnapshotListener = Callable[[Snapshot], None]

_MIN_INTERVAL = 0.1


class TelemetryService:
    """Background telemetry sampler (single-threaded loop)."""

    def __init__(
        self,
        *,
        source: SystemNetworkSource,
        store: SnapshotStore,
        interval: float = 1.0,
    ) -> None:
        self._source = source
        self._store = store
        self._interval = max(_MIN_INTERVAL, float(interval))

        self._previous: Dict[str, RateSample] = {}
        self._previous_total: Optional[RateSample] = None
        self._latest: Optional[Snapshot] = None

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Listeners are notified from the sampling thread with the latest
        # snapshot. A slow listener must tolerate being skipped; we guard it.
        self._listeners: List[SnapshotListener] = []

        self._started_at = time.time()
        self._samples_taken = 0

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    def subscribe(self, listener: SnapshotListener) -> None:
        """Register a snapshot subscriber (invoked on the sampling thread)."""
        self._listeners.append(listener)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop, name="bwmon-telemetry", daemon=True
        )
        self._thread.start()
        logger.info("Telemetry service started (interval=%.2fs)", self._interval)

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        self._thread = None
        logger.info("Telemetry service stopped")

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    @property
    def latest(self) -> Optional[Snapshot]:
        with self._lock:
            return self._latest

    @property
    def sample_count(self) -> int:
        return self._samples_taken

    @property
    def uptime(self) -> float:
        return time.time() - self._started_at

    # ------------------------------------------------------------------ #
    # Sampling
    # ------------------------------------------------------------------ #
    def capture_once(self) -> Snapshot:
        """Read counters and compute rates against the previous read."""
        counters = self._source.read_counters()
        total = self._source.read_total()

        interfaces: Dict[str, InterfaceTraffic] = {}
        for name, sample in counters.items():
            prev = self._previous.get(name)
            download, upload = _derive_rates(prev, sample)
            interfaces[name] = InterfaceTraffic(
                name=name, download_rate=download, upload_rate=upload, counters=sample
            )

        total_download, total_upload = _derive_rates(self._previous_total, total)

        self._previous = counters
        self._previous_total = total

        return Snapshot(
            timestamp=total.timestamp,
            interfaces=interfaces,
            total_download=total_download,
            total_upload=total_upload,
            total_counters=total,
        )

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            tick_start = time.monotonic()
            try:
                snapshot = self.capture_once()
            except Exception:  # noqa: BLE001 - sampling must never die
                logger.exception("Failed to capture network sample")
                self._stop_event.wait(self._interval)
                continue

            self._samples_taken += 1
            self._store.push(snapshot)
            with self._lock:
                self._latest = snapshot
            self._notify(snapshot)

            elapsed = time.monotonic() - tick_start
            remainder = self._interval - elapsed
            if remainder > 0:
                self._stop_event.wait(remainder)

    def _notify(self, snapshot: Snapshot) -> None:
        for listener in list(self._listeners):
            try:
                listener(snapshot)
            except Exception:  # noqa: BLE001 - one listener must not break others
                logger.exception("Snapshot listener failed")


def _derive_rates(
    previous: Optional[RateSample], current: RateSample
) -> tuple[float, float]:
    """bytes/second in and out, guarding against counter resets / first read."""
    if previous is None:
        return 0.0, 0.0
    delta = current.timestamp - previous.timestamp
    if delta <= 0:
        return 0.0, 0.0

    rx_delta = current.bytes_recv - previous.bytes_recv
    tx_delta = current.bytes_sent - previous.bytes_sent
    # OS counters may wrap (reset, sleep/wake) -> clamp to zero rather than
    # emit a meaningless negative rate.
    return max(0.0, rx_delta) / delta, max(0.0, tx_delta) / delta