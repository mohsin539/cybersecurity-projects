"""psutil-based per-process network I/O sampler.

Uses ``psutil.Process.io_counters()`` which reports *all* I/O (disk + network
mixed together), so the numbers are an approximation of network attribution.
The ``TelemetryService`` sampling loop is throttled; on Windows the adapter
waits a few seconds between process scans to bound its CPU cost — scanning
every process in one pass is O(processes) syscalls and the busiest machine
still changes little between scans.
"""
from __future__ import annotations

import logging
import time
from typing import Dict, Optional

import psutil

from domain.process_traffic import ProcessTrafficDelta, ProcessTrafficPort

logger = logging.getLogger(__name__)

# Minimum seconds between full process scans; extra sample() calls inside the
# window return zero deltas (which ProcessTrafficService treats as "no data
# yet", not as "traffic stopped").
_MIN_SCAN_SPACING = 3.0


class PsutilProcessTrafficSource(ProcessTrafficPort):
    """Reads cumulative per-process I/O counters and derives deltas."""

    def __init__(self, min_scan_spacing: float = _MIN_SCAN_SPACING) -> None:
        # 0 disables throttling (used by tests); production settings default to 3s.
        self._min_spacing = max(0.0, float(min_scan_spacing))
        self._last_scan = 0.0
        # pid -> (io_counters.read_bytes, io_counters.write_bytes)
        self._previous: Dict[int, tuple] = {}
        # pid -> process name (kept so deltas survive a renamed pid cache)
        self._names: Dict[int, str] = {}

    def sample(self) -> Dict[int, ProcessTrafficDelta]:
        now = time.monotonic()
        if now - self._last_scan < self._min_spacing:
            # Throttle: return empty so consumers skip this tick gracefully.
            return {}
        self._last_scan = now

        deltas: Dict[int, ProcessTrafficDelta] = {}
        current: Dict[int, tuple] = {}
        for proc in psutil.process_iter(attrs=["pid", "name"]):
            pid = proc.info["pid"]
            name = proc.info.get("name") or f"pid {pid}"
            try:
                io = proc.io_counters()
            except (psutil.NoSuchProcess, psutil.AccessDenied,
                    psutil.ZombieProcess, OSError):
                continue
            counters = (io.read_bytes, io.write_bytes)
            current[pid] = counters
            self._names[pid] = name

            prev = self._previous.get(pid)
            if prev is None:
                continue  # baseline sample: no delta yet
            read_delta = max(0, counters[0] - prev[0])
            write_delta = max(0, counters[1] - prev[1])
            if read_delta == 0 and write_delta == 0:
                continue
            deltas[pid] = ProcessTrafficDelta(
                pid=pid,
                name=self._names.get(pid, name),
                bytes_recv=read_delta,
                bytes_sent=write_delta,
            )

        self._previous = current
        return deltas

    # Keep psutil import context tidy for tests that monkeypatch psutil.
    @staticmethod
    def _process(pid: int) -> Optional[psutil.Process]:
        try:
            return psutil.Process(pid)
        except psutil.NoSuchProcess:
            return None
