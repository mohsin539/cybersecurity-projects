"""Rule based alerting on top of the telemetry stream.

Rules test sampled throughput against a threshold and emit a throttled
``Alert`` (cooldown window) so a sustained breach surfaces once rather than
spamming the dashboard.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from domain.entities import Alert, Snapshot

logger = logging.getLogger(__name__)

AlertListener = Callable[[Alert], None]


@dataclass(frozen=True)
class AlertRule:
    """Raise an alert when throughput exceeds ``threshold_bps``.

    ``interface`` may be ``None`` to watch overall traffic.
    """

    direction: str  # "download" | "upload"
    threshold_bps: float
    interface: Optional[str] = None
    severity: str = "warning"
    source: str = "bandwidth-policy"


class AlertService:
    """Evaluates alert rules against a snapshot and emits throttled alerts."""

    def __init__(
        self,
        rules: List[AlertRule],
        *,
        cooldown_seconds: float = 60.0,
        history_size: int = 200,
    ) -> None:
        self._rules = list(rules)
        self._cooldown = max(0.0, cooldown_seconds)
        self._history: deque = deque(maxlen=history_size)
        self._last_emitted: Dict[Tuple[str, str, Optional[str]], float] = {}
        self._pending: deque = deque(maxlen=history_size)
        self._listeners: List[AlertListener] = []
        self._lock = threading.Lock()

    def subscribe(self, listener: AlertListener) -> None:
        self._listeners.append(listener)

    def evaluate(self, snapshot: Snapshot) -> None:
        """Run every rule against a fresh snapshot."""
        now = time.time()
        with self._lock:
            for rule in self._rules:
                value_bps = self._observed_value(snapshot, rule)
                if value_bps is None or value_bps < rule.threshold_bps:
                    continue
                key = (rule.interface or "*", rule.direction)
                last = self._last_emitted.get(key)
                if last is not None and (now - last) < self._cooldown:
                    continue
                self._last_emitted[key] = now
                alert = Alert(
                    severity=rule.severity,
                    source=rule.source,
                    message=self._message(rule, value_bps),
                    timestamp=now,
                    value_bps=value_bps,
                    threshold_bps=rule.threshold_bps,
                )
                self._history.append(alert)
                self._pending.append(alert)
                logger.warning("ALERT %s %s", alert.severity, alert.message)
                for listener in list(self._listeners):
                    try:
                        listener(alert)
                    except Exception:  # noqa: BLE001
                        logger.exception("Alert listener failed")

    def drain_pending(self) -> List[Alert]:
        """Return new alerts since the last drain (for real-time delivery)."""
        with self._lock:
            items = list(self._pending)
            self._pending.clear()
            return items

    def recent(self, limit: int = 100) -> List[Alert]:
        with self._lock:
            items = list(self._history)
        return items[-limit:]

    @staticmethod
    def _observed_value(snapshot: Snapshot, rule: AlertRule) -> Optional[float]:
        if rule.interface is None:
            rate = (
                snapshot.total_download
                if rule.direction == "download"
                else snapshot.total_upload
            )
            return rate * 8.0  # B/s -> bit/s

        traffic = snapshot.interfaces.get(rule.interface)
        if traffic is None:
            return None
        rate = traffic.download_rate if rule.direction == "download" else traffic.upload_rate
        return rate * 8.0

    @staticmethod
    def _message(rule: AlertRule, value_bps: float) -> str:
        target = rule.interface or "total"
        unit = _bits_per_second_human(value_bps)
        return f"{target} {rule.direction} {unit} exceeds threshold"


def _bits_per_second_human(bps: float) -> str:
    units = ["bps", "Kbps", "Mbps", "Gbps"]
    value = float(bps)
    for unit in units:
        if value < 1000.0 or unit == units[-1]:
            return f"{value:.2f} {unit}"
        value /= 1000.0
    return f"{value:.2f} {units[-1]}"