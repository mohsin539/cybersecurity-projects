"""Alerting layer: router, dedupe, writers (console / file / webhook).

Channels implement write(Alert); Router applies severity routing + per-key
dedupe window. All I/O failures are caught so alerting can't take down ingest.
"""
from __future__ import annotations

import json
import sys
import time
import urllib.request
from pathlib import Path
from typing import Callable, Optional

from .model import Alert

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class ConsoleWriter:
    def write(self, alert: Alert) -> None:
        print(f"[ALERT:{alert.severity}] {alert.rule_id} {alert.rule_name} "
              f"(count={alert.count}) {alert.incident_id}")


class JsonlWriter:
    def __init__(self, path: Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = path.open("a", encoding="utf-8")

    def write(self, alert: Alert) -> None:
        self._fh.write(alert.to_json() + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


class WebhookWriter:
    """POST alert JSON to a URL (TLS by default). Failure-tolerant."""

    def __init__(self, url: str, timeout: float = 5.0, auth_token: str = ""):
        self.url, self.timeout, self.auth_token = url, timeout, auth_token

    def write(self, alert: Alert) -> None:
        try:
            data = alert.to_json().encode("utf-8")
            req = urllib.request.Request(
                self.url, data=data, method="POST",
                headers={"Content-Type": "application/json",
                         **({"Authorization": f"Bearer {self.auth_token}"} if self.auth_token else {})},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp.read()
        except Exception as exc:  # noqa: BLE001 - alerting must be non-fatal
            sys.stderr.write(f"[webhook:{self.url}] send failed: {exc}\n")


class Router:
    """Routes alerts to channels based on severity floor + per-key dedupe."""

    def __init__(self, min_severity: str = "medium"):
        self.channels: list = []
        self.min_severity = min_severity
        self._floor = SEVERITY_ORDER.get(min_severity, 2)
        self._dedupe: dict[str, tuple[float, int]] = {}
        self.dedupe_window_s = 60.0

    def add_channel(self, channel) -> None:
        self.channels.append(channel)

    def route(self, alert: Alert) -> None:
        if SEVERITY_ORDER.get(alert.severity, 0) < self._floor:
            return
        key = alert.rule_id + ":" + alert.incident_id
        now = time.time()
        last, count = self._dedupe.get(key, (0.0, 0))
        if now - last < self.dedupe_window_s:
            self._dedupe[key] = (now, count + 1)
            return  # suppressed within window; count tracked for stats
        self._dedupe[key] = (now, 1)
        for ch in self.channels:
            try:
                ch.write(alert)
            except Exception as exc:  # noqa: BLE001
                sys.stderr.write(f"[channel {ch.__class__.__name__}] {exc}\n")