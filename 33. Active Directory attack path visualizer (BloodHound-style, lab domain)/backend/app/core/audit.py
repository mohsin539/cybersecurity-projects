"""Append-only, in-process audit trail (ISO 27001 A.8.15 logging).

In production this streams to immutable storage / SIEM; the interface is
deliberately the same so the rest of the code never changes.
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from typing import Any

_LOCK = threading.Lock()
_AUDIT: list[dict[str, Any]] = []


def record(event: str, *, actor: str = "system", outcome: str = "success",
           severity: str = "info", **details: Any) -> None:
    entry = {
        "id": uuid.uuid4().hex,
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": event,
        "actor": actor,
        "outcome": outcome,
        "severity": severity,
        **details,
    }
    with _LOCK:
        _AUDIT.append(entry)
    # Production: also emit JSON line to SIEM collector.
    if details.get("severity") in {"warn", "alert"}:
        print(json.dumps(entry))  # placeholder for syslog/SIEM shipper


def tail(limit: int = 200) -> list[dict[str, Any]]:
    with _LOCK:
        return list(reversed(_AUDIT[-limit:]))


def all_events() -> list[dict[str, Any]]:
    with _LOCK:
        return list(_AUDIT)
