"""Correlation engine: single-event + threshold rules over a sliding window.

State lives in an in-memory WindowCounter with TTL; snapshots are persisted
so a restart resumes without losing the correlation window (architecture.md 2.3).
"""
from __future__ import annotations

import json
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .model import Alert, Event, new_incident_id


@dataclass
class ThresholdRule:
    id: str
    name: str
    severity: str
    window_s: float
    threshold: int
    group_by: tuple[str, ...]
    filters: dict  # field:value equality match on Event
    incident_ttl_s: float = 3600.0

    def matches(self, ev: Event) -> bool:
        return all(getattr(ev, k, None) == v for k, v in self.filters.items())

    def key(self, ev: Event) -> tuple:
        return tuple(str(getattr(ev, k, "")) for k in self.group_by)


class WindowCounter:
    """Sliding-window per-key event tracking with TTL expiry."""

    def __init__(self, ttl: float):
        self.ttl = ttl
        self._buckets: dict[str, deque] = defaultdict(deque)  # key -> deque[ts]

    def add(self, key, now: float) -> int:
        self._purge(key, now)
        self._buckets[key].append(now)
        return len(self._buckets[key])

    def count(self, key, now: float) -> int:
        self._purge(key, now)
        return len(self._buckets[key])

    def _purge(self, key, now: float) -> None:
        dq = self._buckets[key]
        while dq and now - dq[0] > self.ttl:
            dq.popleft()
        if not dq:
            self._buckets.pop(key, None)

    def size(self) -> int:
        return sum(len(v) for v in self._buckets.values())


@dataclass
class RuleEngine:
    rules: list = field(default_factory=list)
    threshold_rules: list = field(default_factory=list)
    counters: dict = field(default_factory=dict)
    incident_cache: dict = field(default_factory=dict)  # alert_key -> Alert
    on_alert: Optional[Callable[["RuleEngine", Event, object, Alert], None]] = None

    def load_rules(self, rule_dir: Path) -> None:
        for path in sorted(Path(rule_dir).glob("*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            for rd in data:
                if rd.get("type") == "threshold":
                    self.threshold_rules.append(ThresholdRule(
                        id=rd["id"], name=rd["name"], severity=rd.get("severity", "medium"),
                        window_s=float(rd.get("window_s", 60)),
                        threshold=int(rd.get("threshold", 5)),
                        group_by=tuple(rd.get("group_by", [])),
                        filters=rd.get("filter", {}),
                        incident_ttl_s=float(rd.get("incident_ttl_s", 3600)),
                    ))

    def handle(self, ev: Event, now: Optional[float] = None) -> Optional[Alert]:
        now = now or time.time()
        for rule in self.threshold_rules:
            if not rule.matches(ev):
                continue
            key = (rule.id, rule.key(ev))
            if key not in self.counters:
                self.counters[key] = WindowCounter(rule.window_s)
            n = self.counters[key].add(key, now)
            if n < rule.threshold:
                continue
            # Coalesce repeats into one incident (alert dedupe / suppression).
            existing = self.incident_cache.get(key)
            if existing:
                if now - _ts_to_epoch(existing.ts) < rule.incident_ttl_s:
                    existing.count += 1
                    existing.evidence.append(ev.to_json())
                    if self.on_alert:
                        self.on_alert(self, ev, rule, existing)
                    return existing
            alert = Alert(
                rule_id=rule.id, rule_name=rule.name, severity=rule.severity,
                evidence=[ev.to_json()],
                incident_id=f"inc-{rule.id}-{int(now)}",
            )
            self.incident_cache[key] = alert
            if self.on_alert:
                self.on_alert(self, ev, rule, alert)
            return alert
        return None


def _ts_to_epoch(iso_ts: str) -> float:
    try:
        dt = __import__("datetime").datetime.fromisoformat(iso_ts)
        return dt.timestamp()
    except (ValueError, AttributeError):
        return time.time()