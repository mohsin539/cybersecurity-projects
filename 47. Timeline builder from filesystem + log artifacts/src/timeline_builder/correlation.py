from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Iterable

from .models import SEVERITY_ORDER, Severity, TimelineEvent, ensure_utc


@dataclass
class CorrelationGroup:
    key: str
    start: str
    end: str
    count: int
    event_ids: list[str] = field(default_factory=list)
    hosts: set[str] = field(default_factory=set)
    users: set[str] = field(default_factory=set)
    max_severity: Severity = Severity.INFO


class Correlator:
    def __init__(self, window: timedelta = timedelta(seconds=5), min_events: int = 3):
        if window.total_seconds() <= 0:
            raise ValueError("window must be positive")
        self.window = window
        self.min_events = max(1, min_events)

    def correlate(self, events: Iterable[TimelineEvent], key_fn=None) -> list[CorrelationGroup]:
        def default_key(event: TimelineEvent) -> str:
            return f"{event.host or '-'}|{event.source_path or '-'}|{event.user or '-'}"

        key_fn = key_fn or default_key
        buckets: dict[str, list[TimelineEvent]] = defaultdict(list)
        for event in events:
            buckets[key_fn(event)].append(event)

        groups: list[CorrelationGroup] = []
        for key, items in buckets.items():
            items.sort(key=lambda e: e.sort_key())
            current: list[TimelineEvent] = []
            for event in items:
                if not current:
                    current = [event]
                    continue
                gap = ensure_utc(event.timestamp) - ensure_utc(current[-1].timestamp)
                if gap <= self.window:
                    current.append(event)
                else:
                    self._emit(groups, key, current)
                    current = [event]
            self._emit(groups, key, current)
        groups.sort(key=lambda g: g.start)
        return groups

    def _emit(self, groups: list[CorrelationGroup], key: str, items: list[TimelineEvent]) -> None:
        if len(items) < self.min_events:
            return
        max_sev = max((e.severity for e in items), key=lambda s: SEVERITY_ORDER[s])
        groups.append(
            CorrelationGroup(
                key=key,
                start=ensure_utc(items[0].timestamp).isoformat(),
                end=ensure_utc(items[-1].timestamp).isoformat(),
                count=len(items),
                event_ids=[e.event_id for e in items],
                hosts={e.host for e in items if e.host},
                users={e.user for e in items if e.user},
                max_severity=max_sev,
            )
        )
