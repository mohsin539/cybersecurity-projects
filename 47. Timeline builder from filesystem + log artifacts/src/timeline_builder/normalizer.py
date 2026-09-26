from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from typing import Iterable

from .config import ScanOptions
from .models import SEVERITY_ORDER, Severity, TimelineEvent, ensure_utc


class TimelineNormalizer:
    def __init__(self, options: ScanOptions | None = None, dedupe: bool = True):
        self.options = options or ScanOptions()
        self.dedupe = dedupe

    def normalize(self, events: Iterable[TimelineEvent]) -> list[TimelineEvent]:
        normalized: list[TimelineEvent] = []
        seen: set[tuple] = set()
        for event in events:
            event.timestamp = ensure_utc(event.timestamp)
            if self.dedupe:
                key = (
                    event.timestamp.isoformat(),
                    event.source_path,
                    event.time_kind.value,
                    event.description[:120],
                )
                if key in seen:
                    continue
                seen.add(key)
            normalized.append(event)
        normalized.sort(key=lambda e: e.sort_key())
        return normalized

    @staticmethod
    def buckets(events: Iterable[TimelineEvent], width: timedelta = timedelta(hours=1)) -> list[tuple[datetime, int]]:
        if width.total_seconds() <= 0:
            raise ValueError("bucket width must be positive")
        counters: Counter[datetime] = Counter()
        for event in events:
            ts = ensure_utc(event.timestamp)
            epoch = int(ts.timestamp())
            bucket = epoch - (epoch % int(width.total_seconds()))
            counters[datetime.fromtimestamp(bucket, tz=ts.tzinfo)] += 1
        return sorted(counters.items())

    @staticmethod
    def summarize(events: Iterable[TimelineEvent]) -> dict:
        events = list(events)
        by_source: Counter[str] = Counter()
        by_severity: Counter[str] = Counter()
        by_host: Counter[str] = Counter()
        timestamps = []
        for event in events:
            by_source[event.source_type.value] += 1
            by_severity[event.severity.value] += 1
            if event.host:
                by_host[event.host] += 1
            timestamps.append(event.normalized_timestamp())
        span = None
        if timestamps:
            span = {
                "start": min(timestamps).isoformat(),
                "end": max(timestamps).isoformat(),
            }
        high_plus = sum(
            count for sev, count in by_severity.items() if SEVERITY_ORDER[Severity(sev)] >= SEVERITY_ORDER[Severity.HIGH]
        )
        return {
            "total": len(events),
            "by_source": dict(by_source),
            "by_severity": dict(by_severity),
            "by_host": dict(by_host.most_common(20)),
            "high_or_above": high_plus,
            "span": span,
        }
