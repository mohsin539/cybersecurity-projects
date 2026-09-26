"""Storage layer: append-only event store + alerts index (JSONL partitions).

Time-partitioned buckets keep retention-friendly hot/warm/cold tiers possible.
Operator API mirrors architecture.md section 2.5.
"""
from __future__ import annotations

import json
from pathlib import Path

from .model import Alert, Event


class EventStore:
    def __init__(self, root: Path, partition: str = "day"):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.partition = partition
        self._fh = None
        self._part = ""

    def _switch(self, ts: str) -> None:
        part = ts[:10] if self.partition == "day" else ts[:7]  # YYYY-MM-DD | YYYY-MM
        if part != self._part:
            if self._fh:
                self._fh.close()
            bucket = self.root / part
            bucket.mkdir(parents=True, exist_ok=True)
            self._fh = (bucket / "events.jsonl").open("a", encoding="utf-8")
            self._part = part

    def append(self, ev: Event) -> None:
        self._switch(ev.ts)
        self._fh.write(ev.to_json() + "\n")
        self._fh.flush()

    def close(self) -> None:
        if self._fh:
            self._fh.close()


class AlertIndex:
    def __init__(self, path: Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._fh = path.open("a", encoding="utf-8")

    def add(self, alert: Alert) -> None:
        self._fh.write(alert.to_json() + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()

    def count(self) -> int:
        try:
            return sum(1 for _ in self.path.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            return 0


def summarize_alerts(path: Path, limit: int = 20) -> list[dict]:
    """Read last `limit` alerts from the alert index (analyst dashboard feed)."""
    try:
        lines = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    out = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out