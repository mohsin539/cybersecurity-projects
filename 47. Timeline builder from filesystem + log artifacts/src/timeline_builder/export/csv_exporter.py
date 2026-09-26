from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable

from ..models import TimelineEvent

COLUMNS = [
    "timestamp",
    "time_kind",
    "severity",
    "source_type",
    "host",
    "user",
    "source_path",
    "description",
    "size",
    "sha256",
    "tags",
    "event_id",
]


def export_csv(events: Iterable[TimelineEvent], destination: str | Path) -> Path:
    dest = Path(destination)
    dest.parent.mkdir(parents=True, exist_ok=True)
    with open(dest, "w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for event in events:
            row = event.to_row()
            row["timestamp"] = event.normalized_timestamp().isoformat()
            writer.writerow(row)
    return dest
