from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from ..models import TimelineEvent


def export_json(events: Iterable[TimelineEvent], destination: str | Path, metadata: dict[str, Any] | None = None) -> Path:
    dest = Path(destination)
    dest.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for event in events:
        row = event.to_row()
        row["timestamp"] = event.normalized_timestamp().isoformat()
        row["raw"] = event.raw
        rows.append(row)
    payload = {
        "product": "TimelineBuilder",
        "generated": datetime.now(timezone.utc).isoformat(),
        "metadata": metadata or {},
        "event_count": len(rows),
        "events": rows,
    }
    dest.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return dest
