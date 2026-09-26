from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class SourceType(str, Enum):
    FILESYSTEM = "filesystem"
    LOG = "log"
    ARTIFACT = "artifact"


class TimeKind(str, Enum):
    MODIFIED = "M"
    ACCESSED = "A"
    CHANGED = "C"
    CREATED = "B"
    EVENT = "E"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass
class TimelineEvent:
    timestamp: datetime
    source_type: SourceType
    source_path: str
    description: str
    time_kind: TimeKind = TimeKind.EVENT
    host: str = ""
    user: str = ""
    severity: Severity = Severity.INFO
    size: int | None = None
    sha256: str = ""
    tags: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def normalized_timestamp(self) -> datetime:
        return ensure_utc(self.timestamp)

    def macb(self) -> str:
        return self.time_kind.value

    def to_row(self) -> dict[str, Any]:
        ts = self.normalized_timestamp().isoformat()
        return {
            "event_id": self.event_id,
            "timestamp": ts,
            "time_kind": self.time_kind.value,
            "source_type": self.source_type.value,
            "source_path": self.source_path,
            "host": self.host,
            "user": self.user,
            "severity": self.severity.value,
            "size": self.size,
            "sha256": self.sha256,
            "description": self.description,
            "tags": ",".join(self.tags),
        }

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "TimelineEvent":
        tags = row.get("tags") or ""
        return cls(
            timestamp=datetime.fromisoformat(row["timestamp"]),
            source_type=SourceType(row["source_type"]),
            source_path=row["source_path"],
            description=row["description"],
            time_kind=TimeKind(row.get("time_kind") or "E"),
            host=row.get("host") or "",
            user=row.get("user") or "",
            severity=Severity(row.get("severity") or "info"),
            size=row.get("size"),
            sha256=row.get("sha256") or "",
            tags=[t for t in tags.split(",") if t],
            raw=row.get("raw") or {},
            event_id=row.get("event_id") or uuid.uuid4().hex,
        )

    def sort_key(self) -> tuple[datetime, str]:
        return (self.normalized_timestamp(), self.source_path)


@dataclass
class CollectionResult:
    events: list[TimelineEvent] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    files_seen: int = 0
    bytes_seen: int = 0
    sources: list[str] = field(default_factory=list)

    def extend(self, other: "CollectionResult") -> None:
        self.events.extend(other.events)
        self.errors.extend(other.errors)
        self.files_seen += other.files_seen
        self.bytes_seen += other.bytes_seen
        self.sources.extend(other.sources)
