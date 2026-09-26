from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

from ..models import Severity, SourceType, TimeKind, TimelineEvent

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    kind TEXT NOT NULL,
    added TEXT NOT NULL,
    events INTEGER NOT NULL DEFAULT 0,
    artifact_hash TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    time_kind TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_path TEXT NOT NULL,
    host TEXT DEFAULT '',
    user TEXT DEFAULT '',
    severity TEXT NOT NULL,
    size INTEGER,
    sha256 TEXT DEFAULT '',
    description TEXT NOT NULL,
    tags TEXT DEFAULT '',
    raw TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_src ON events(source_type);
CREATE INDEX IF NOT EXISTS idx_events_path ON events(source_path);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user);
"""


class CaseStore:
    def __init__(self, path: str | Path, case_id: str = ""):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.case_id = case_id or self.path.stem
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        with self._lock:
            self.conn.executescript(SCHEMA)
            self.conn.commit()
        self.set_meta("case_id", self.case_id)
        self.set_meta("created", datetime.now(timezone.utc).isoformat())

    def close(self) -> None:
        with self._lock:
            self.conn.commit()
            self.conn.close()

    def __enter__(self) -> "CaseStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def set_meta(self, key: str, value: str) -> None:
        with self._lock:
            self.conn.execute(
                "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
            self.conn.commit()

    def get_meta(self, key: str, default: str = "") -> str:
        with self._lock:
            row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def add_source(self, path: str, kind: str, events: int = 0, artifact_hash: str = "") -> int:
        with self._lock:
            cursor = self.conn.execute(
                "INSERT INTO sources(path, kind, added, events, artifact_hash) VALUES(?, ?, ?, ?, ?)",
                (path, kind, datetime.now(timezone.utc).isoformat(), events, artifact_hash),
            )
            self.conn.commit()
            return int(cursor.lastrowid)

    def add_events(self, events: Iterable[TimelineEvent], batch_size: int = 1000) -> int:
        inserted = 0
        batch: list[tuple] = []
        with self._lock:
            for event in events:
                row = event.to_row()
                batch.append(
                    (
                        row["event_id"],
                        row["timestamp"],
                        row["time_kind"],
                        row["source_type"],
                        row["source_path"],
                        row["host"],
                        row["user"],
                        row["severity"],
                        row["size"],
                        row["sha256"],
                        row["description"],
                        row["tags"],
                        json.dumps(event.raw, default=str),
                    )
                )
                if len(batch) >= batch_size:
                    inserted += self._flush(batch)
                    batch = []
            if batch:
                inserted += self._flush(batch)
            self.conn.commit()
        return inserted

    def _flush(self, batch: list[tuple]) -> int:
        cursor = self.conn.executemany(
            "INSERT OR IGNORE INTO events(event_id, timestamp, time_kind, source_type, source_path, host, user, "
            "severity, size, sha256, description, tags, raw) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            batch,
        )
        return cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else len(batch)

    def _build_filters(
        self,
        text: str = "",
        source_types: list[str] | None = None,
        severities: list[str] | None = None,
        hosts: list[str] | None = None,
        users: list[str] | None = None,
        start: str | None = None,
        end: str | None = None,
    ) -> tuple[str, list]:
        clauses: list[str] = []
        params: list = []
        if text:
            clauses.append("(description LIKE ? OR source_path LIKE ? OR user LIKE ? OR host LIKE ?)")
            like = f"%{text}%"
            params.extend([like, like, like, like])
        if source_types:
            clauses.append("source_type IN (" + ",".join("?" for _ in source_types) + ")")
            params.extend(source_types)
        if severities:
            clauses.append("severity IN (" + ",".join("?" for _ in severities) + ")")
            params.extend(severities)
        if hosts:
            clauses.append("host IN (" + ",".join("?" for _ in hosts) + ")")
            params.extend(hosts)
        if users:
            clauses.append("user IN (" + ",".join("?" for _ in users) + ")")
            params.extend(users)
        if start:
            clauses.append("timestamp >= ?")
            params.append(start)
        if end:
            clauses.append("timestamp <= ?")
            params.append(end)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        return where, params

    def query(self, limit: int = 50000, offset: int = 0, order: str = "ASC", **filters) -> list[TimelineEvent]:
        where, params = self._build_filters(**filters)
        direction = "DESC" if str(order).upper() == "DESC" else "ASC"
        sql = f"SELECT * FROM events{where} ORDER BY timestamp {direction} LIMIT ? OFFSET ?"
        params = [*params, int(limit), int(offset)]
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._row_to_event(row) for row in rows]

    def count(self, **filters) -> int:
        where, params = self._build_filters(**filters)
        with self._lock:
            row = self.conn.execute(f"SELECT COUNT(*) AS n FROM events{where}", params).fetchone()
        return int(row["n"])

    def distinct(self, column: str) -> list[str]:
        allowed = {"host", "user", "source_type", "severity", "source_path"}
        if column not in allowed:
            raise ValueError(f"unsupported column: {column}")
        with self._lock:
            rows = self.conn.execute(
                f"SELECT DISTINCT {column} AS v FROM events WHERE {column} <> '' ORDER BY {column} LIMIT 1000"
            ).fetchall()
        return [row["v"] for row in rows]

    def iter_events(self, order: str = "ASC") -> Iterator[TimelineEvent]:
        direction = "DESC" if str(order).upper() == "DESC" else "ASC"
        with self._lock:
            cursor = self.conn.execute(f"SELECT * FROM events ORDER BY timestamp {direction}")
            for row in cursor:
                yield self._row_to_event(row)

    def stats(self) -> dict:
        with self._lock:
            total = self.conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"]
            by_sev = self.conn.execute("SELECT severity AS k, COUNT(*) AS n FROM events GROUP BY severity").fetchall()
            by_src = self.conn.execute("SELECT source_type AS k, COUNT(*) AS n FROM events GROUP BY source_type").fetchall()
            by_host = self.conn.execute(
                "SELECT host AS k, COUNT(*) AS n FROM events WHERE host <> '' GROUP BY host ORDER BY n DESC LIMIT 20"
            ).fetchall()
            span = self.conn.execute("SELECT MIN(timestamp) AS lo, MAX(timestamp) AS hi FROM events").fetchone()
        return {
            "total": total,
            "by_severity": {row["k"]: row["n"] for row in by_sev},
            "by_source": {row["k"]: row["n"] for row in by_src},
            "by_host": {row["k"]: row["n"] for row in by_host},
            "span": {"start": span["lo"], "end": span["hi"]},
        }

    def sources(self) -> list[dict]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM sources ORDER BY added").fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> TimelineEvent:
        tags = [t for t in (row["tags"] or "").split(",") if t]
        try:
            raw = json.loads(row["raw"]) if row["raw"] else {}
        except (json.JSONDecodeError, TypeError):
            raw = {}
        return TimelineEvent(
            timestamp=datetime.fromisoformat(row["timestamp"]),
            source_type=SourceType(row["source_type"]),
            source_path=row["source_path"],
            description=row["description"],
            time_kind=TimeKind(row["time_kind"]),
            host=row["host"] or "",
            user=row["user"] or "",
            severity=Severity(row["severity"]),
            size=row["size"],
            sha256=row["sha256"] or "",
            tags=tags,
            raw=raw,
            event_id=row["event_id"],
        )
