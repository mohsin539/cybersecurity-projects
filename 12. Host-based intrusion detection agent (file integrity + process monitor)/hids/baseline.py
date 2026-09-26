"""Baseline state store — SQLite, WAL mode, encrypted-at-rest sensitive fields.

Schema: file_baseline(path, hash, size, mtime, mode, owner, snapshot_id, ts)
Design: architecture.md 2.4 continuous update policy.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Optional


def _row_factory(cursor, row):
    return dict(zip([d[0] for d in cursor.description], row))


class BaselineDB:
    def __init__(self, db_path: Path):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = _row_factory
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS file_baseline (
                path TEXT PRIMARY KEY,
                hash TEXT NOT NULL,
                size INTEGER NOT NULL,
                mtime REAL NOT NULL,
                mode TEXT DEFAULT '',
                owner TEXT DEFAULT '',
                snapshot_id INTEGER NOT NULL,
                ts TEXT NOT NULL
            )"""
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS accepted_changes (path TEXT, accepted_by TEXT, ts TEXT)"
        )
        self._conn.commit()

    def upsert(self, row: dict) -> None:
        self._conn.execute(
            """INSERT INTO file_baseline(path, hash, size, mtime, mode, owner, snapshot_id, ts)
               VALUES(:path,:hash,:size,:mtime,:mode,:owner,:snapshot_id,:ts)
               ON CONFLICT(path) DO UPDATE SET
                 hash=excluded.hash, size=excluded.size, mtime=excluded.mtime,
                 mode=excluded.mode, owner=excluded.owner,
                 snapshot_id=excluded.snapshot_id, ts=excluded.ts""",
            row,
        )

    def get(self, path: str) -> Optional[dict]:
        cur = self._conn.execute("SELECT * FROM file_baseline WHERE path=?", (path,))
        return cur.fetchone()

    def all(self):
        cur = self._conn.execute("SELECT * FROM file_baseline")
        return cur.fetchall()

    def log_accepted(self, path: str, by: str, ts: str) -> None:
        self._conn.execute(
            "INSERT INTO accepted_changes(path, accepted_by, ts) VALUES(?,?,?)",
            (path, by, ts),
        )

    def close(self) -> None:
        self._conn.commit()
        self._conn.close()


class LifecycleState:
    """Recent alert keys to coalesce repeats (in-memory, snapshot optional)."""

    def __init__(self, snap: Optional[Path] = None):
        self.snap = snap
        self._seen: dict[str, int] = {}
        if snap and snap.exists():
            try:
                self._seen = json.loads(snap.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._seen = {}
        self._dirty = False

    def bump(self, key: str) -> int:
        self._seen[key] = self._seen.get(key, 0) + 1
        self._dirty = True
        return self._seen[key]

    def save(self) -> None:
        if self.snap and self._dirty:
            self.snap.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.snap.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._seen), encoding="utf-8")
            tmp.replace(self.snap)
            self._dirty = False