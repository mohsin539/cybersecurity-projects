"""SQLite event store (ISO 27001 A.8.28 secure coding / A.8.15 logging).

- WAL mode, synchronous=FULL for integrity.
- Prepared statements only (OWASP A03 - no string-built SQL).
- Batched, single-writer ingestion with a global monotonic sequencer.
- Separate hardened path for the append-only audit chain.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

from .crypto import IntegrityService

_SCHEMA_SAMPLE = """
CREATE TABLE IF NOT EXISTS samples (
    id INTEGER PRIMARY KEY,
    sha256 TEXT NOT NULL UNIQUE,
    sha1 TEXT, md5 TEXT,
    name TEXT NOT NULL, size INTEGER NOT NULL,
    pe_machine TEXT, pe_subsystem TEXT,
    first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
    ingested_at INTEGER NOT NULL
);
"""

_SCHEMA_SESSION = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    sample_id INTEGER REFERENCES samples(id),
    started_at INTEGER NOT NULL, ended_at INTEGER,
    duration_ms INTEGER,
    event_count INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'running',
    policy_hash TEXT NOT NULL, sandbox TEXT NOT NULL,
    notes TEXT
);
"""

_SCHEMA_EVENTS = """
CREATE TABLE IF NOT EXISTS events (
    seq INTEGER PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id),
    ts_ns INTEGER NOT NULL, pid INTEGER NOT NULL, tid INTEGER NOT NULL,
    category TEXT NOT NULL,
    api TEXT NOT NULL, module TEXT,
    args JSON, ret TEXT, status TEXT,
    parent_seq INTEGER, tags JSON
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id, seq);
CREATE INDEX IF NOT EXISTS idx_events_api ON events(api);
CREATE INDEX IF NOT EXISTS idx_events_cat ON events(category);
"""

_SCHEMA_ARTIFACTS = """
CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY,
    session_id TEXT, kind TEXT NOT NULL, path TEXT NOT NULL,
    sha256 TEXT NOT NULL, size INTEGER NOT NULL
);
"""

_SCHEMA_REPORTS = """
CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    generated_at INTEGER NOT NULL,
    format TEXT NOT NULL, filename TEXT NOT NULL,
    report_sha256 TEXT NOT NULL, size INTEGER NOT NULL,
    filters JSON
);
"""


class EventStore:
    """Thread-safe transactional store for capture events + registry."""

    def __init__(self, data_dir: Path) -> None:
        store_dir = data_dir / "store"
        store_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = store_dir / "acsv.db"
        self._write_lock = threading.Lock()
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(_SCHEMA_SAMPLE)
        self.conn.executescript(_SCHEMA_SESSION)
        self.conn.executescript(_SCHEMA_EVENTS)
        self.conn.executescript(_SCHEMA_ARTIFACTS)
        self.conn.executescript(_SCHEMA_REPORTS)
        self.conn.commit()
        self.integrity = IntegrityService()

    # ------------------------------------------------------------------ kvs
    def set_kv(self, key: str, value: str) -> None:
        with self._write_lock:
            self.conn.execute(
                "INSERT INTO kv(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
            self.conn.commit()

    def get_kv(self, key: str, default: str = "") -> str:
        try:
            row = self.conn.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
            return row["value"] if row else default
        except sqlite3.OperationalError:
            with self._write_lock:
                self.conn.execute(
                    "CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
                self.conn.commit()
            return self.get_kv(key, default)

    # ---------------------------------------------------------------- samples
    def upsert_sample(self, meta: dict) -> int:
        with self._write_lock:
            self.conn.execute(
                """INSERT INTO samples
                   (sha256, sha1, md5, name, size, pe_machine, pe_subsystem,
                    first_seen, last_seen, ingested_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(sha256) DO UPDATE SET last_seen=excluded.last_seen""",
                (
                    meta["sha256"], meta.get("sha1", ""), meta.get("md5", ""),
                    meta["name"], meta["size"],
                    meta.get("pe_machine", ""), meta.get("pe_subsystem", ""),
                    meta["first_seen"], time.time_ns(), time.time_ns(),
                ),
            )
            self.conn.commit()
            row = self.conn.execute(
                "SELECT id FROM samples WHERE sha256=?", (meta["sha256"],)
            ).fetchone()
            return int(row["id"])

    def list_samples(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM samples ORDER BY last_seen DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def get_sample(self, sample_id: int) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM samples WHERE id=?", (sample_id,)
        ).fetchone()
        return dict(row) if row else None

    # --------------------------------------------------------------- sessions
    def create_session(self, session_id: str, sample_id: int, policy_hash: str,
                       sandbox: str, started_at: int | None = None) -> None:
        started_at = started_at or time.time_ns()
        with self._write_lock:
            self.conn.execute(
                "INSERT INTO sessions(id, sample_id, started_at, policy_hash, sandbox, status) "
                "VALUES (?,?,?,?,?,?)",
                (session_id, sample_id, started_at, policy_hash, sandbox, "running"),
            )
            self.conn.commit()

    def finish_session(self, session_id: str, status: str) -> None:
        with self._write_lock:
            now = time.time_ns()
            self.conn.execute(
                "UPDATE sessions SET ended_at=?, duration_ms=?, status=? WHERE id=?",
                (now, (now - self.get_session(session_id)["started_at"]) // 1_000_000,
                 status, session_id),
            )
            cnt = self.conn.execute(
                "SELECT COUNT(*) AS c FROM events WHERE session_id=?", (session_id,)
            ).fetchone()["c"]
            self.conn.execute(
                "UPDATE sessions SET event_count=? WHERE id=?", (cnt, session_id)
            )
            self.conn.commit()

    def get_session(self, session_id: str) -> dict:
        row = self.conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
        if row is None:
            raise KeyError(session_id)
        return dict(row)

    def list_sessions(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM sessions ORDER BY started_at DESC").fetchall()
        return [dict(r) for r in rows]

    # ----------------------------------------------------------------- events
    def insert_events(self, session_id: str, pipe_events: list[dict]) -> None:
        if not pipe_events:
            return
        with self._write_lock:
            self.conn.executemany(
                """INSERT INTO events
                   (seq, session_id, ts_ns, pid, tid, category, api, module,
                    args, ret, status, parent_seq, tags)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                [
                    (
                        int(e["seq"]), session_id, int(e["ts_ns"]), int(e["pid"]),
                        int(e["tid"]), e["category"], e["api"], e.get("module", ""),
                        json.dumps(e.get("args", {})), str(e.get("ret", "")),
                        e.get("status", "UNKNOWN"),
                        e.get("parent_seq"), json.dumps(e.get("tags", [])),
                    )
                    for e in pipe_events
                ],
            )
            self.conn.commit()

    def iter_events(self, session_id: str, limit: int | None = None) -> list[dict]:
        sql = "SELECT * FROM events WHERE session_id=? ORDER BY seq"
        args: list[str] = [session_id]
        if limit:
            sql += " LIMIT ?"
            args.append(str(limit))
        rows = self.conn.execute(sql, args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["args"] = json.loads(d["args"] or "{}")
            d["tags"] = json.loads(d["tags"] or "[]")
            out.append(d)
        return out

    def event_count(self, session_id: str) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS c FROM events WHERE session_id=?", (session_id,)
        ).fetchone()
        return int(row["c"])

    def export_events(self, session_id: str, sink) -> None:
        cur = self.conn.execute("SELECT * FROM events WHERE session_id=? ORDER BY seq",
                                (session_id,))
        for r in cur:
            d = dict(r)
            d["args"] = json.loads(d["args"] or "{}")
            d["tags"] = json.loads(d["tags"] or "[]")
            sink(d)

    # --------------------------------------------------------------- artifacts
    def add_artifact(self, session_id: str, kind: str, path: str, sha256: str, size: int) -> None:
        with self._write_lock:
            self.conn.execute(
                "INSERT INTO artifacts(session_id, kind, path, sha256, size) VALUES (?,?,?,?,?)",
                (session_id, kind, path, sha256, size),
            )
            self.conn.commit()

    # ---------------------------------------------------------------- reports
    def add_report(self, report_id: str, session_id: str, fmt: str, filename: str,
                   report_sha256: str, size: int, filters: dict) -> None:
        with self._write_lock:
            self.conn.execute(
                "INSERT INTO reports(id, session_id, generated_at, format, filename, "
                "report_sha256, size, filters) VALUES (?,?,?,?,?,?,?,?)",
                (report_id, session_id, time.time_ns(), fmt, filename, report_sha256,
                 size, json.dumps(filters)),
            )
            self.conn.commit()

    def list_reports(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM reports ORDER BY generated_at DESC").fetchall()
        for r in rows:
            r = dict(r)
            r["filters"] = json.loads(r["filters"] or "{}")
            yield r

    # ---------------------------------------------------------------- close
    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass