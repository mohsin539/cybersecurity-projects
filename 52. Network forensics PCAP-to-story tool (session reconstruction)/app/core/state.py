"""state.py - Persistent state management for cases, captures, sessions, reports.

Mirrors the 'STORAGE LAYER' of architecture.md (SS4.5) but as a single portable
SQLite database so the tool ships fully self-contained (documented in state.md):

  tables: cases | captures | sessions | reports | audit | config

All writes go through the same thread (main GUI loop via async runner) so SQLite
single-writer semantics are respected.
"""

from __future__ import annotations

import datetime
import json
import os
import sqlite3
from pathlib import Path

ENV_DATA_DIR = "PCAFLESS_DATA_DIR"


def default_data_dir() -> Path:
    return Path(os.environ.get(ENV_DATA_DIR, Path.home() / ".pcapless"))


def iso_ts() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class StateDB:
    """Thin wrapper around SQLite exposing typed domain methods."""

    def __init__(self, db_path=None):
        self.path = Path(db_path) if db_path else default_data_dir() / "pcapless.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA foreign_keys=ON;")
        self._init_schema()

    # ----------------------------------------------------------------- schema
    def _init_schema(self):
        c = self._conn
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                clearance INTEGER NOT NULL DEFAULT 2,
                ts_created TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS captures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                filename TEXT NOT NULL,
                file_sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                frames INTEGER NOT NULL DEFAULT 0,
                ts_imported TEXT NOT NULL,
                FOREIGN KEY(case_id) REFERENCES cases(case_id)
            );
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                capture_id INTEGER NOT NULL,
                session_id TEXT UNIQUE NOT NULL,
                flow_key TEXT NOT NULL,
                proto TEXT NOT NULL,
                l7 TEXT NOT NULL,
                src TEXT, sport INTEGER, dst TEXT, dport INTEGER,
                start_ts TEXT, end_ts TEXT,
                bytes_c2s INTEGER DEFAULT 0,
                bytes_s2c INTEGER DEFAULT 0,
                frames INTEGER DEFAULT 0,
                stats_json TEXT,
                story_json TEXT,
                events_json TEXT,
                beacon INTEGER DEFAULT 0,
                FOREIGN KEY(capture_id) REFERENCES captures(id)
            );
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                session_id TEXT,
                fmt TEXT NOT NULL,
                filename TEXT NOT NULL,
                file_sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                report_version INTEGER NOT NULL DEFAULT 1,
                ts_created TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                obj TEXT,
                evidence_hash TEXT,
                prev_hash TEXT,
                event_hash TEXT NOT NULL,
                signature TEXT NOT NULL,
                verdict TEXT NOT NULL DEFAULT 'ALLOWED'
            );
            CREATE TABLE IF NOT EXISTS config (
                key TEXT PRIMARY KEY,
                value TEXT
            );
            """
        )
        # default case so out-of-box UX never asks for a case id.
        self._conn.execute(
            "INSERT OR IGNORE INTO cases(case_id, name, clearance, ts_created) VALUES('DEFAULT','Default Case',2,?)",
            (iso_ts(),),
        )
        self._conn.commit()

    # ---------------------------------------------------------------- cases
    def cases(self):
        return self._conn.execute("SELECT * FROM cases ORDER BY ts_created DESC").fetchall()

    def case_clearance(self, case_id: str) -> int:
        row = self._conn.execute("SELECT clearance FROM cases WHERE case_id=?", (case_id,)).fetchone()
        return int(row["clearance"]) if row else 2

    def create_case(self, case_id: str, name: str, clearance: int = 2) -> bool:
        if self._conn.execute("SELECT 1 FROM cases WHERE case_id=?", (case_id,)).fetchone():
            return False
        self._conn.execute(
            "INSERT INTO cases(case_id,name,clearance,ts_created) VALUES(?,?,?,?)",
            (case_id, name, clearance, iso_ts()),
        )
        self._conn.commit()
        return True

    # ------------------------------------------------------------- captures
    def add_capture(self, case_id, filename, file_sha256, size_bytes, frames) -> int:
        cur = self._conn.execute(
            "INSERT INTO captures(case_id,filename,file_sha256,size_bytes,frames,ts_imported) VALUES(?,?,?,?,?,?)",
            (case_id, filename, file_sha256, size_bytes, frames, iso_ts()),
        )
        self._conn.commit()
        return cur.lastrowid

    def captures(self):
        return self._conn.execute(
            "SELECT c.*, (SELECT COUNT(*) FROM sessions s WHERE s.capture_id=c.id) n_sessions FROM captures c ORDER BY c.ts_imported DESC"
        ).fetchall()

    # ------------------------------------------------------------- sessions
    def add_session(self, capture_id, rec: dict) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO sessions
               (capture_id, session_id, flow_key, proto, l7, src, sport, dst, dport,
                start_ts, end_ts, bytes_c2s, bytes_s2c, frames, stats_json, story_json, events_json, beacon)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                capture_id, rec["session_id"], rec["flow_key"], rec["proto"], rec["l7"],
                rec.get("src"), rec.get("sport"), rec.get("dst"), rec.get("dport"),
                rec.get("start_ts"), rec.get("end_ts"),
                rec.get("bytes_c2s", 0), rec.get("bytes_s2c", 0), rec.get("frames", 0),
                json.dumps(rec.get("stats", {})),
                json.dumps(rec.get("story", {})),
                json.dumps(rec.get("events", [])),
                1 if rec.get("beacon") else 0,
            ),
        )
        self._conn.commit()

    def sessions(self, capture_id=None):
        if capture_id is not None:
            return self._conn.execute(
                "SELECT * FROM sessions WHERE capture_id=? ORDER BY start_ts", (capture_id,)
            ).fetchall()
        return self._conn.execute("SELECT * FROM sessions ORDER BY start_ts").fetchall()

    def session(self, session_id):
        return self._conn.execute("SELECT * FROM sessions WHERE session_id=?", (session_id,)).fetchone()

    def session_recs(self, capture_id=None):
        rows = self.sessions(capture_id)
        recs = []
        for r in rows:
            recs.append(self._row_to_rec(r))
        return recs

    def session_rec(self, session_id):
        r = self.session(session_id)
        return self._row_to_rec(r) if r else None

    @staticmethod
    def _row_to_rec(r) -> dict:
        rec = {
            "session_id": r["session_id"],
            "flow_key": r["flow_key"],
            "proto": r["proto"],
            "l7": r["l7"],
            "src": r["src"],
            "sport": r["sport"],
            "dst": r["dst"],
            "dport": r["dport"],
            "start_ts": r["start_ts"],
            "end_ts": r["end_ts"],
            "bytes_c2s": r["bytes_c2s"],
            "bytes_s2c": r["bytes_s2c"],
            "total_bytes": (r["bytes_c2s"] or 0) + (r["bytes_s2c"] or 0),
            "frames": r["frames"],
            "beacon": bool(r["beacon"]),
            "stats": json.loads(r["stats_json"] or "{}"),
            "story": json.loads(r["story_json"] or "{}"),
            "events": json.loads(r["events_json"] or "[]"),
        }
        return rec

    # -------------------------------------------------------------- reports
    def add_report(self, case_id, session_id, fmt, filename, file_sha256, size_bytes):
        cur = self._conn.execute(
            """INSERT INTO reports(case_id, session_id, fmt, filename, file_sha256, size_bytes,
               report_version, ts_created) VALUES(?,?,?,?,?,?, (SELECT COALESCE(MAX(report_version),0)+1
               FROM reports WHERE session_id IS ? OR session_id=?), ?)""",
            (case_id, session_id, fmt, filename, file_sha256, size_bytes, session_id, session_id, iso_ts()),
        )
        self._conn.commit()
        return cur.lastrowid

    def reports(self, session_id=None):
        if session_id:
            return self._conn.execute("SELECT * FROM reports WHERE session_id=? ORDER BY ts_created DESC", (session_id,)).fetchall()
        return self._conn.execute("SELECT * FROM reports ORDER BY ts_created DESC").fetchall()

    # ---------------------------------------------------------------- audit
    def append_audit(self, entry: dict) -> None:
        self._conn.execute(
            """INSERT INTO audit(ts,actor,action,obj,evidence_hash,prev_hash,event_hash,signature,verdict)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (
                entry["ts"], entry["actor"], entry["action"], entry.get("obj"),
                entry.get("evidence_hash"), entry["prev_hash"], entry["event_hash"],
                entry["signature"], entry.get("verdict", "ALLOWED"),
            ),
        )
        self._conn.commit()

    def audit_all(self, limit=500):
        return self._conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

    def audit_last_hash(self) -> str:
        row = self._conn.execute("SELECT event_hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        return row["event_hash"] if row else "GENESIS"

    def audit_count(self):
        return self._conn.execute("SELECT COUNT(*) n FROM audit").fetchone()["n"]

    def audit_verify(self):
        """Recompute backward hash chain to detect tamper. Returns (ok, bad_ids)."""
        rows = self._conn.execute("SELECT * FROM audit ORDER BY id ASC").fetchall()
        prev = "GENESIS"
        bad = []
        for r in rows:
            payload = f"{prev}|{r['ts']}|{r['actor']}|{r['action']}|{r['obj'] or ''}|{r['evidence_hash'] or ''}"
            import hashlib as _hl
            recomputed = _hl.sha256(payload.encode("utf-8")).hexdigest()
            if recomputed != r["event_hash"]:
                bad.append(r["id"])
            prev = r["event_hash"]
        return (len(bad) == 0, bad)

    # ---------------------------------------------------------------- config
    def get_cfg(self, key, default=None):
        row = self._conn.execute("SELECT value FROM config WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_cfg(self, key, value):
        self._conn.execute(
            "INSERT INTO config(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )
        self._conn.commit()

    def close(self):
        self._conn.close()


def _chain_hash(prev_hash: str, ts: str, actor: str, action: str, obj: str, evidence_hash: str) -> str:
    import hashlib
    payload = f"{prev_hash}|{ts}|{actor}|{action}|{obj}|{evidence_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()