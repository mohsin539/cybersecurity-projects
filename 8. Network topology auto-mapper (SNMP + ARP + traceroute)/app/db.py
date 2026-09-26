from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from .config import CFG
from .util import now_ts

_lock = threading.Lock()


def _conn(db: Path | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db or CFG.db_path), timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


_SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  pw_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'operator',
  totp_enabled INTEGER DEFAULT 0,
  totp_secret TEXT,
  created_at TEXT,
  last_login TEXT
);
CREATE TABLE IF NOT EXISTS scopes(
  id INTEGER PRIMARY KEY,
  cidr TEXT UNIQUE NOT NULL,
  label TEXT,
  added_at TEXT
);
CREATE TABLE IF NOT EXISTS settings(
  key TEXT PRIMARY KEY,
  value TEXT
);
CREATE TABLE IF NOT EXISTS jobs(
  id TEXT PRIMARY KEY,
  mode TEXT, scope TEXT, state TEXT, message TEXT,
  started_at TEXT, finished_at TEXT, progress INTEGER DEFAULT 0,
  counts TEXT
);
CREATE TABLE IF NOT EXISTS devices(
  id TEXT PRIMARY KEY,
  name TEXT, ip TEXT, mac TEXT, vendor TEXT, kind TEXT, source TEXT,
  sys_descr TEXT, first_seen TEXT, last_seen TEXT
);
CREATE TABLE IF NOT EXISTS interfaces(
  id TEXT PRIMARY KEY,
  device_id TEXT, if_index INTEGER, if_descr TEXT, if_type TEXT,
  mac TEXT, last_seen TEXT
);
CREATE TABLE IF NOT EXISTS links(
  id TEXT PRIMARY KEY,
  source TEXT, target TEXT, kind TEXT, protocol TEXT,
  confidence REAL, status TEXT, first_seen TEXT, last_seen TEXT
);
CREATE TABLE IF NOT EXISTS observations(
  id TEXT PRIMARY KEY,
  job_id TEXT, kind TEXT, source TEXT, observer TEXT,
  payload TEXT, observed_at TEXT, signature TEXT
);
CREATE INDEX IF NOT EXISTS idx_links_s ON links(source);
CREATE INDEX IF NOT EXISTS idx_links_t ON links(target);
CREATE INDEX IF NOT EXISTS idx_if_dev ON interfaces(device_id);
"""


def init_db() -> None:
    with _lock:
        conn = _conn()
        try:
            conn.executescript(_SCHEMA)
            conn.commit()
        finally:
            conn.close()


def q(sql: str, params: tuple = ()) -> list[dict]:
    with _lock:
        conn = _conn()
        try:
            rows = conn.execute(sql, params).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def q1(sql: str, params: tuple = ()) -> dict | None:
    rows = q(sql, params)
    return rows[0] if rows else None


def run(sql: str, params: tuple = ()) -> int:
    with _lock:
        conn = _conn()
        try:
            cur = conn.execute(sql, params)
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()


# ---------- settings ----------

def get_setting(key: str, default: str = "") -> str:
    row = q1("SELECT value FROM settings WHERE key=?", (key,))
    return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    run("INSERT INTO settings(key,value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))


def get_json_setting(key: str, default=None):
    raw = get_setting(key, "")
    if not raw:
        return default
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return default


def set_json_setting(key: str, value) -> None:
    set_setting(key, json.dumps(value))


# ---------- users ----------

def create_user(username: str, pw_hash: str, salt: str, role: str) -> None:
    run(
        "INSERT OR IGNORE INTO users(username,pw_hash,salt,role,created_at)"
        " VALUES(?,?,?,?,?)",
        (username, pw_hash, salt, role, now_ts()),
    )


def ensure_default_admin() -> None:
    row = q1("SELECT id FROM users WHERE username='admin'")
    if row:
        return
    import hashlib
    from .util import pbkdf2
    salt = hashlib.sha256(b"ntm-bootstrap-salt").digest()
    create_user("admin", pbkdf2("admin123", salt), salt.hex(), "admin")


def get_user(username: str) -> dict | None:
    return q1("SELECT * FROM users WHERE username=?", (username,))


def list_users() -> list[dict]:
    return q("SELECT id,username,role,totp_enabled,created_at,last_login FROM users ORDER BY id")


def get_conn(db: Path | None = None) -> sqlite3.Connection:
    """Raw connection for long-lived/synchronous app code (WAL, FK on). The
    caller owns closing it. Used by engine._runner for job result writes.
    """
    return _conn(db or CFG.db_path)


def upsert_job(job: dict) -> None:
    """Insert or refresh a job record (jobs table). job is engine's in-memory
    dict keyed: id,mode,scope,state,message,progress,started_at,finished_at,
    created_count(s). Keeps history window + an ML-style staged 'counts' slot.
    """
    run(
        "INSERT INTO jobs(id,mode,scope,state,message,progress,started_at,"
        "finished_at,counts) VALUES(?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(id) DO UPDATE SET state=excluded.state,"
        " progress=excluded.progress, message=excluded.message,"
        " finished_at=excluded.finished_at, counts=excluded.counts",
        (job.get("id", ""), job.get("mode", "?"), job.get("scope", ""),
         job.get("state", "queued"), job.get("message", ""),
         int(job.get("progress", 0)), job.get("started_at", ""),
         job.get("finished_at", ""), json.dumps(job.get("counts", {}))),
    )


def get_job(job_id: str) -> dict | None:
    return q1("SELECT * FROM jobs WHERE id=?", (job_id,))