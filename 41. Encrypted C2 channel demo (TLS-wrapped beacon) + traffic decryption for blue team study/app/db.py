import sqlite3
import threading
from contextlib import contextmanager

from app.config import DATABASE

_local = threading.local()


def _conn():
    if getattr(_local, "conn", None) is None:
        _local.conn = sqlite3.connect(str(DATABASE), timeout=30)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _local.conn.execute("PRAGMA foreign_keys=ON")
    return _local.conn


@contextmanager
def cursor(commit=False):
    c = _conn()
    cur = c.cursor()
    try:
        yield cur
        if commit:
            c.commit()
    finally:
        cur.close()


def close():
    c = getattr(_local, "conn", None)
    if c is not None:
        c.close()
        _local.conn = None


def init_db():
    with cursor(commit=True) as cur:
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                uuid TEXT PRIMARY KEY,
                agent_name TEXT,
                hw_id TEXT,
                ip TEXT,
                os TEXT,
                status TEXT,
                first_seen TEXT,
                last_seen TEXT,
                beacon_interval REAL,
                jitter REAL,
                ja3 TEXT,
                ja3s TEXT,
                sni TEXT,
                tls_version TEXT,
                cipher TEXT,
                auth_method TEXT,
                risk_score REAL DEFAULT 0,
                kill_switch INTEGER DEFAULT 0,
                notes TEXT
            );

            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT UNIQUE,
                session_uuid TEXT,
                command TEXT,
                status TEXT,
                created_at TEXT,
                issued_at TEXT,
                result_at TEXT,
                result_data TEXT,
                result_size INTEGER
            );

            CREATE TABLE IF NOT EXISTS traffic (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_uuid TEXT,
                ts TEXT,
                event TEXT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                record_len INTEGER,
                meta TEXT,
                ciphertext TEXT,
                plaintext TEXT,
                decrypted INTEGER DEFAULT 0,
                key_id TEXT
            );

            CREATE TABLE IF NOT EXISTS keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_uuid TEXT,
                key_type TEXT,
                label TEXT,
                key_value TEXT,
                created_at TEXT,
                status TEXT
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT,
                rule_id TEXT,
                rule_name TEXT,
                session_uuid TEXT,
                severity TEXT,
                score REAL,
                detail TEXT,
                status TEXT,
                mitre_id TEXT
            );

            CREATE TABLE IF NOT EXISTS rules (
                rule_id TEXT PRIMARY KEY,
                name TEXT,
                severity TEXT,
                support TEXT,
                mitre_id TEXT,
                enabled INTEGER DEFAULT 1,
                description TEXT
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT,
                actor TEXT,
                action TEXT,
                zone TEXT,
                detail TEXT,
                ip TEXT
            );

            CREATE TABLE IF NOT EXISTS report_bundles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT,
                scope TEXT,
                formats TEXT,
                file_name TEXT,
                file_size INTEGER,
                path TEXT
            );
            """
        )


def query_all(sql, params=()):
    with cursor() as cur:
        cur.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]


def query_one(sql, params=()):
    with cursor() as cur:
        cur.execute(sql, params)
        row = cur.fetchone()
        return dict(row) if row else None


def execute(sql, params=()):
    with cursor(commit=True) as cur:
        cur.execute(sql, params)
        return cur.lastrowid


def now_iso():
    import datetime

    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")