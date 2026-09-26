from __future__ import annotations

import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Optional

from .models import Sample

_SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256          TEXT UNIQUE NOT NULL,
    original_name   TEXT NOT NULL,
    size            INTEGER NOT NULL,
    ext             TEXT,
    magic_hex       TEXT,
    magic_hint      TEXT,
    quarantined_path TEXT,
    created_iso     TEXT
);
CREATE TABLE IF NOT EXISTS analyses (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id        INTEGER NOT NULL,
    entropy          REAL,
    high_entropy_ratio REAL,
    pattern          TEXT,
    risk_flag        INTEGER,
    confidence       REAL,
    fingerprint_json TEXT,
    report_md        TEXT,
    report_json      TEXT,
    created_iso      TEXT
);
CREATE INDEX IF NOT EXISTS idx_analyses_sample ON analyses(sample_id);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def default_workspace_root() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "RansomLens_Workspace")


class Workspace:
    """Zone-4 style storage: vault (deduped sample copies), reports, ledger, state DB.

    architecture.md mapping: Malware Vault / Artifact Store (section 6.2).
    """

    def __init__(self, root: Optional[str] = None):
        self.root = os.path.abspath(root or default_workspace_root())
        self.vault = os.path.join(self.root, "vault")
        self.reports = os.path.join(self.root, "reports")
        self.ledger_path = os.path.join(self.root, "ledger.jsonl")
        self.db_path = os.path.join(self.root, "workbench.db")
        self._lock = threading.RLock()
        self._ensure_dirs()
        self._init_db()

    # -- lifecycle ----------------------------------------------------------
    def _ensure_dirs(self) -> None:
        for d in (self.root, self.vault, self.reports):
            os.makedirs(d, exist_ok=True)

    def _conn(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path)
        con.row_factory = sqlite3.Row
        return con

    def _init_db(self) -> None:
        with self._lock:
            con = self._conn()
            try:
                con.executescript(_SCHEMA)
                con.commit()
            finally:
                con.close()

    # -- samples ------------------------------------------------------------
    def upsert_sample(self, sample: Sample) -> tuple[int, bool]:
        with self._lock:
            con = self._conn()
            try:
                row = con.execute("SELECT id FROM samples WHERE sha256=?", (sample.sha256,)).fetchone()
                if row is not None:
                    return int(row[0]), False
                cur = con.execute(
                    "INSERT INTO samples (sha256, original_name, size, ext, magic_hex, magic_hint, "
                    "quarantined_path, created_iso) VALUES (?,?,?,?,?,?,?,?)",
                    (sample.sha256, sample.original_name, sample.size, sample.ext, sample.magic_hex,
                     sample.magic_hint, sample.quarantined_path, sample.created_iso),
                )
                con.commit()
                return int(cur.lastrowid), True
            finally:
                con.close()

    def get_sample_id(self, sha256: str) -> Optional[int]:
        with self._lock:
            con = self._conn()
            try:
                row = con.execute("SELECT id FROM samples WHERE sha256=?", (sha256,)).fetchone()
                return int(row[0]) if row is not None else None
            finally:
                con.close()

    # -- analyses -----------------------------------------------------------
    def add_analysis(self, sample_id: int, entropy: float, high_entropy_ratio: float,
                     pattern: str, risk_flag: bool, confidence: float,
                     fingerprint_json: str, report_md: str, report_json: str) -> int:
        with self._lock:
            con = self._conn()
            try:
                cur = con.execute(
                    "INSERT INTO analyses (sample_id, entropy, high_entropy_ratio, pattern, risk_flag, "
                    "confidence, fingerprint_json, report_md, report_json, created_iso) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (sample_id, entropy, high_entropy_ratio, pattern, int(risk_flag), confidence,
                     fingerprint_json, report_md, report_json, now_iso()),
                )
                con.commit()
                return int(cur.lastrowid)
            finally:
                con.close()

    def list_samples(self, limit: int = 200) -> list[dict[str, Any]]:
        return self._query(
            "SELECT * FROM samples ORDER BY id DESC LIMIT ?", (limit,)
        )

    def list_analyses(self, limit: int = 200) -> list[dict[str, Any]]:
        return self._query(
            "SELECT a.*, s.original_name, s.sha256 FROM analyses a "
            "JOIN samples s ON s.id = a.sample_id ORDER BY a.id DESC LIMIT ?",
            (limit,),
        )

    def stats(self) -> dict[str, int]:
        con = self._conn()
        try:
            samples = con.execute("SELECT COUNT(*) FROM samples").fetchone()[0]
            analyses = con.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
            high_risk = con.execute("SELECT COUNT(*) FROM analyses WHERE risk_flag=1").fetchone()[0]
            vault_files = len(os.listdir(self.vault)) if os.path.isdir(self.vault) else 0
            reports = len(self.list_reports()[0]) if os.path.isdir(self.reports) else 0
        finally:
            con.close()
        return {"samples": samples, "analyses": analyses, "high_risk": high_risk,
                "vault_files": vault_files, "reports": reports}

    # -- reports ------------------------------------------------------------
    def list_reports(self) -> tuple[list[str], list[str]]:
        md, js = [], []
        if not os.path.isdir(self.reports):
            return md, js
        for name in sorted(os.listdir(self.reports), reverse=True):
            if name.startswith("RPT_") and name.endswith(".md"):
                md.append(os.path.join(self.reports, name))
            elif name.startswith("RPT_") and name.endswith(".json"):
                js.append(os.path.join(self.reports, name))
        return md, js

    def _query(self, sql: str, params: tuple) -> list[dict[str, Any]]:
        with self._lock:
            con = self._conn()
            try:
                return [dict(r) for r in con.execute(sql, params).fetchall()]
            finally:
                con.close()