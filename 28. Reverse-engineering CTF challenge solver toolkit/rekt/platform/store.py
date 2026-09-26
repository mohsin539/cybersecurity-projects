"""SQLite project store (WAL). Parameterized SQL only (OWASP A03).

Content-addressed artifact store: samples are stored by SHA-256 so the sandbox
always works on immutable, deduplicated copies (ARCHITECTURE.md §3.2).
"""
from __future__ import annotations

import hashlib
import sqlite3
import threading
import time
import uuid
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS artifacts(
  sha256 TEXT PRIMARY KEY,
  size INTEGER NOT NULL,
  first_seen REAL NOT NULL,
  note TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  artifact_sha256 TEXT NOT NULL,
  source TEXT NOT NULL,
  kind TEXT NOT NULL,
  detail TEXT NOT NULL,
  created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs(
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  artifact_sha256 TEXT NOT NULL,
  status TEXT NOT NULL,
  policy_json TEXT NOT NULL DEFAULT '{}',
  started REAL NOT NULL,
  finished REAL
);
"""


class ProjectStore:
    """One SQLite file per project. Thread-safe for the job scheduler."""

    def __init__(self, project_dir: Path) -> None:
        self.dir = Path(project_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.dir / "project.db"
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.commit()

    # -- artifacts -------------------------------------------------------
    @staticmethod
    def sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def add_artifact(self, data: bytes, note: str = "") -> str:
        sha = self.sha256(data)
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO artifacts(sha256, size, first_seen, note) "
                "VALUES(?,?,?,?)",
                (sha, len(data), time.time(), note),
            )
            self._conn.commit()
        return sha

    def get_artifact(self, sha: str) -> bytes | None:
        """Artifacts live in the blobs dir, addressed by hash."""
        p = self.dir / "blobs" / sha
        if p.exists():
            return p.read_bytes()
        return None

    def put_blob(self, sha: str, data: bytes) -> None:
        bd = self.dir / "blobs"
        bd.mkdir(exist_ok=True)
        p = bd / sha
        if not p.exists():  # immutable content-addressed store
            tmp = p.with_suffix(".tmp")
            tmp.write_bytes(data)
            tmp.replace(p)  # atomic-ish, avoids torn writes

    def list_artifacts(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT sha256, size, first_seen, note FROM artifacts ORDER BY first_seen DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    # -- findings --------------------------------------------------------
    def add_finding(self, sha: str, source: str, kind: str, detail: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO findings(artifact_sha256, source, kind, detail, created) "
                "VALUES(?,?,?,?,?)",
                (sha, source, kind, detail, time.time()),
            )
            self._conn.commit()

    def findings_for(self, sha: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT source, kind, detail, created FROM findings "
                "WHERE artifact_sha256=? ORDER BY id",
                (sha,),
            ).fetchall()
        return [dict(r) for r in rows]

    # -- jobs ------------------------------------------------------------
    def job_start(self, kind: str, sha: str, policy_json: str) -> str:
        job_id = str(uuid.uuid4())
        with self._lock:
            self._conn.execute(
                "INSERT INTO jobs(id, kind, artifact_sha256, status, policy_json, started) "
                "VALUES(?,?,?,?,?,?)",
                (job_id, kind, sha, "running", policy_json, time.time()),
            )
            self._conn.commit()
        return job_id

    def job_end(self, job_id: str, status: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE jobs SET status=?, finished=? WHERE id=?",
                (status, time.time(), job_id),
            )
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()
