"""Append-only, hash-chained audit service (ISO 27001 A.5.33, A.8.15;
OWASP A09, A08).

Audit entries are chained: entry_hash = HMAC-SHA256(master_hmac_key,
prev_hash || canonical(payload)). A mirrored .jsonl journal is written first
and fsync'd; the SQLite mirror is updated for queryability. `verify_chain`
recomputes the chain and returns affected entries on tamper.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

from .crypto import DPAPIStore, IntegrityService


class AuditService:
    ACTIONS = {
        "APP_START", "APP_EXIT", "POLICY_LOAD", "SAMPLE_INTAKE", "SAMPLE_DELETE",
        "SESSION_START", "SESSION_STOP", "SESSION_ABORT", "EVENT_IMPORT",
        "REPORT_GENERATE", "REPORT_DOWNLOAD", "REPORT_DELETE", "REPORT_SIGN",
        "SETTINGS_CHANGE", "INTEGRITY_CHECK", "AUDIT_EXPORT", "AUDIT_ROTATE_KEYS",
        "AUTH_FAILED", "ACCESS_DENIED", "ACCESS_NAV",
    }

    def __init__(self, data_dir: Path, dapi: DPAPIStore, enabled: bool = True) -> None:
        audit_dir = data_dir / "audit"
        audit_dir.mkdir(parents=True, exist_ok=True)
        self.audit_dir = audit_dir
        self.journal = audit_dir / "audit.jsonl"
        self.db_path = audit_dir / "audit.db"
        self.enabled = enabled
        self.dapi = dapi
        self.integrity = IntegrityService()
        self._lock = threading.Lock()
        self._seq = 0
        self._prev_hash = b"\x00" * 32
        import sqlite3
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS audit_log ("
            " seq INTEGER PRIMARY KEY, ts_ns INTEGER NOT NULL, actor TEXT NOT NULL, "
            " action TEXT NOT NULL, payload JSON NOT NULL, prev_hash TEXT NOT NULL, "
            " entry_hash TEXT NOT NULL UNIQUE)"
        )
        self.conn.commit()
        self._load_tail()
        self.actor = "local-user"

    # ------------------------------------------------------------------- init
    def _load_tail(self) -> None:
        if not self.journal.exists():
            return
        last = None
        with open(self.journal, "rb") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = line
        if last:
            prev = json.loads(last)
            self._seq = int(prev["seq"])
            self._prev_hash = bytes.fromhex(prev["entry_hash"])

    # ----------------------------------------------------------------- record
    def record(self, action: str, payload: dict, actor: str | None = None) -> str | None:
        if not self.enabled:
            return None
        if action not in self.ACTIONS:
            raise ValueError(f"unknown audit action: {action}")
        with self._lock:
            self._seq += 1
            entry = {
                "seq": self._seq,
                "ts_ns": time.time_ns(),
                "actor": actor or self.actor,
                "action": action,
                "payload": payload,
                "prev_hash": self._prev_hash.hex(),
                "entry_hash": "",
            }
            canon = self.integrity.canonical_bytes(
                {k: v for k, v in entry.items() if k != "entry_hash"}
            )
            entry["entry_hash"] = self.integrity.hmac_chain_entry(
                self._prev_hash, canon, self.dapi.get_hmac_key()
            )
            line = json.dumps(entry, separators=(",", ":")) + "\n"
            with open(self.journal, "ab") as fh:
                fh.write(line.encode())
                fh.flush()
                try:
                    fh.flush()
                    import os
                    os.fsync(fh.fileno())
                except OSError:
                    pass
            self.conn.execute(
                "INSERT INTO audit_log(seq, ts_ns, actor, action, payload, prev_hash, entry_hash) "
                "VALUES (?,?,?,?,?,?,?)",
                (entry["seq"], entry["ts_ns"], entry["actor"], entry["action"],
                 json.dumps(entry["payload"]), entry["prev_hash"], entry["entry_hash"]),
            )
            self.conn.commit()
            self._prev_hash = bytes.fromhex(entry["entry_hash"])
            return entry["entry_hash"]

    # ------------------------------------------------------------------- read
    def iter_entries(self, reverse: bool = True) -> list[dict]:
        order = "DESC" if reverse else "ASC"
        rows = self.conn.execute(
            f"SELECT * FROM audit_log ORDER BY seq {order}"
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["payload"] = json.loads(d["payload"] or "{}")
            d["ts_dt"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(d["ts_ns"] / 1e9))
            out.append(d)
        return out

    def count(self) -> int:
        return self._seq

    # --------------------------------------------------------- integrity check
    def verify_chain(self) -> tuple[bool, list[dict]]:
        """Recompute HMAC chain. Returns (ok, [bad_entries])."""
        failures: list[dict] = []
        prev = b"\x00" * 32
        sqlite_rows = {
            r["seq"]: dict(r) for r in self.conn.execute("SELECT * FROM audit_log")
        }
        with open(self.journal, "rb") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    failures.append({"journal_line": lineno, "error": "invalid JSON"})
                    continue
                canon = self.integrity.canonical_bytes(
                    {k: v for k, v in entry.items() if k != "entry_hash"}
                )
                expected = self.integrity.hmac_chain_entry(
                    prev, canon, self.dapi.get_hmac_key()
                )
                if expected != entry.get("entry_hash"):
                    failures.append({
                        "journal_line": lineno, "seq": entry.get("seq"),
                        "error": "chain mismatch",
                    })
                    prev = bytes.fromhex(entry["entry_hash"]) if entry.get("entry_hash") else b"\x00" * 32
                    continue
                prev = bytes.fromhex(entry["entry_hash"])
                if not sqlite_rows.pop(entry["seq"], None):
                    failures.append({"seq": entry.get("seq"), "error": "missing in sqlite mirror"})
        for orphan in sqlite_rows.values():
            failures.append({"seq": orphan["seq"], "error": "orphan in sqlite mirror"})
        return (not failures, failures)

    def export(self, dest: Path) -> dict:
        """Copy the journal + manifest (for SIEM onboarding)."""
        import hashlib
        copy = dest / "audit.jsonl"
        copy.write_bytes(self.journal.read_bytes())
        manifest = {
            "exported_at": time.time_ns(),
            "lines": self.count(),
            "sha256": hashlib.sha256(copy.read_bytes()).hexdigest(),
            "schema": "acsv-audit@1.0",
        }
        (dest / "audit.manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )
        return manifest

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass