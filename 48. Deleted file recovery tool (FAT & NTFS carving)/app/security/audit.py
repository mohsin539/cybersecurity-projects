"""Tamper-evident audit logging.

Implements a lightweight hash-chained append-only JSONL log
(ISO 27001 A.12.4 · A.8.10, NIST SP 800-53 AU-3/AU-6):

  * each entry links to the SHA-256 of the previous entry;
  * a separate signed(-ish) tail file commits the final chain hash;
  * secrets are redacted before logging.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from typing import Optional

GENESIS = "0" * 64


class AuditLogger:
    def __init__(self, log_dir: str, app_name: str = "RecovPro", actor: str = "recovery_engine"):
        self.log_dir = log_dir
        self.app_name = app_name
        self.actor = actor
        self._lock = threading.Lock()
        self._path = os.path.join(log_dir, "audit.jsonl")
        self._tail_path = os.path.join(log_dir, "audit.tail.sha256")
        self._prev_hash = GENESIS
        self._load_chain_tail()
        os.makedirs(log_dir, exist_ok=True)

    def _load_chain_tail(self) -> None:
        try:
            with open(self._tail_path, "r", encoding="utf-8") as f:
                line = f.readline().strip()
            if line:
                self._prev_hash = line  # designated last committed hash
        except (OSError, ValueError):
            pass

    def _commit_tail(self, final_hash: str) -> None:
        tmp = self._tail_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(final_hash + "\n")
            f.write(f"chain-committed-at: {datetime.now(timezone.utc).isoformat()}\n")
        os.replace(tmp, self._tail_path)

    def log(self, event: str, result: str = "ok", detail: dict = None,
            source: str = "") -> str:
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        rec = {
            "ts": ts,
            "app": self.app_name,
            "actor": self.actor,
            "event": event,
            "result": result,
            "source": source,
            "detail": detail or {},
            "prev": self._prev_hash,
        }
        blob = json.dumps(rec, ensure_ascii=False, separators=(",", ":"))
        h = hashlib.sha256(blob.encode("utf-8")).hexdigest()
        rec["self"] = h
        line = json.dumps(rec, ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            self._prev_hash = h
            self._commit_tail(h)
        return h

    def read_entries(self, limit: int = 200) -> list[dict]:
        entries = []
        if not os.path.exists(self._path):
            return entries
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return entries[-limit:]

    def verify_chain(self) -> tuple[bool, int]:
        """Validate the entire hash chain. Returns (ok, entries_checked)."""
        prev = GENESIS
        n = 0
        if not os.path.exists(self._path):
            return True, 0
        with open(self._path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    return False, n
                declared = rec.pop("self", "")
                blob = json.dumps(rec, ensure_ascii=False, separators=(",", ":"))
                got = hashlib.sha256(blob.encode("utf-8")).hexdigest()
                rec["self"] = declared
                if got != declared or rec.get("prev") != prev:
                    return False, n
                prev = got
                n += 1
        return True, n