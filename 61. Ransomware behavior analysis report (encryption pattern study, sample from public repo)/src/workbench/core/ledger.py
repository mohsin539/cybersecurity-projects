from __future__ import annotations

import hashlib
import json
import os
import threading
from typing import Iterator, Optional

from .models import AuditEvent

# ISO 27001 A.8.15 / A.8.2 - tamper-evident audit logging (architecture.md section 15.2)
# Each entry carries the hash of the previous entry, forming a hash chain. Rewriting
# any historical entry invalidates the entire chain and is detected by verify().

GENESIS_HASH = "GENESIS"


class Ledger:
    def __init__(self, path: str):
        self.path = os.path.abspath(path)
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        if not os.path.exists(self.path):
            with open(self.path, "w", encoding="utf-8") as f:
                f.write("")
        self._lock = threading.Lock()

    # -- hashing ------------------------------------------------------------
    @staticmethod
    def _payload_hash(entry: dict) -> str:
        payload = {k: v for k, v in entry.items() if k != "hash"}
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, ensure_ascii=True, default=str).encode("utf-8")
        ).hexdigest()

    # -- write --------------------------------------------------------------
    def append(self, actor: str, action: str, detail: str, ts: str) -> AuditEvent:
        if detail is not None and len(detail) > 400:
            detail = detail[:400] + "..."
        with self._lock:
            seq, prev = self._tail()
            entry = {
                "seq": seq,
                "ts": ts,
                "actor": actor,
                "action": action,
                "detail": detail,
                "prev_hash": prev,
            }
            entry["hash"] = self._payload_hash(entry)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=True) + "\n")
            return AuditEvent(**entry)

    def _tail(self) -> tuple[int, str]:
        last = ""
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        last = line
        except OSError:
            return 1, GENESIS_HASH
        if not last:
            return 1, GENESIS_HASH
        try:
            prev = json.loads(last)
        except Exception:
            return 1, GENESIS_HASH
        return int(prev.get("seq", 0)) + 1, prev.get("hash", GENESIS_HASH)

    # -- read ---------------------------------------------------------------
    def entries(self) -> Iterator[AuditEvent]:
        with self._lock:
            if not os.path.exists(self.path):
                return
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield AuditEvent(**json.loads(line))
                    except Exception:
                        continue

    def count(self) -> int:
        return sum(1 for _ in self.entries())

    def verify(self) -> tuple[bool, Optional[int]]:
        """Return (chain_ok, first_broken_line_number)."""
        prev = GENESIS_HASH
        with self._lock:
            if not os.path.exists(self.path):
                return True, None
            with open(self.path, "r", encoding="utf-8") as f:
                for i, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except Exception:
                        return False, i
                    calc = self._payload_hash(entry)
                    if entry.get("hash") != calc or entry.get("prev_hash") != prev:
                        return False, i
                    prev = entry["hash"]
        return True, None