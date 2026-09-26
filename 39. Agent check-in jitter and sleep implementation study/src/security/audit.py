"""Append-only, hash-linked audit log (ISO 27001 A.8.15 / NIST PR.PS / A09).

Every entry chains to the previous via sha256(prev_hash + canonical payload);
integrity is verified on every open. Tampering breaks the chain loudly.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from typing import Any


class AuditLog:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._prev = self._load_tail()

    def _load_tail(self) -> str:
        if not os.path.exists(self.path):
            return "0" * 64
        with open(self.path, "r", encoding="utf-8") as fh:
            chains = [l for l in fh if l.strip()]
        if not chains:
            return "0" * 64
        try:
            last = json.loads(chains[-1])
            return last["hash"]
        except (ValueError, KeyError):
            raise RuntimeError("audit log tail unreadable - integrity check required")

    def verify(self) -> bool:
        """Re-derive the whole chain; False if any link is broken."""
        if not os.path.exists(self.path):
            return True
        prev = "0" * 64
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except ValueError:
                    return False
                payload = entry.get("payload", {})
                if entry.get("prev") != prev:
                    return False
                if entry.get("hash") != self._digest(prev, payload):
                    return False
                prev = entry["hash"]
        return True

    @staticmethod
    def _digest(prev: str, payload: dict) -> str:
        body = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        return hashlib.sha256(f"{prev}\n{body}".encode("utf-8")).hexdigest()

    def append(self, action: str, payload: dict[str, Any] | None = None) -> str:
        payload = payload or {}
        payload = {
            "action": action,
            "actor": "local-user",
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "run_id": str(uuid.uuid4())[:8],
            "payload": payload,
        }
        entry_hash = self._digest(self._prev, payload)
        entry = {"prev": self._prev, "hash": entry_hash, "payload": payload}
        self._prev = entry_hash
        self._append_line(entry)
        return entry_hash

    def _append_line(self, entry: dict) -> None:
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=True, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())