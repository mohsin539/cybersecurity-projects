from __future__ import annotations

import hashlib
import json
import threading

from .config import CFG
from .util import hash_val, now_ts

_lock = threading.Lock()


def _key() -> bytes:
    p = CFG.audit_key_path
    if not p.exists():
        import os
        p.write_bytes(os.urandom(32))
    return p.read_bytes()


class Audit:
    """Append-only, hash-chained JSONL audit ledger.

    Each record embeds ``prev_hash`` and ``hash`` = sha256(canonical_json + prev)
    signed-domain keyed, making tampering detectable. Verify walks the chain.
    Credentials and raw sensitive values must never be passed here.
    """

    def __init__(self) -> None:
        self.path = CFG.audit_path
        self._seq = 0

    def _load_seq(self) -> int:
        if not self.path.exists():
            return 0
        last = None
        try:
            lines = self.path.read_text("utf-8").splitlines()
            if lines and lines[-1].strip():
                last = json.loads(lines[-1])
                return int(last.get("seq", 0))
        except (OSError, ValueError):
            pass
        return 0

    def next_hash(self, prev: str, record: dict) -> str:
        blob = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(_key() + b"|" + prev.encode() + b"|" + blob).hexdigest()

    def append(self, actor: str, action: str, target: str = "",
               detail: dict | None = None, level: str = "info") -> dict:
        with _lock:
            if not self._seq:
                self._seq = self._load_seq()
            if not self.path.exists():
                self.path.parent.mkdir(parents=True, exist_ok=True)
            prev = "0" * 64
            if self.path.exists() and self.path.stat().st_size > 0:
                try:
                    last = json.loads(self.path.read_text("utf-8").splitlines()[-1])
                    prev = last["hash"]
                except (OSError, ValueError, KeyError):
                    pass
            self._seq += 1
            rec = {
                "seq": self._seq,
                "ts": now_ts(),
                "actor": actor,
                "action": action,
                "target": target,
                "detail": detail or {},
                "level": level,
            }
            rec["prev_hash"] = prev
            rec["hash"] = self.next_hash(prev, rec)
            line = json.dumps(rec) + "\n"
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line)
            return rec

    def tail(self, n: int = 200) -> list[dict]:
        if not self.path.exists():
            return []
        lines = self.path.read_text("utf-8").splitlines()[-n:]
        out = []
        for ln in lines:
            try:
                out.append(json.loads(ln))
            except ValueError:
                continue
        return out

    def verify(self) -> dict:
        status = {"ok": True, "records": 0, "broken_at": None}
        prev = "0" * 64
        if not self.path.exists():
            return {"ok": True, "records": 0, "broken_at": None}
        for ln in self.path.read_text("utf-8").splitlines():
            try:
                rec = json.loads(ln)
            except ValueError:
                status["ok"] = False
                status["broken_at"] = "malformed-line"
                return status
            exp = self.next_hash(prev, rec)
            if rec.get("prev_hash", "") != prev or rec.get("hash") != exp:
                status["ok"] = False
                status["broken_at"] = f"seq={rec.get('seq')}"
                return status
            prev = rec["hash"]
            status["records"] += 1
        return status


AUDIT = Audit()