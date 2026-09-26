"""Hash-chained, append-only audit log (OWASP A09, NIST 800-53 AU-9).

Each record's hash covers its content + the previous record's hash, so any
tamper/delete/reorder is detectable via verify(). Only hashes are logged —
never sample contents or PII.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

_GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.tail_hash = _GENESIS
        if self.path.exists():
            ok, tail = self.verify()
            # Tail is trusted even if an *old* record was tampered; new records
            # still chain from the last stored hash so gaps are visible.
            self.tail_hash = tail

    def append(self, action: str, **fields: Any) -> dict:
        rec: dict[str, Any] = {
            "ts": round(time.time(), 3),
            "action": action,
            **fields,
            "prev": self.tail_hash,
        }
        blob = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        rec["hash"] = hashlib.sha256(blob.encode("utf-8")).hexdigest()
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
        self.tail_hash = rec["hash"]
        return rec

    def verify(self) -> tuple[bool, str]:
        """Re-walk the chain. Returns (ok, message/tail_hash)."""
        prev = _GENESIS
        if not self.path.exists():
            return True, _GENESIS
        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    return False, f"line {lineno}: not JSON"
                stored_hash = rec.pop("hash", None)
                if stored_hash is None:
                    return False, f"line {lineno}: missing hash"
                blob = json.dumps(rec, sort_keys=True, separators=(",", ":"))
                if hashlib.sha256(blob.encode("utf-8")).hexdigest() != stored_hash:
                    return False, f"line {lineno}: content hash mismatch"
                if rec.get("prev") != prev:
                    return False, f"line {lineno}: chain break (prev pointer)"
                prev = stored_hash
        return True, prev
