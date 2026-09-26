from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

GENESIS = "0" * 64
AUDIT_HEADER = {"record": "TimelineBuilder audit log", "version": 1}


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _digest(prev_hash: str, payload: dict[str, Any]) -> str:
    import hashlib

    material = (prev_hash + "|" + _canonical(payload)).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


@dataclass
class AuditRecord:
    seq: int
    timestamp: str
    actor: str
    action: str
    target: str
    outcome: str
    detail: dict[str, Any]
    prev_hash: str
    hash: str


class AuditLogger:
    def __init__(self, path: str | Path, actor: str = "analyst", case_id: str = ""):
        self.path = Path(path)
        self.actor = actor
        self.case_id = case_id
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists() or self.path.stat().st_size == 0:
            with open(self.path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(_canonical(AUDIT_HEADER) + "\n")
        self._seq, self._last_hash = self._load_head()

    def _load_head(self) -> tuple[int, str]:
        seq = 0
        last = GENESIS
        for record in self._iter_records():
            if "hash" not in record:
                continue
            seq = int(record.get("seq", seq))
            last = record["hash"]
        return seq, last

    def _iter_records(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return
        with open(self.path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue

    def log(self, action: str, target: str = "", outcome: str = "success", **detail: Any) -> AuditRecord:
        with self._lock:
            self._seq += 1
            payload = {
                "seq": self._seq,
                "ts": datetime.now(timezone.utc).isoformat(),
                "actor": self.actor,
                "case_id": self.case_id,
                "action": action,
                "target": target,
                "outcome": outcome,
                "detail": detail or {},
            }
            record_hash = _digest(self._last_hash, payload)
            full = dict(payload)
            full["prev_hash"] = self._last_hash
            full["hash"] = record_hash
            with open(self.path, "a", encoding="utf-8", newline="\n") as handle:
                handle.write(_canonical(full) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            self._last_hash = record_hash
            return AuditRecord(
                seq=full["seq"],
                timestamp=full["ts"],
                actor=full["actor"],
                action=full["action"],
                target=full["target"],
                outcome=full["outcome"],
                detail=full["detail"],
                prev_hash=full["prev_hash"],
                hash=full["hash"],
            )

    def tail(self, count: int = 100) -> list[dict[str, Any]]:
        records = [r for r in self._iter_records() if "hash" in r]
        return records[-count:]

    def verify(self) -> tuple[bool, str]:
        return verify_audit_chain(self.path)


def verify_audit_chain(path: str | Path) -> tuple[bool, str]:
    path = Path(path)
    if not path.exists():
        return False, "audit log not found"
    prev = GENESIS
    expected_seq = 1
    count = 0
    with open(path, "r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                return False, f"malformed JSON at line {line_no}"
            if "hash" not in record:
                continue
            stored_prev = record.pop("prev_hash", None)
            stored_hash = record.pop("hash", None)
            if stored_prev != prev:
                return False, f"broken chain link at line {line_no} (seq {record.get('seq')})"
            recomputed = _digest(prev, record)
            if recomputed != stored_hash:
                return False, f"hash mismatch at line {line_no} (seq {record.get('seq')})"
            if int(record.get("seq", 0)) != expected_seq:
                return False, f"sequence gap at line {line_no}"
            prev = stored_hash
            expected_seq += 1
            count += 1
    return True, f"chain intact ({count} records)"
