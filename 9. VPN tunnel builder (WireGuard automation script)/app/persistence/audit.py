"""Hash-chained, append-only, tamper-evident audit log (NIST AU-2..6, A.8.15).

Every event links to the SHA-256 of the previous event:
    event_hash = SHA256( prev_hash || canonical(event_json) )

Verify() replays the chain and reports any break — audit evidence for an ISMS
(ISO 27001 A.8.15). The file is opened in append mode; detail strings are
redacted by the caller layer before being written.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path


def canonical_json(record: dict) -> str:
    try:
        return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise ValueError("event not JSON-serializable") from exc


def compute_hash(prev_hash: str, record: dict) -> str:
    payload = prev_hash + "|" + canonical_json(record)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _last_hash(self) -> tuple[str, dict | None]:
        last: dict | None = None
        if self.path.exists():
            try:
                with open(self.path, "rb") as fh:
                    fh.seek(0, os.SEEK_END)
                    size = fh.tell()
                    if size > 0:
                        fh.seek(max(0, size - 4096))
                        tail = fh.read().decode("utf-8", errors="replace").rstrip("\n")
                        line = (tail.split("\n") or [""])[-1]
                        if line.strip():
                            last = json.loads(line)
            except (ValueError, OSError):
                last = None
        if last:
            return str(last.get("event_hash", "")), last
        return "", None

    def append(
        self,
        action: str,
        actor: str,
        session: str,
        target: str,
        result: str,
        detail: str = "",
        ts: str | None = None,
    ) -> dict:
        prev_hash, _ = self._last_hash()
        record = {
            "ts": ts or datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "action": action,
            "actor": actor,
            "session": session,
            "target": target,
            "result": result,
            "detail": detail,
        }
        event_hash = compute_hash(prev_hash, record)
        record["prev_hash"] = prev_hash
        record["event_hash"] = event_hash
        line = json.dumps(record, sort_keys=False) + "\n"
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())
        return record

    def read_all(self) -> list[dict]:
        if not self.path.exists():
            return []
        events = []
        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except ValueError:
                    events.append({
                        "ts": "-", "action": "audit.corrupt", "actor": "-",
                        "session": "-", "target": self.path.name, "result": "ERR",
                        "detail": "unparsable audit line",
                        "prev_hash": "", "event_hash": "",
                    })
        return events

    def recent(self, limit: int = 100) -> list[dict]:
        return self.read_all()[-limit:]

    def verify(self) -> tuple[bool, list[dict]]:
        """Replay the chain. Returns (valid, list of broken events)."""
        prev = ""
        broken: list[dict] = []
        for ev in self.read_all():
            payload = {k: ev[k] for k in ev if k not in ("event_hash", "prev_hash")}
            expected = compute_hash(ev.get("prev_hash", ""), payload)
            if ev.get("event_hash") != expected:
                broken.append(ev)
            prev = ev.get("event_hash", prev)
        return (len(broken) == 0), broken

    def export(self, destination: Path) -> None:
        with open(self.path, "r", encoding="utf-8") as src, \
             open(destination, "w", encoding="utf-8") as dst:
            dst.write(src.read())

    def prune(self, retention_days: int) -> int:
        """Remove events older than retention_days (returns removed count).
        Not append-only-safe if chattr +a is active — handled by caller.
        """
        if retention_days <= 0:
            return 0
        cutoff = datetime.now(timezone.utc).timestamp() - retention_days * 86400
        all_events = self.read_all()
        kept = []
        for ev in all_events:
            try:
                ts = datetime.fromisoformat(ev.get("ts", "")).timestamp()
            except ValueError:
                kept.append(ev)
                continue
            if ts >= cutoff:
                kept.append(ev)
        removed = len(all_events) - len(kept)
        if removed:
            with open(self.path, "w", encoding="utf-8") as fh:
                for ev in kept:
                    fh.write(canonical_json(ev) + "\n")
        return removed