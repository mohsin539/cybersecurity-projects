"""Tamper-evident audit logging.

Implements ISO/IEC 27001:2022 A.8.15 (Logging) and the log-record guidance of
NIST SP 800-92 (Guide to Computer Security Log Management). Logs are written as
newline-delimited JSON with a SHA-256 hash chain; every line references the
digest of the previous line so deletions or edits are detectable.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .integrity import HashChain

SEVERITY = {
    "DEBUG": 10, "INFO": 20, "NOTICE": 25,
    "WARNING": 30, "ERROR": 40, "CRITICAL": 50, "SECURITY": 45,
}


class AuditLogger:
    """Hash-chained JSON-lines audit log."""

    def __init__(self, path: Optional[str] = None, actor: str = "operator",
                 severity_floor: str = "INFO"):
        self.path = path
        self.actor = actor
        self.floor = SEVERITY.get(severity_floor, 20)
        self.entries: List[Dict] = []
        self._chain = HashChain([])
        self._load()

    # -- persistence --------------------------------------------------------
    def _load(self) -> None:
        if self.path and os.path.isfile(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if line:
                            self.entries.append(json.loads(line))
                self._chain = HashChain(self.entries)
            except Exception:  # noqa: BLE001
                self.entries = []
                self._chain = HashChain([])

    def _flush(self, record: Dict) -> None:
        if not self.path:
            return
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")

    # -- api ----------------------------------------------------------------
    def log(self, level: str, event: str, message: str = "", **details: Any) -> Dict:
        level = level.upper()
        if SEVERITY.get(level, 20) < self.floor:
            return {}
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "level": level,
            "event": event,
            "actor": self.actor,
            "host": os.environ.get("COMPUTERNAME") or "unknown",
            "pid": os.getpid(),
            "message": message,
            "details": details,
        }
        record = self._chain.append(payload)
        self._flush(record)
        return record

    def info(self, event: str, message: str = "", **d: Any) -> Dict:
        return self.log("INFO", event, message, **d)

    def notice(self, event: str, message: str = "", **d: Any) -> Dict:
        return self.log("NOTICE", event, message, **d)

    def warning(self, event: str, message: str = "", **d: Any) -> Dict:
        return self.log("WARNING", event, message, **d)

    def error(self, event: str, message: str = "", **d: Any) -> Dict:
        return self.log("ERROR", event, message, **d)

    def security(self, event: str, message: str = "", **d: Any) -> Dict:
        return self.log("SECURITY", event, message, **d)

    # -- verification -------------------------------------------------------
    def verify(self) -> bool:
        return HashChain.verify(self.entries)

    def export(self) -> List[Dict]:
        return list(self.entries)
