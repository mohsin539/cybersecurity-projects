"""Tamper-evident structured audit logging.

Compliance targets:
  - ISO 27001 A.12.4 (logging & monitoring), A.16 (incident)
  - NIST SP 800-53 AU-2/3/6/11 (event logging, chaining, tamper resistance)
  - OWASP Top 10 A09 (logging & monitoring failures)

Every record is written to an append-only JSONL stream. Each entry carries
`prev_hash` and `entry_hash` so any deletion/reordering is detectable, and an
HMAC-SHA256 (keyed by the audit secret) makes forgery detectable. Records are
`fsync`ed before returning.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from app.config import settings

_OUTCOME = Literal["success", "failure"]
_LINES_PER_SHA_FINAL = 100_000


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AuditLogger:
    def __init__(self, log_dir: str | None = None, secret: str | None = None) -> None:
        self.log_dir = Path(log_dir or settings.audit_log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._secret = secret or f"audit::{settings.secret_key}"
        self._tail_hash: str | None = self._load_last_hash()
        self._persister = None

    def set_persister(self, func) -> None:
        """Attach a DB persister (called after each record, best-effort)."""
        self._persister = func

    def _current_logfile(self) -> Path:
        return self.log_dir / "audit.jsonl"

    def _load_last_hash(self) -> str | None:
        logfile = self._current_logfile()
        if not logfile.exists():
            return None
        try:
            lines = logfile.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return None
        for line in reversed(lines):
            try:
                entry = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue
            h = entry.get("entry_hash")
            if h:
                return h
        return None

    def _chain_hash(self, payload: str, prev: str | None = None) -> str:
        return self._compute((prev if prev is not None else self._tail_hash), payload)

    def _compute(self, prev: str | None, payload: str) -> str:
        msg = ((prev or "") + "\n" + payload).encode("utf-8")
        sha = hashlib.sha256(msg).hexdigest()
        hmac_sig = hmac.new(self._secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()
        return f"{sha}:{hmac_sig}"

    def record(
        self,
        action: str,
        *,
        actor: str | None = None,
        actor_type: str = "user",
        outcome: _OUTCOME = "success",
        resource: str | None = None,
        ip: str | None = None,
        details: dict[str, Any] | None = None,
        severity: str = "info",
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "v": 1,
            "ts": _utcnow_iso(),
            "actor": actor,
            "actor_type": actor_type,
            "action": action,
            "outcome": outcome,
            "resource": resource,
            "ip": ip,
            "severity": severity,
        }
        if details:
            # Redact known secret material before it ever touches the log.
            safe = {k: ("[REDACTED]" if _is_secret(k) else v) for k, v in details.items()}
            payload["details"] = safe

        body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        entry_hash = self._chain_hash(body) if settings.audit_enable_tamper_evidence else sha256_only(body)
        entry = dict(payload)
        entry["prev_hash"] = self._tail_hash
        entry["entry_hash"] = entry_hash

        line = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
        with open(self._current_logfile(), "a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())

        self._tail_hash = entry_hash
        if self._persister:
            try:
                self._persister(entry)
            except Exception:  # noqa: BLE001 - audit must never break the API
                pass
        return entry

    def verify_chain(self) -> tuple[bool, str]:
        """Recompute the HMAC/SHA chain over the whole log. Returns (ok, detail)."""
        logfile = self._current_logfile()
        if not logfile.exists():
            return (True, "no log file present")
        prev: str | None = None
        ok = True
        for i, line in enumerate(logfile.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                return (False, f"line {i}: not valid JSON")
            declared = entry.get("entry_hash")
            recomputed = self._compute(prev, entry_body(entry))
            if declared != recomputed:
                return (False, f"line {i}: tampered (hash mismatch)")
            prev = declared
        return (ok, "chained hashes verified OK" if prev else "no entries")


def sha256_only(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def entry_body(entry: dict[str, Any]) -> str:
    """Reconstruct the canonical payload body of a stored entry (without
    prev_hash / entry_hash) so verification is reproducible."""
    payload = {k: v for k, v in entry.items() if k not in ("prev_hash", "entry_hash")}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


_SECRET_KEYS = {"password", "key", "token", "secret", "cookie", "refresh", "authorization", "apikey"}


def _is_secret(key: str) -> bool:
    k = key.lower()
    return any(s in k for s in _SECRET_KEYS)


audit = AuditLogger()