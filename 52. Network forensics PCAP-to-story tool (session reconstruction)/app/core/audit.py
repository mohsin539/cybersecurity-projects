"""audit.py - Append-only audit bus with hash-chaining and HMAC signatures.

Implements architecture.md SS8 ("Audit Function enabled by default"):

  - every operation emits an AuditEntry {ts, actor, action, obj, evidence_hash}
  - event_hash = SHA256(prev_hash | ts | actor | action | obj | evidence_hash)
  - signature   = HMAC-SHA256(audit_key, event_hash)
  - append-only; verify_all() re-walks the chain to detect late tampering
"""

from __future__ import annotations

import hashlib
import hmac
import json

from .security import audit_key
from .state import iso_ts


def _chain_hash(prev_hash: str, ts: str, actor: str, action: str, obj: str, evidence_hash: str) -> str:
    payload = f"{prev_hash}|{ts}|{actor}|{action}|{obj}|{evidence_hash}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditBus:
    def __init__(self, db, actor: str = "analyst"):
        self.db = db
        self.actor = actor

    def log(self, action: str, obj: str = "", evidence_hash: str = "", verdict: str = "ALLOWED", actor: str | None = None) -> dict:
        prev = self.db.audit_last_hash()
        ts = iso_ts()
        event_hash = _chain_hash(prev, ts, actor or self.actor, action, obj, evidence_hash)
        sig = hmac.new(audit_key(), event_hash.encode("utf-8"), hashlib.sha256).hexdigest()
        entry = {
            "ts": ts,
            "actor": actor or self.actor,
            "action": action,
            "obj": obj,
            "evidence_hash": evidence_hash,
            "prev_hash": prev,
            "event_hash": event_hash,
            "signature": sig,
            "verdict": verdict,
        }
        self.db.append_audit(entry)
        return entry

    def verify(self):
        return self.db.audit_verify()


class Auditor:
    """Stateless facade so callers can audit without holding a bus instance."""

    @staticmethod
    def record(db, action, obj="", evidence_hash="", verdict="ALLOWED", actor="system"):
        return AuditBus(db, actor).log(action, obj, evidence_hash, verdict)


def evidence_id_of(payload: bytes) -> str:
    return sha256_bytes(payload)


def jsonify(entry: dict) -> str:
    return json.dumps(entry, sort_keys=True, indent=2)