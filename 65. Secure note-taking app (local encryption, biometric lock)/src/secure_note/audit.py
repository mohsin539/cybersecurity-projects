"""Tamper-evident, hash-chained audit ledger.

Each event carries: prev_hash (SHA-256 chain), self hash, and an HMAC
signature keyed by the DPAPI-bound audit key. The entire ledger is
encrypted at rest with AES-256-GCM (AK). Corruption or modification is
detectable via chain recomputation (architecture.md section 10).
"""

from __future__ import annotations

import json
import os
import time
import traceback
import uuid

from . import crypto_core as cc
from . import dpapi_binding as dpapi

CAT_AUTH = "AUTH"
CAT_CRYPTO = "CRYPTO"
CAT_DATA = "DATA"
CAT_ADMIN = "ADMIN"
CAT_COMPLIANCE = "COMPLIANCE"
CAT_ERROR = "ERROR"


class AuditLedger:
    def __init__(self, path: str, ak_path: str):
        self.path = path
        self.ak_path = ak_path
        self.ak = self._load_audit_key()
        self._events: list[dict] = []
        self._last_seq = 0
        self._dirty = False
        self.load()

    # -- key -----------------------------------------------------------------
    def _load_audit_key(self) -> bytes:
        if os.path.exists(self.ak_path):
            blob = open(self.ak_path, "rb").read()
            try:
                return dpapi.dpapi_unprotect(blob)
            except OSError:
                return b"__failed_key_%s" % uuid.uuid4().bytes
        ak = cc.random_bytes(32)
        os.makedirs(os.path.dirname(self.ak_path), exist_ok=True)
        with open(self.ak_path, "wb") as f:
            f.write(dpapi.dpapi_protect(ak))
        return ak

    # -- persistence -----------------------------------------------------------
    def load(self) -> None:
        try:
            if os.path.exists(self.path):
                envelope = json.loads(open(self.path, encoding="utf-8").read())
                payload = cc.aead_load(self.ak, envelope)
                data = json.loads(payload.decode("utf-8"))
                self._events = data if isinstance(data, list) else []
            else:
                self._events = []
            self._last_seq = max((e.get("seq", 0) for e in self._events), default=0)
            self._dirty = False
        except Exception:
            # Integrity failure: rename the suspect ledger so it cannot silently
            # masquerade as valid; start a new one and record the event.
            try:
                os.replace(self.path, self.path + ".tampered_%d" % time.time_ns())
            except OSError:
                pass
            self._events = []
            self._last_seq = 0
            self.log("AUDIT_LEDGER_FAILURE", "TAMPER_EVIDENCE",
                     "Ledger failed authentication/decryption; quarantined", CAT_ERROR)

    def _save(self) -> None:
        payload = json.dumps(self._events).encode("utf-8")
        envelope = cc.aead_dump(self.ak, payload)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"schema": 1, **envelope}, f)
        os.replace(tmp, self.path)  # atomic
        self._dirty = False

    # -- writing ---------------------------------------------------------------
    def log(self, action: str, result: str, details: str = "", category: str = CAT_AUTH) -> int:
        prev = self._events[-1]["hash"] if self._events else cc.sha256(b"genesis").hex()
        seq = self._last_seq + 1
        ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        body = {
            "seq": seq,
            "ts": ts,
            "actor": "device-owner",
            "action": action,
            "result": result,
            "category": category,
            "details": details,
            "prev_hash": prev,
        }
        chain_input = f"{prev}|{seq}|{ts}|{body['action']}|{body['result']}|{details}".encode("utf-8")
        body["hash"] = cc.sha256(chain_input).hex()
        body["sig"] = cc.hmac_sha256(self.ak, chain_input).hex()
        self._events.append(body)
        self._last_seq = seq
        self._dirty = True
        try:
            self._save()
        except Exception:
            traceback.print_exc()
        return seq

    # -- verification -----------------------------------------------------------
    def verify_chain(self) -> dict:
        """Recompute the full hash chain; returns verification report."""
        errors = []
        prev = cc.sha256(b"genesis").hex()
        for e in self._events:
            if e.get("prev_hash") != prev:
                errors.append(f"seq {e['seq']}: break in chain (expected prev {prev[:12]}…)")
            chain_input = f"{e['prev_hash']}|{e['seq']}|{e['ts']}|{e['action']}|{e['result']}|{e['details']}".encode("utf-8")
            if e.get("hash") != cc.sha256(chain_input).hex():
                errors.append(f"seq {e['seq']}: hash mismatch")
            if e.get("sig") != cc.hmac_sha256(self.ak, chain_input).hex():
                errors.append(f"seq {e['seq']}: HMAC signature invalid")
            prev = e["hash"]
        ok = not errors
        return {"ok": ok, "errors": errors, "count": len(self._events)}

    def events(self, limit: int | None = None) -> list[dict]:
        if limit:
            return self._events[-limit:]
        return self._events

    # -- export ----------------------------------------------------------------
    def export_rows(self, limit: int | None = None) -> list[dict]:
        return [
            {k: e.get(k) for k in ("seq", "ts", "action", "result", "category", "details")}
            for e in self.events(limit)
        ]


class NullAudit(AuditLedger):
    """In-memory fallback used when running outside a writable profile."""

    def __init__(self):
        object.__setattr__(self, "_events", [])
        object.__setattr__(self, "_last_seq", 0)
        object.__setattr__(self, "ak", b"\x00" * 32)

    def log(self, action, result, details="", category=CAT_AUTH) -> int:
        self._events.append({"seq": self._last_seq + 1, "action": action,
                             "result": result, "details": details, "category": category})
        self._last_seq += 1
        return self._last_seq

    def verify_chain(self) -> dict:
        return {"ok": True, "errors": [], "count": len(self._events)}

    def events(self, limit=None):
        return list(self._events[-limit:] if limit else self._events)

    def export_rows(self, limit=None):
        return list(self._events[-limit:] if limit else self._events)