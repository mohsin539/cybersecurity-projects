"""Hash-chained audit ledger (ISO A.8.15/A.8.16, NIST AU-2..AU-12).

Append-only JSONL. Every event is chained: event.hash = SHA-256 over the
canonical event body including prev_hash. Any tamper is detected IMMEDIATELY
on load (AuditTamperedError) and on demand via verify() (memory.md fail-closed).
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from pathlib import Path

from .integrity import canonical_json, sha256_text

# Audit event taxonomy (NIST AU-2 style) — actions used by the pipeline.
ACTION_GENESIS = "LEDGER_GENESIS"
ACTION_SAMPLE_SEALED = "SAMPLE_SEALED"
ACTION_STRINGS_DONE = "ENGINE_STRINGS_DONE"
ACTION_PE_DONE = "ENGINE_PE_DONE"
ACTION_INTEL_DONE = "INTEL_LOOKUP_DONE"
ACTION_CARD_GENERATED = "TRIAGE_CARD_GENERATED"
ACTION_INTEL_EGRESS = "INTEL_EGRESS"
ACTION_IOC_ADDED = "IOC_ADDED"
ACTION_CASE_SEALED = "CASE_SEALED"
ACTION_VERIFY_OK = "CHAIN_VERIFY_OK"

_ORDER = ("event_id", "seq", "ts", "actor", "action", "payload", "prev_hash")


def _chain_text(ev: dict) -> str:
    """Canonical event body — the exact bytes that get hashed."""
    return canonical_json({k: ev[k] for k in _ORDER})


class AuditTamperedError(Exception):
    """Raised when the chain fails verification on load/verify."""


class AuditLedger:
    """An append-only, single-writer, hash-chained audit ledger."""

    def __init__(self, path: str | Path, genesis_actor: str = "system",
                 genesis_action: str = ACTION_GENESIS):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._events: list[dict] = []
        if self.path.exists():
            self._load()
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._append_event({
                "actor": genesis_actor,
                "action": genesis_action,
                "payload": {"schema": "sap.audit.v1"},
            })

    # ------------------------------------------------------------------ load
    def _load(self) -> None:
        events: list[dict] = []
        prev: str | None = None
        with open(self.path, "r", encoding="utf-8", newline="\n") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise AuditTamperedError(
                        f"torn line {lineno} in {self.path.name}") from exc
                if ev.get("prev_hash") != prev:
                    raise AuditTamperedError(
                        f"broken chain at line {lineno} (prev_hash mismatch)")
                if ev.get("hash") != sha256_text(_chain_text(ev)):
                    raise AuditTamperedError(
                        f"hash mismatch at line {lineno}")
                prev = ev.get("hash")
                events.append(ev)
        if not events or events[0]["action"] not in (ACTION_GENESIS, "CUSTODY_GENESIS"):
            raise AuditTamperedError("ledger is missing its genesis event")
        self._events = events

    # ------------------------------------------------------------------ write
    def _append_event(self, body: dict) -> dict:
        seq = len(self._events) + 1
        ev = {
            "event_id": uuid.uuid4().hex,
            "seq": seq,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "actor": body["actor"],
            "action": body["action"],
            "payload": body.get("payload", {}),
            "prev_hash": self._events[-1]["hash"] if self._events else None,
        }
        ev["hash"] = sha256_text(_chain_text(ev))
        self._events.append(ev)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(ev, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return ev

    def log(self, actor: str, action: str, payload: dict | None = None) -> dict:
        with self._lock:
            return self._append_event({
                "actor": actor,
                "action": action,
                "payload": payload or {},
            })

    @property
    def events(self) -> tuple[dict, ...]:
        with self._lock:
            return tuple(self._events)

    @property
    def head(self) -> str | None:
        with self._lock:
            return self._events[-1]["hash"] if self._events else None

    @property
    def count(self) -> int:
        with self._lock:
            return len(self._events)

    # ------------------------------------------------------------------ verify
    def verify(self) -> bool:
        """Re-read the file from disk and re-walk the full chain."""
        try:
            probe = AuditLedger(self.path)
        except AuditTamperedError:
            return False
        with self._lock:
            return len(probe._events) == len(self._events) \
                and probe._events[-1]["hash"] == self._events[-1]["hash"]

    def seal(self, signer, actor: str = "system") -> dict:
        """Freeze the chain: Ed25519 (or fallback) signature over the head.

        Returns the seal object; later appends invalidate the seal by design
        (state.md W3).
        """
        head = self.head
        if head is None:
            raise AuditTamperedError("cannot seal an empty ledger")
        signature_hex = signer.sign_text(head)
        seal = {
            "ledger": self.path.name,
            "chain_head": head,
            "events": self.count,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "signature_hex": signature_hex,
        }
        self._seal_path().parent.mkdir(parents=True, exist_ok=True)
        self._seal_path().write_text(
            json.dumps(seal, indent=2, sort_keys=True), encoding="utf-8")
        self.log(actor, ACTION_CASE_SEALED,
                 {"chain_head": head, "events": self.count})
        return seal

    def _seal_path(self) -> Path:
        return self.path.parent / "seal.json"