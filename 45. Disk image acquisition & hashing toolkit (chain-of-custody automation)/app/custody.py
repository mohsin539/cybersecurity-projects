#!/usr/bin/env python3
"""Tamper-evident, hash-chained chain-of-custody ledger.

Every custody event is:
  * appended to a JSON ledger file,
  * chained to the previous record via ``prev_hash`` (SHA-256 over the
    canonical serialization),
  * HMAC-SHA256 signed with an operator-derived key (PBKDF2-HMAC-SHA256,
    OWASP-recommended iteration count) so that any alteration is detectable,
  * recorded with an exact UTC timestamp.

The signature key is NEVER stored.  Only a salt + iteration count + key
fingerprint are persisted; re-deriving the key requires the operator's
passphrase, which is mandatory to append new events or audit the chain.
Reserved ``sig``/``tsa`` fields document where an X.509 (eIDAS) signature and
an RFC 3161 trusted-timestamp token will be attached in certified variants.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import platform
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .config import LEDGER_V1

PBKDF2_ITERATIONS = 310_000
KEY_LEN = 32
SALT_LEN = 16
GENESIS = "GENESIS"


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _canonical(record: Dict[str, Any]) -> bytes:
    """Deterministic serialization for hashing/signing (stable key order)."""
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")


def derive_key(passphrase: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations, dklen=KEY_LEN)


def key_fingerprint(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:16]


def machine_id() -> str:
    raw = f"{platform.node()}|{platform.system()}|{os.getenv('USERNAME','')}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]


class Ledger:
    def __init__(self, path: Optional[str] = None):
        self.path = path
        self.meta: Dict[str, Any] = {}
        self.records: List[Dict[str, Any]] = []

    # -- loading -----------------------------------------------------------
    @classmethod
    def create_new(cls, path: str, case_id: str, case_name: str,
                   operator: str, role: str, org: str, passphrase: str):
        led = cls(path)
        salt = secrets.token_bytes(SALT_LEN)
        key = derive_key(passphrase, salt)
        led.meta = {
            "ledger_version": LEDGER_V1,
            "case_id": case_id,
            "case_name": case_name,
            "created": _now_utc(),
            "operator": operator,
            "operator_role": role,
            "operator_org": org,
            "pbkdf2": {"iterations": PBKDF2_ITERATIONS, "salt_hex": salt.hex()},
            "key_fingerprint": key_fingerprint(key),
            "machine_id": machine_id(),
            "note": "Tamper-evident chain-of-custody ledger. Signing key derived "
                    "from operator passphrase; never stored.",
        }
        led.records = []
        led.flush()
        led.append("ledger_created", "Chain-of-custody ledger initialised", key)
        return led

    @classmethod
    def load(cls, path: str) -> "Ledger":
        led = cls(path)
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        led.meta = data["meta"]
        led.records = data["records"]
        return led

    # -- serialization -----------------------------------------------------
    def flush(self) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"meta": self.meta, "records": self.records}, fh,
                      indent=2, ensure_ascii=False)
        os.replace(tmp, self.path)

    # -- signing -----------------------------------------------------------
    def append(self, action: str, description: str, key: bytes,
               exhibit: Optional[str] = None,
               detail: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        prev = self.records[-1]["record_hash"] if self.records else GENESIS
        record = {
            "v": LEDGER_V1,
            "event_id": str(uuid.uuid4()),
            "ts": _now_utc(),
            "machine_id": machine_id(),
            "actor": self.meta["operator"],
            "actor_role": self.meta["operator_role"],
            "org": self.meta["operator_org"],
            "action": action,
            "description": description,
            "exhibit": exhibit,
            "detail": detail or {},
            "prev_hash": prev,
            "record_hash": None,   # sha256 over signed body (own body + prev)
            "hmac": None,          # HMAC-SHA256 over body with derived key
            "sig": None,           # reserved: X.509/eIDAS signature
            "tsa": None,           # reserved: RFC 3161 trusted timestamp token
        }
        body = {
            k: record[k] for k in (
                "v", "event_id", "ts", "machine_id", "actor", "actor_role",
                "org", "action", "description", "exhibit", "detail", "prev_hash")
        }
        record["record_hash"] = hashlib.sha256(_canonical(body)).hexdigest()
        record["hmac"] = hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()
        self.records.append(record)
        self.flush()
        return record

    # -- integrity audit ---------------------------------------------------
    def verify(self, passphrase: str) -> Tuple[bool, List[str]]:
        """Re-derive key from *passphrase*, validate chain + HMAC on every
        record. Returns (ok, problems)."""
        problems: List[str] = []
        salt = bytes.fromhex(self.meta["pbkdf2"]["salt_hex"])
        iters = self.meta["pbkdf2"]["iterations"]
        key = derive_key(passphrase, salt, iters)
        if key_fingerprint(key) != self.meta["key_fingerprint"]:
            return False, ["Passphrase does not match ledger key fingerprint."]

        prev = GENESIS
        for i, rec in enumerate(self.records):
            body = {
                k: rec[k] for k in (
                    "v", "event_id", "ts", "machine_id", "actor", "actor_role",
                    "org", "action", "description", "exhibit", "detail", "prev_hash")
            }
            if body["prev_hash"] != prev:
                problems.append(f"Record #{i} ({rec['action']}): chain broken "
                                f"(prev_hash mismatch).")
            calc = hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()
            if calc != rec.get("hmac"):
                problems.append(f"Record #{i} ({rec['action']}): HMAC invalid.")
            prev = rec["record_hash"]
        return (len(problems) == 0), problems

    def timeline(self) -> List[Dict[str, Any]]:
        """Human-friendly custody timeline, newest first."""
        out = []
        for rec in reversed(self.records):
            out.append({
                "ts": rec["ts"],
                "action": rec["action"],
                "description": rec["description"],
                "exhibit": rec.get("exhibit"),
                "actor": rec["actor"],
            })
        return out

    def tail_hashes(self, exhibit: str) -> List[str]:
        return [r["record_hash"] for r in self.records
                if (r.get("exhibit") or "").lower() == exhibit.lower()]


def sign_bytes(data: bytes, key: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()