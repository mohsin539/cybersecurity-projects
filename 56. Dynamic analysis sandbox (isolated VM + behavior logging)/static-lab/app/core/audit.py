"""Tamper-evident, hash-chained audit store.

Design (from architecture.md §8):
  * SQLite ledger with append-only entries
  * each row: chain_hash = SHA256(prev_hash || payload || ts || nonce)
  * integrity is protected with a machine-scoped HMAC key (DPAPI-encrypted at rest on Windows)
Verify walks the whole chain and reports tampering.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import time
from typing import Any, Optional

_PFX = "StaticLab::audit::v1"


class AuditStore:
    def __init__(self, db_path: str, hmac_key: bytes):
        self.db_path = db_path
        self.hmac_key = hmac_key
        self._conn = sqlite3.connect(db_path)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS audit_chain ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " chain_hash TEXT NOT NULL,"
            " prev_hash TEXT,"
            " ts TEXT NOT NULL,"
            " payload TEXT NOT NULL,"
            " mac TEXT NOT NULL)"
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    def _payload(self, action: str, target: str, detail: Optional[str]) -> str:
        return json.dumps({"action": action, "target": target, "detail": detail}, sort_keys=True)

    def _make_entry(self, action: str, target: str, detail: Optional[str] = None) -> dict[str, Any]:
        ts = time.strftime("%Y-%m-%dT%H:%M:%S.ffffffZ", time.gmtime())
        payload = self._payload(action, target, detail)
        prev = self.last_hash()
        body = f"{_PFX}|{prev}|{ts}|{payload}".encode()
        mac = hmac.new(self.hmac_key, body, hashlib.sha256).hexdigest()
        nonce = hashlib.sha256(os.urandom(16)).hexdigest()
        chain = hashlib.sha256(body + nonce.encode()).hexdigest()
        return {"ts": ts, "payload": payload, "prev": prev, "mac": mac, "chain": chain}

    # ------------------------------------------------------------------
    def last_hash(self) -> Optional[str]:
        row = self._conn.execute("SELECT chain_hash FROM audit_chain ORDER BY id DESC LIMIT 1").fetchone()
        return row[0] if row else None

    def append(self, action: str, target: str, detail: Optional[str] = None) -> str:
        e = self._make_entry(action, target, detail)
        self._conn.execute(
            "INSERT INTO audit_chain (chain_hash, prev_hash, ts, payload, mac) VALUES (?,?,?,?,?)",
            (e["chain"], e["prev"], e["ts"], e["payload"], e["mac"]),
        )
        self._conn.commit()
        return e["chain"]

    # ------------------------------------------------------------------
    def verify_chain(self) -> tuple[bool, list[str]]:
        """Validate MAC + chain continuity. Returns (ok, tamper_points)."""
        issues: list[str] = []
        prev: Optional[str] = None
        for row in self._conn.execute("SELECT chain_hash, prev_hash, ts, payload, mac FROM audit_chain ORDER BY id ASC"):
            chain, pprev, ts, payload, mac = row
            body = f"{_PFX}|{pprev}|{ts}|{payload}".encode()
            expected_mac = hmac.new(self.hmac_key, body, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected_mac, mac):
                issues.append(f"record {chain[:12]}: MAC mismatch (app/staging tamper)")
            if pprev != prev:
                issues.append(f"record {chain[:12]}: prev_hash <{pprev}> does not match chain")
            prev = chain
        return (len(issues) == 0, issues)

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM audit_chain").fetchone()[0]

    def export(self) -> list[dict[str, str]]:
        return [
            {"chain_hash": r[0], "prev_hash": r[1], "ts": r[2], "payload": r[3], "mac": r[4]}
            for r in self._conn.execute(
                "SELECT chain_hash, prev_hash, ts, payload, mac FROM audit_chain ORDER BY id ASC"
            )
        ]

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass