"""Cryptographic helpers for tamper-evident processing (NIST SP 800-53 AU-9)."""

import hashlib
import hmac
from datetime import datetime, timezone


def hash_original(value: str, salt: str | None = None) -> str:
    """Never store the original - store only this hash (data minimization)."""
    payload = value.encode("utf-8")
    if salt:
        return hmac.new(salt.encode(), payload, hashlib.sha256).hexdigest()
    return hashlib.sha256(payload).hexdigest()


def hash_redacted(value: str) -> str:
    """Integrity hash of the redacted output."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class MerkleAnchor:
    """Linking Hashes for an append-only, tamper-evident audit chain.

    Each record hash includes the previous record's hash, forming a
    hash chain (blockchain-lite). Periodically the chain root is
    anchored externally (RFC 3161 TSA or public ledger).
    """

    def __init__(self) -> None:
        self._root = "0" * 64
        self._count = 0

    def append(self, record_hash: str) -> str:
        """Append a record; returns its chain position."""
        combined = f"{self._root}|{record_hash}".encode()
        self._root = hashlib.sha256(combined).hexdigest()
        self._count += 1
        return self._root

    @property
    def root(self) -> str:
        return self._root

    @property
    def count(self) -> int:
        return self._count

    def audit_ticket(self) -> dict:
        """Externally anchorable proof of current chain state."""
        return {
            "root": self._root,
            "record_count": self._count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


def hmac_chain_step(root: str, next_hash: str) -> str:
    """One chain step: combine current root with the next record hash."""
    combined = f"{root}|{next_hash}".encode()
    return hashlib.sha256(combined).hexdigest()


def verify_chain(ll: list[str], known_root: str) -> bool:
    """Verify a chain of record hashes against a known root."""
    root = "0" * 64
    for record_hash in ll:
        root = hmac_chain_step(root, record_hash)
    return root == known_root
