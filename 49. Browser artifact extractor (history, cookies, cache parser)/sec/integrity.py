"""Evidence integrity primitives: hashing, manifests and keyed chaining.

Maps to:
* NIST SP 800-86 (Integrating Forensic Techniques into Incident Response)
* RFC 3227 (Guidelines for Evidence Collection and Archiving)
* ISO/IEC 27001:2022 A.8.3 (Information backup / evidence handling)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timezone
from typing import Dict, Iterable, List

CHUNK = 1024 * 1024


def sha256_file(path: str) -> str:
    """Stream a file and return its SHA-256 digest (hex). Never loads it whole."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def new_scan_id() -> str:
    """A collision-resistant, sortable scan identifier."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"BAE-{stamp}-{secrets.token_hex(4)}"


def build_manifest(evidence_items: Iterable) -> Dict:
    """Create a machine-verifiable manifest over all collected evidence."""
    entries: List[Dict] = []
    for item in evidence_items:
        entries.append({
            "category": item.category if hasattr(item, "category") else item["category"],
            "source_path": item.source_path if hasattr(item, "source_path") else item["source_path"],
            "sha256": item.source_sha256 if hasattr(item, "source_sha256") else item["source_sha256"],
            "record_count": item.record_count if hasattr(item, "record_count") else item.get("record_count", 0),
            "collected_at": item.collected_at if hasattr(item, "collected_at") else item.get("collected_at", ""),
        })
    canonical = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "algorithm": "SHA-256",
        "item_count": len(entries),
        "manifest_sha256": sha256_bytes(canonical),
        "items": entries,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


class HashChain:
    """Append-only SHA-256 hash chain used to make audit logs tamper-evident.

    Each entry hashes the previous chain value together with the entry payload,
    so any retro-active edit breaks the chain and is detected by
    :meth:`verify`.
    """

    GENESIS = "0" * 64

    def __init__(self, entries: List[Dict]):
        self.entries = entries
        self._head = entries[-1]["chain"] if entries else self.GENESIS

    def append(self, payload: Dict) -> Dict:
        record = dict(payload)
        record["chain_prev"] = self._head
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        record["chain"] = hashlib.sha256(canonical).hexdigest()
        self._head = record["chain"]
        self.entries.append(record)
        return record

    @staticmethod
    def verify(entries: List[Dict]) -> bool:
        prev = HashChain.GENESIS
        for record in entries:
            body = {k: v for k, v in record.items() if k != "chain"}
            body["chain_prev"] = prev
            canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
            if hashlib.sha256(canonical).hexdigest() != record.get("chain"):
                return False
            prev = record["chain"]
        return True


def sign_manifest(manifest: Dict, secret: str) -> str:
    """HMAC-SHA256 the manifest so its authenticity can be checked later."""
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
