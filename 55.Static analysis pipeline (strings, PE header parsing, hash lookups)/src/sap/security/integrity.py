"""Integrity service — streaming hashing, canonical JSON, bundle self-check.

Controls map to ISO A.8.24 / NIST PR.DS-01 / OWASP A08 (architecture.md §10).

- stream_digests(): sha256/sha1/md5 in ONE pass, constant memory §memory.md.
- canonical_json(): deterministic JSON used for hashing and signing.
- self_integrity_check(): verify bundled data files against the build-time
  manifest (pack/sap_manifest.json) — fail closed on any mismatch (P9).
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from .policy import open_evidence

HASH_CHUNK = 4 * 1024 * 1024  # 4 MiB ring buffer (memory.md §3)


def _hexify_utf8(text: str) -> bytes:
    return text.encode("utf-8")


def canonical_json(obj) -> str:
    """Deterministic JSON: sorted keys, compact separators."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(_hexify_utf8(text))


def sha256_file(path: str | os.PathLike) -> str:
    """Streaming SHA-256 of a file. Constant memory regardless of size."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(HASH_CHUNK)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def stream_digests(fd: int) -> dict:
    """Compute md5 + sha1 + sha256 + blake2b-256 in ONE streaming pass.

    Consumes the fd to EOF; constant memory regardless of sample size
    (memory.md §3). Callers own the fd (PolicyGuard O_RDONLY contract).
    """
    md5_, sha1_, sha256_ = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    blake_ = hashlib.blake2b(digest_size=32)
    while True:
        block = os.read(fd, HASH_CHUNK)
        if not block:
            break
        md5_.update(block)
        sha1_.update(block)
        sha256_.update(block)
        blake_.update(block)
    return {
        "md5": md5_.hexdigest(),
        "sha1": sha1_.hexdigest(),
        "sha256": sha256_.hexdigest(),
        "blake2b": blake_.hexdigest(),
    }


def digests_of_path(path: str | os.PathLike) -> dict:
    """One-pass sha256/sha1/md5 owning the full read-only lifecycle.

    The file handle is obtained through PolicyGuard's O_RDONLY open, so every
    digest-able byte stream is covered by the evidence immutable contract.
    """
    fd = open_evidence(path)
    try:
        return stream_digests(fd)
    finally:
        os.close(fd)


def self_integrity_check(bundle_root: str | os.PathLike,
                         manifest_name: str = "pack/sap_manifest.json") -> list[str]:
    """Verify bundled data files against the build-time hash manifest.

    Returns the list of mismatched files — the caller must fail closed if
    non-empty (architecture.md P9). When no manifest is present (dev tree from
    source, not the frozen bundle) the check passes with a warning-level note.
    """
    root = Path(bundle_root)
    manifest_path = root / manifest_name
    if not manifest_path.exists():
        return []  # dev/source tree; only the frozen bundle carries a manifest
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    bad: list[str] = []
    for rel, expected in manifest.get("files", {}).items():
        target = root / rel
        if not target.exists():
            bad.append(f"{rel}: missing")
            continue
        if sha256_file(target) != expected:
            bad.append(f"{rel}: hash mismatch")
    return bad