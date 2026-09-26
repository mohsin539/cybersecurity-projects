"""Hashing engine — digest families + source-level derived digests.

Produces the digests the whole case is keyed on (architecture.md §5.1 S1):
sha256 (identity), sha1 + md5 (threat-intel interop, FLAGGED for legacy),
and blake2b-256 as the internal content-address key.

Single streaming pass that never loads the sample into memory (memory.md §3).
"""
from __future__ import annotations

from pathlib import Path

from sap.security.integrity import stream_digests
from sap.security.policy import open_evidence


def compute_all(path: str | Path) -> dict:
    """One streaming pass over the sample returning md5/sha1/sha256/blake2b."""
    import os

    fd = open_evidence(path)
    try:
        return stream_digests(fd)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def format_ietf(digests: dict) -> dict:
    """IETF/STIX-friendly digest block (architecture.md §7.3 data mapping)."""
    return {
        "SHA-256": digests["sha256"],
        "SHA-1": digests["sha1"],
        "MD5": digests["md5"],
    }