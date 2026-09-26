#!/usr/bin/env python3
"""Streaming multi-algorithm digest engine.

Uses only the standard library ``hashlib`` (FIPS-validated OpenSSL build on
CPython Windows wheels). Digests are computed incrementally over large chunks,
so a multi-TB image can be handled with constant memory usage.
"""

from __future__ import annotations

import hashlib
import os
from typing import Callable, Dict, Iterable, Optional

from .config import CHUNK_SIZE


def build_hashers(algorithms: Iterable[str]):
    """Create hasher objects. Falls back gracefully on unsupported names."""
    res = {}
    for algo in algorithms:
        name = algo.lower()
        if name == "blake2b":
            res[name] = hashlib.blake2b(digest_size=32)
        else:
            res[name] = hashlib.new(name)
    return res


# CPU identity capabilities (revealed for the tool report).
def self_test_hashlib() -> Dict[str, bool]:
    """Verify each algorithm is available in this runtime."""
    out = {}
    for algo, _label in _algo_labels().items():
        try:
            build_hashers([algo])[algo].update(b"DIHT")
            out[algo] = True
        except (ValueError, TypeError):
            out[algo] = False
    return out


def _algo_labels():
    return {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256",
            "sha3_256": "SHA3-256", "blake2b": "BLAKE2b-256"}


def digest_stream(fp, algorithms: Iterable[str] = ("sha256", "sha3_256"),
                  chunk: int = CHUNK_SIZE,
                  progress_cb: Optional[Callable[[int], None]] = None,
                  cancel_cb: Optional[Callable[[], bool]] = None,
                  total: Optional[int] = None):
    """Read *fp* in chunks, updating one hasher per algorithm.

    Returns ``(digests, bytes_read)`` where digests is ``{algo: hexdigest}``.
    """
    hashers = build_hashers(algorithms)
    nbytes = 0
    while True:
        if cancel_cb is not None and cancel_cb():
            raise InterruptedError("cancelled")
        block = fp.read(chunk)
        if not block:
            break
        for h in hashers.values():
            h.update(block)
        nbytes += len(block)
        if progress_cb is not None:
            progress_cb(nbytes)
    return {a: h.hexdigest() for a, h in hashers.items()}, nbytes


def digest_file(path: str, algorithms: Iterable[str] = ("sha256", "sha3_256"),
                progress_cb=None, cancel_cb=None):
    """Convenience wrapper that digests a file without keeping it open."""
    size = os.path.getsize(path)
    with open(path, "rb") as fp:
        digests, nbytes = digest_stream(
            fp, algorithms, progress_cb=progress_cb,
            cancel_cb=cancel_cb, total=size)
    return digests, nbytes


def write_sha256sums(path: str, hashes: Dict[str, str]):
    """Write a standard POSIX-style SHA256SUMS file (widely used by ftk/dd)."""
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for entry in hashes:
            fh.write(f"{hashes[entry]}  {entry}\n")