"""File hashing primitives."""

from __future__ import annotations

import hashlib
from typing import Optional

import pefile


def _read_chunked(path: str, chunk_size: int = 1024 * 1024) -> bytes:
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk


def hash_file(
    path: str,
    algorithms: tuple[str, ...] = ("md5", "sha1", "sha256", "sha512"),
) -> dict[str, str]:
    """Compute requested digest families of a file in a single streaming pass."""
    digests = {alg: hashlib.new(alg) for alg in algorithms}
    for chunk in _read_chunked(path):
        for d in digests.values():
            d.update(chunk)
    return {alg: d.hexdigest() for alg, d in digests.items()}


def hash_bytes(data: bytes, alg: str = "sha256") -> str:
    return hashlib.new(alg, data).hexdigest()


def pe_derived_hashes(path: str) -> dict[str, Optional[str]]:
    """imphash + PE authentihash (as computed by pefile)."""
    out: dict[str, Optional[str]] = {"imphash": None, "authentihash": None}
    try:
        pe = pefile.PE(path, fast_load=True)
    except Exception:
        return out
    try:
        try:
            h = pe.get_imphash()
            out["imphash"] = h or None
        except Exception:
            out["imphash"] = None
        try:
            pe.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
                ]
            )
            out["authentihash"] = pe.get_authentihash()
        except Exception:
            out["authentihash"] = None
    finally:
        pe.close()
    return out