"""Encoding/decoding toolbox — recipe ops are pure functions (RiskClass: PURE).

Side-effect free, all bounded (A04: no algorithmic bombs). Round-trip property
tested in tests/test_recipes.py.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import urllib.parse


class OpError(ValueError):
    """Raised when an op cannot process the input."""


def b64_encode(data: bytes) -> bytes:
    return base64.b64encode(data)


def b64_decode(data: bytes) -> bytes:
    try:
        return base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError) as e:
        raise OpError(f"invalid base64: {e}") from e


def b32_encode(data: bytes) -> bytes:
    return base64.b32encode(data)


def b32_decode(data: bytes) -> bytes:
    try:
        return base64.b32decode(data, casefold=True)
    except (binascii.Error, ValueError) as e:
        raise OpError(f"invalid base32: {e}") from e


def b85_encode(data: bytes) -> bytes:
    return base64.b85encode(data)


def b85_decode(data: bytes) -> bytes:
    try:
        return base64.b85decode(data)
    except (binascii.Error, ValueError) as e:
        raise OpError(f"invalid base85: {e}") from e


def hex_encode(data: bytes) -> bytes:
    return data.hex().encode("ascii")


def hex_decode(data: bytes) -> bytes:
    try:
        return bytes.fromhex(data.decode("ascii", "strict").strip())
    except (ValueError, UnicodeDecodeError) as e:
        raise OpError(f"invalid hex: {e}") from e


def url_decode(data: bytes) -> bytes:
    return urllib.parse.unquote_to_bytes(data.decode("latin-1"))


def url_encode(data: bytes) -> bytes:
    return urllib.parse.quote_from_bytes(data).encode("ascii")


def rot13(data: bytes) -> bytes:
    return codecs.encode(data.decode("latin-1"), "rot13").encode("latin-1")


def xor(data: bytes, key: bytes) -> bytes:
    if not key:
        raise OpError("empty XOR key")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def xor_brute_single(data: bytes, limit: int = 256) -> list[tuple[int, bytes]]:
    """Brute-force single-byte XOR keys (classic CTF move). Bounded to 256 tries."""
    out: list[tuple[int, bytes]] = []
    for k in range(limit):
        out.append((k, bytes(b ^ k for b in data)))
    return out


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).hexdigest().encode("ascii")


def to_text(data: bytes, errors: str = "replace") -> str:
    return data.decode("utf-8", errors=errors)


OPS: dict[str, callable] = {
    "b64_encode": b64_encode,
    "b64_decode": b64_decode,
    "b32_encode": b32_encode,
    "b32_decode": b32_decode,
    "b85_encode": b85_encode,
    "b85_decode": b85_decode,
    "hex_encode": hex_encode,
    "hex_decode": hex_decode,
    "url_encode": url_encode,
    "url_decode": url_decode,
    "rot13": rot13,
    "sha256": sha256,
}

# Ops taking an extra key argument (typed at the command bus, A03).
KEYED_OPS: dict[str, callable] = {
    "xor": xor,
}

RISK_CLASS = "PURE"  # every op in this module is side-effect free
