"""Minimal stdlib bloom filter (BPF) — probabilistic set membership.

Pure-python, deterministic, persisted as a compact header + bytearray blob.
Used for always-on local IOC membership checks (architecture.md §8.1): hits are
then resolved to verdicts through the persisted fact vault (ioc_facts.json).
"""
from __future__ import annotations

import hashlib
import math
import os
import struct

_BIT_SHIFT = 3  # byte = 8 bits


class BloomFilter:
    """Bloom filter with double-hash indexing (sha256 + sha1)."""

    def __init__(self, capacity: int = 1_000_000, error_rate: float = 0.001):
        if capacity < 1 or not (0 < error_rate < 1):
            raise ValueError("capacity>=1 and 0<error_rate<1")
        self.capacity = capacity
        self.error_rate = float(error_rate)
        # m = - n ln(p) / (ln2)^2 ; k = (m/n) ln2
        self.num_bits = max(1, int(-capacity * math.log(error_rate) / (math.log(2) ** 2)))
        self.num_hashes = max(1, int((self.num_bits / capacity) * math.log(2)))
        self._bytes = bytearray((self.num_bits + 7) // 8)
        self._count = 0

    @property
    def count(self) -> int:
        return self._count

    # -- indexing ----------------------------------------------------------
    def _indexes(self, key: bytes):
        h1 = int.from_bytes(hashlib.sha256(key).digest(), "big")
        h2 = int.from_bytes(hashlib.md5(key).digest(), "big")
        m = self.num_bits
        for i in range(self.num_hashes):
            yield (h1 + i * h2 + i) % m

    # -- API ----------------------------------------------------------------
    def add(self, key: bytes) -> None:
        for idx in self._indexes(key):
            self._bytes[idx >> _BIT_SHIFT] |= 1 << (idx & 7)
        self._count += 1

    def add_hex(self, hexdigest: str) -> None:
        self.add(bytes.fromhex(hexdigest.lower()))

    def __contains__(self, key: bytes) -> bool:
        for idx in self._indexes(key):
            if not (self._bytes[idx >> _BIT_SHIFT] & (1 << (idx & 7))):
                return False
        return True

    def contains_hex(self, hexdigest: str) -> bool:
        return bytes.fromhex(hexdigest.lower()) in self

    # -- persistence ----------------------------------------------------------
    def to_bytes(self) -> bytes:
        return (b"SAPB1" + struct.pack("<IIdI", self.capacity, self.num_bits,
                                       self.error_rate, self.num_hashes)
                + bytes(self._bytes))

    @classmethod
    def from_bytes(cls, blob: bytes) -> "BloomFilter":
        if not blob.startswith(b"SAPB1") or len(blob) < 20:
            raise ValueError("not a SAP bloom blob")
        capacity, num_bits, error_rate, num_hashes = struct.unpack(
            "<IIdI", blob[5:25])
        bf = cls.__new__(cls)
        bf.capacity, bf.num_bits, bf.error_rate, bf.num_hashes = (
            capacity, num_bits, error_rate, num_hashes)
        bf._bytes = bytearray(blob[25:])
        bf._count = 0  # count is not persisted; treated as informational
        return bf

    def save(self, path: str | os.PathLike) -> None:
        with open(path, "wb") as fh:
            fh.write(self.to_bytes())

    @classmethod
    def load_or_new(cls, path: str | os.PathLike,
                    capacity: int = 1_000_000,
                    error_rate: float = 0.001) -> "BloomFilter":
        p = os.fspath(path)
        if os.path.exists(p):
            with open(p, "rb") as fh:
                return cls.from_bytes(fh.read())
        bf = cls(capacity=capacity, error_rate=error_rate)
        return bf

    def fingerprint(self) -> str:
        return hashlib.sha256(bytes(self._bytes[:256])).hexdigest()[:16]