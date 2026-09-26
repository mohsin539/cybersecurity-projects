from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Callable

CHUNK_SIZE = 1024 * 1024

ProgressFn = Callable[[int], None]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: str | Path, max_bytes: int | None = None, progress: ProgressFn | None = None) -> str:
    digest = hashlib.sha256()
    total = 0
    with open(Path(path), "rb") as handle:
        while True:
            if max_bytes is not None and total >= max_bytes:
                break
            to_read = CHUNK_SIZE
            if max_bytes is not None:
                to_read = min(CHUNK_SIZE, max_bytes - total)
            chunk = handle.read(to_read)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            if progress is not None:
                progress(total)
    return digest.hexdigest()


def verify_file_hash(path: str | Path, expected: str) -> bool:
    return sha256_file(path).lower() == (expected or "").lower()
