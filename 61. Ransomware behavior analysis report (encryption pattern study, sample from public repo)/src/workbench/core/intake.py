from __future__ import annotations

import hashlib
import os
import shutil
from datetime import datetime, timezone
from typing import Optional

from .models import Sample
from .workspace import now_iso

# architecture.md section 6.1 / 6.2: hash-first intake, SHA-256 verified,
# deduplicated, quarantined copy only (files are NEVER executed).

_MAGIC_HINTS = (
    (b"PK\x03\x04", "zip/office container"),
    (b"PK\x05\x06", "zip empty container"),
    (b"\x89PNG\r\n\x1a\n", "png image"),
    (b"\xff\xd8\xff", "jpeg image"),
    (b"%PDF-", "pdf document"),
    (b"MZ", "pe executable"),
    (b"\x7fELF", "elf executable"),
    (b"\xca\xfe\xba\xbe", "mach-o fat / java class"),
    (b"GIF87a", "gif image"),
    (b"GIF89a", "gif image"),
    (b"BM", "bmp image"),
    (b"RIFF", "riff container (wav/avi)"),
    (b"SQLite format 3", "sqlite database"),
    (b"{\r\n", "json-ish text"),
    (b"<!DOCTYPE", "xml/html document"),
    (b"{\x0c\xd6", "crx/chrome extension"),
)


def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def magic_hint(data: bytes) -> tuple[str, str]:
    raw = data[:16]
    hex_prefix = data[:8].hex()
    for sig, label in _MAGIC_HINTS:
        if raw.startswith(sig):
            return hex_prefix, label
    return hex_prefix, "unknown/raw"


def vault_path_for(vault_dir: str, sha256: str) -> str:
    return os.path.join(vault_dir, sha256 + ".bin")


def ingest(path: str, vault_dir: str) -> tuple[Sample, bool]:
    """Quarantine one file into the vault.

    Returns the Sample record and whether it was newly quarantined (dedupe flag).
    """
    sha = sha256_file(path)
    dest = vault_path_for(vault_dir, sha)
    already = os.path.exists(dest)

    with open(path, "rb") as f:
        head = f.read(64)
    hex_prefix, hint = magic_hint(head)

    if not already:
        shutil.copy2(path, dest)
        try:
            os.utime(dest, None)
        except OSError:
            pass

    sample = Sample(
        sha256=sha,
        original_name=os.path.basename(path),
        size=os.path.getsize(path),
        ext=os.path.splitext(path)[1].lower() or "none",
        magic_hex=hex_prefix,
        magic_hint=hint,
        quarantined_path=dest,
        created_iso=now_iso(),
    )
    return sample, (not already)


def read_quarantined(sample: Sample) -> bytes:
    with open(sample.quarantined_path, "rb") as f:
        return f.read()


def human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024.0
    return f"{n:.1f} GB"