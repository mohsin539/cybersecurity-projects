"""Sample intake service (ISO 27001 A.5.9/5.10, A.5.28; OWASP A03, A05).

- Hashes samples (SHA-256/SHA-1/MD5) via IntegrityService.
- Parses minimal PE headers with the standard library only (no binary dep).
- Never executes the sample (default-deny) - sends to capture runner only on
  explicit analyst action.
- Path canonicalization for transfers; zip/archive extraction is guarded
  against zip-slip.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import struct
import time
from pathlib import Path
from urllib.parse import urlparse

from .crypto import IntegrityService


def _pe_u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def _pe_u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def parse_pe_meta(path: Path) -> dict:
    """Return {machine_spec, subsystem, entry_point} using only stdlib."""
    meta = {"machine": "", "subsystem": "", "entry_point": "", "is_pe": False}
    try:
        with open(path, "rb") as fh:
            head = fh.read(2)
            if head != b"MZ":
                return meta
            fh.seek(0x3C)
            pe_off = struct.unpack("<I", fh.read(4))[0]
            fh.seek(pe_off)
            if fh.read(4) != b"PE\x00\x00":
                return meta
            fh.seek(pe_off + 4)
            machine = _pe_u16(fh.read(2), 0)
            fh.seek(pe_off + 4 + 2 + 2 + 4 + 4 + 4 + 2 + 2 + 2 + 2 + 2 + 2)
            opt_magic = _pe_u16(fh.read(2), 0)
            if opt_magic == 0x10B or opt_magic == 0x20B:
                fh.seek(pe_off + 4 + 2 + 2 + 4 + 4 + 4 + 2 + 2 + 2 + 2 + 2 + 2 + 2 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4)
                entry = _pe_u32(fh.read(4), 0)
                fh.seek(pe_off + 4 + 2 + 2 + 4 + 4 + 4 + 2 + 2 + 2 + 2 + 2 + 2 + 2 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4)
                subsystem = _pe_u16(fh.read(2), 0)
                meta["subsystem"] = {2: "GUI", 3: "CUI"}.get(subsystem, f"0x{subsystem:x}")
                meta["entry_point"] = f"0x{entry:x}"
            meta["machine"] = {
                0x014C: "x86", 0x8664: "x64", 0xAA64: "ARM64", 0x01C0: "ARM",
            }.get(machine, f"0x{machine:x}")
            meta["is_pe"] = True
    except OSError:
        pass
    return meta


class SampleIntake:
    def __init__(self, store, audit) -> None:
        self.store = store
        self.audit = audit
        self.integrity = IntegrityService()

    def ingest(self, path: Path) -> dict:
        p = Path(path).expanduser().resolve()
        if not p.is_file():
            raise ValueError(f"not a file: {p}")
        stat = p.stat()
        if stat.st_size > self._max_size():
            raise ValueError("sample exceeds configured max size")
        sha256 = self.integrity.sha256_file(p)
        raw = p.read_bytes()
        sha1 = hashlib.sha1(raw).hexdigest()
        md5 = hashlib.md5(raw).hexdigest()
        pe = parse_pe_meta(p)
        now = time.time_ns()
        meta = {
            "sha256": sha256, "sha1": sha1, "md5": md5,
            "name": p.name, "size": stat.st_size,
            "pe_machine": pe["machine"], "pe_subsystem": pe["subsystem"],
            "pe_entry": pe["entry_point"], "is_pe": pe["is_pe"],
            "first_seen": now,
        }
        sample_id = self.store.upsert_sample(meta)
        self.audit.record("SAMPLE_INTAKE", {"sample_id": sample_id, "sha256": sha256,
                                            "name": p.name, "size": stat.st_size})
        self.store.add_artifact("unassigned", "sample_static", str(p), sha256, stat.st_size)
        meta["id"] = sample_id
        return meta

    def register_virtual(self, name: str = "demo-sample.bin",
                         hex_seed: str = "demo-corpus-0001") -> dict:
        """Register a synthetic sample for offline replay (no file touched)."""
        import hashlib
        seed = hex_seed.encode()
        meta = {
            "sha256": hashlib.sha256(seed).hexdigest(),
            "sha1": hashlib.sha1(seed).hexdigest(),
            "md5": hashlib.md5(seed).hexdigest(),
            "name": name, "size": 0, "pe_machine": "replay", "pe_subsystem": "N/A",
            "first_seen": time.time_ns(),
        }
        sample_id = self.store.upsert_sample(meta)
        self.audit.record("SAMPLE_INTAKE", {"sample_id": sample_id, "sha256": meta["sha256"],
                                            "name": name, "size": 0, "virtual": True})
        meta["id"] = sample_id
        return meta

    def _max_size(self):
        return 1 << 30


def safe_join(base: Path, name: str) -> Path:
    """Path traversal guard (OWASP A01)."""
    base = base.resolve()
    target = (base / name).resolve()
    if not str(target).startswith(str(base)):
        raise ValueError("path escapes base directory")
    return target


def looks_like_hostile_url(value: str) -> bool:
    """Reject IP-literal / internal host attempts (OWASP A10 stub)."""
    parsed = urlparse(value)
    if parsed.scheme not in ("", "http", "https"):
        return True
    host = parsed.hostname
    if host:
        try:
            ip = ipaddress.ip_address(host)
            if not ip.is_global:
                return True
        except ValueError:
            if re.match(r"(localhost|.*\.internal|.*\.local)$", host, re.I):
                return True
    return False