"""PE header parsing engine — pefile primary, lief optional cross-check.

architecture.md §5.3:

- DOS/COFF/Optional/Section/Import/Export/Resource/Rich header extraction
- section-level Shannon entropy (packer heuristics)
- overlay detection, checksum verification, timestamp plausibility
- entry-point residency checks (writable / non-executable sections)
- optional lief cross-validation to defeat parser-specific drift (A.8.28)

Memory contract (memory.md §3): the sample is fed to pefile as an RO mmap
view, never fully copied into Python heap. lief cross-check runs only below a
size budget. Failures are captured as structured engine errors (isolation).
"""
from __future__ import annotations

import datetime as _dt
import mmap as _mmap
import os as _os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from sap.security.integrity import canonical_json, sha256_text
from sap.security.policy import open_evidence

try:
    import pefile
    _HAVE_PEFILE = True
except Exception:  # pragma: no cover - pefile is a core dependency
    pefile = None  # type: ignore
    _HAVE_PEFILE = False

try:
    import lief  # optional dual-backend cross-check
    _HAVE_LIEF = True
except Exception:
    lief = None  # type: ignore
    _HAVE_LIEF = False

# lief loads the PE into its own model; skip above this size (memory.md §6).
LIEF_CROSSCHECK_MAX_BYTES = 64 * 1024 * 1024


class PeParseError(Exception):
    reason: str = ""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass
class PeResult:
    status: str = "ok"
    backend: str = "unknown"
    format: str = "PE"
    mz: bool = False
    machine: Optional[str] = None
    machine_id: Optional[str] = None
    bitness: str = "?"
    entry_point: Optional[int] = None
    image_base: Optional[str] = None
    subsystem: Optional[int] = None
    timestamp: Optional[int] = None
    timestamp_utc: Optional[str] = None
    checksum_ok: bool = True
    has_security_cert: bool = False
    has_debug_dir: bool = False
    has_tls_dir: bool = False
    has_reloc_dir: bool = False
    overlay_size: int = 0
    sections: List[dict] = field(default_factory=list)
    imports: List[dict] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    resources: dict = field(default_factory=dict)
    rich: Optional[dict] = None
    anomalies: List[str] = field(default_factory=list)
    cross_check: dict = field(default_factory=dict)
    fingerprint: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "backend": self.backend,
            "format": self.format,
            "mz": self.mz,
            "machine": self.machine,
            "machine_id": self.machine_id,
            "bitness": self.bitness,
            "entry_point": self.entry_point,
            "image_base": self.image_base,
            "subsystem": self.subsystem,
            "timestamp": self.timestamp,
            "timestamp_utc": self.timestamp_utc,
            "checksum_ok": self.checksum_ok,
            "has_security_cert": self.has_security_cert,
            "has_debug_dir": self.has_debug_dir,
            "has_tls_dir": self.has_tls_dir,
            "has_reloc_dir": self.has_reloc_dir,
            "overlay_size": self.overlay_size,
            "sections": self.sections,
            "imports": self.imports,
            "exports": self.exports,
            "resources": self.resources,
            "rich": self.rich,
            "anomalies": self.anomalies,
            "cross_check": self.cross_check,
            "fingerprint": self.fingerprint,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
def _plausible_year(ts: int) -> bool:
    """Heuristic: PE build timestamps outside 1997..2032 are suspicious."""
    try:
        year = _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc).year
        return 1997 <= year <= 2032
    except Exception:
        return False


def _read_only_map(path: str | Path, file_size: int | None):
    """Open via PolicyGuard, sniff MZ, return (mm, fh, file_size, is_mz)."""
    fd = open_evidence(path)
    try:
        head = _os.read(fd, 2)
        if file_size is None:
            file_size = _os.fstat(fd).st_size
        fh = _os.fdopen(fd, "rb")
        fd = None  # ownership transferred to fh
        if file_size == 0:
            fh.close()
            raise PeParseError("empty file")
        try:
            mm = _mmap.mmap(fh.fileno(), 0, access=_mmap.ACCESS_READ)
        except (ValueError, OSError) as exc:
            fh.close()
            raise PeParseError(str(exc)) from exc
        return mm, fh, file_size, head == b"MZ"
    finally:
        if fd is not None:
            _os.close(fd)


def parse_pe(path: str | Path, file_size: int | None = None) -> PeResult:
    """Parse a PE file with pefile over an RO mmap; lief cross-check when able."""
    res = PeResult()
    if not _HAVE_PEFILE:
        res.status = "error"
        res.error = "pefile backend unavailable"
        res.backend = "none"
        return res
    res.backend = "pefile"

    try:
        mm, fh, file_size, res.mz = _read_only_map(path, file_size)
    except (PeParseError, OSError) as exc:
        res.status = "error"
        res.error = str(exc)[:300]
        return res

    pe = None
    try:
        try:
            # fast_load only skips directory parsing; directories are then
            # parsed explicitly over the mmap view (constant-memory design).
            pe = pefile.PE(data=mm, fast_load=True)
        except Exception as exc:
            res.status = "not-pe"
            res.error = str(exc)[:300]
            return res
        try:
            pe.parse_data_directories()
        except Exception as exc:
            res.status = "not-pe"
            res.error = f"directory parse failed: {exc}"[:300]
            return res

        header = getattr(pe, "FILE_HEADER", None)
        opt = getattr(pe, "OPTIONAL_HEADER", None)
        if header is None:
            res.status = "not-pe"
            res.error = "no COFF file header"
            return res
        res.machine_id = hex(header.Machine)
        res.timestamp = header.TimeDateStamp
        res.machine = _pe_machine_name(header.Machine)

        if opt is not None:
            magic = getattr(opt, "Magic", 0)
            res.bitness = "PE32+" if magic == 0x20B else ("PE32" if magic == 0x10B else "?")
            res.entry_point = getattr(opt, "AddressOfEntryPoint", None)
            res.image_base = hex(getattr(opt, "ImageBase", 0))
            res.subsystem = getattr(opt, "Subsystem", None)
            if res.timestamp:
                try:
                    res.timestamp_utc = _dt.datetime.fromtimestamp(
                        res.timestamp, tz=_dt.timezone.utc).isoformat().replace("+00:00", "Z")
                except Exception:
                    res.timestamp_utc = None
            for dd in (getattr(opt, "data_directories", None) or []):
                name = (getattr(dd, "name", "") or "").upper()
                if not getattr(dd, "VirtualAddress", 0):
                    continue
                if "SECURITY" in name:
                    res.has_security_cert = True
                elif "DEBUG" in name:
                    res.has_debug_dir = True
                elif "TLS" in name:
                    res.has_tls_dir = True
                elif "BASERELOC" in name:
                    res.has_reloc_dir = True
            try:
                res.checksum_ok = bool(pe.verify_checksum())
            except Exception:
                res.checksum_ok = False

        # ---- sections -------------------------------------------------------
        for s in getattr(pe, "sections", []) or []:
            raw_name = (getattr(s, "Name", b"") or b"").rstrip(b"\x00")
            name = raw_name.decode("latin-1", "replace")
            ch = int(getattr(s, "Characteristics", 0))
            ent = -1.0
            try:
                ent = float(s.get_entropy())
            except Exception:
                ent = -1.0
            res.sections.append({
                "name": name or "(none)",
                "virtual_address": int(getattr(s, "VirtualAddress", 0)),
                "virtual_size": int(getattr(s, "Misc_VirtualSize", 0)),
                "raw_size": int(getattr(s, "SizeOfRawData", 0)),
                "pointer_to_raw": int(getattr(s, "PointerToRawData", 0)),
                "entropy": round(ent, 3) if ent >= 0 else None,
                "characteristics": hex(ch),
                "executable": bool(ch & 0x20000000),
                "writable": bool(ch & 0x80000000),
            })

        # ---- imports / exports ------------------------------------------------
        for entry in (getattr(pe, "DIRECTORY_ENTRY_IMPORT", None) or []):
            dll = (entry.dll or b"?").decode("latin-1", "replace")
            funcs = [
                imp.name.decode("latin-1", "replace")
                for imp in (getattr(entry, "imports", None) or [])
                if imp is not None and imp.name
            ]
            res.imports.append({"dll": dll, "functions": funcs})

        exp_dir = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
        for sym in (getattr(exp_dir, "symbols", None) or []):
            if getattr(sym, "name", None):
                res.exports.append(sym.name.decode("latin-1", "replace"))

        # ---- resources ---------------------------------------------------------
        res.resources = _extract_resources(pe)

        # ---- rich header -------------------------------------------------------
        res.rich = _parse_rich(pe)

        # ---- overlay -----------------------------------------------------------
        off = pe.get_overlay_data_start_offset()
        if off is not None:
            res.overlay_size = max(0, int(file_size) - int(off))

        res.fingerprint = _compute_fingerprint(res)

        # ---- heuristic anomalies ------------------------------------------------
        res.anomalies = _detect_anomalies(res)

        res.cross_check = _lief_cross_check(path, res, file_size)
        return res
    except Exception as exc:  # structured, isolated failure
        res.status = "error"
        res.error = f"{type(exc).__name__}: {exc}"[:300]
        return res
    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception:
                pass
        try:
            mm.close()
        except Exception:
            pass
        try:
            fh.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
def _pe_machine_name(machine: int) -> str:
    mapping = {
        0x014C: "I386", 0x8664: "AMD64", 0x01C0: "ARM", 0xAA64: "ARM64",
        0x01F0: "POWERPC", 0x0200: "IA64", 0x0102: "RISCV",
    }
    return mapping.get(machine, f"unknown({hex(machine)})")


def _extract_resources(pe) -> dict:
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is None:
        return {}
    counts: dict[str, int] = {}
    type_names = {
        1: "icon", 2: "cursor", 3: "bitmap", 4: "menu", 5: "dialog",
        6: "string", 7: "fontdir", 8: "font", 9: "accelerator", 10: "rcdata",
        11: "messagetable", 12: "group_cursor", 14: "group_icon",
        16: "version", 24: "manifest",
    }
    directory = getattr(root, "directory", None)
    for entry in (getattr(directory, "entries", None) or []):
        ident = getattr(entry, "id", None)
        label = type_names.get(ident, str(ident) if ident is not None else "?")
        counts[label] = counts.get(label, 0) + 1
    strings_present = 0
    try:
        strings_present = len(pe.get_resources_strings())
    except Exception:
        strings_present = 0
    return {"type_counts": counts, "resource_strings": strings_present}


def _parse_rich(pe) -> dict | None:
    try:
        rh = pe.parse_rich_header()
        if rh is None:
            return None
        compids = []
        for v in (getattr(rh, "values", None) or []):
            if isinstance(v, (tuple, list)) and len(v) >= 1:
                compids.append(str(v[0]))
            elif isinstance(v, dict):
                compids.append(str(v.get("comp_id", v)))
        return {"comp_ids": compids[:50], "checksum": getattr(rh, "checksum", None)}
    except Exception:
        return None


def _compute_fingerprint(res: PeResult) -> str:
    core = canonical_json({
        "machine": res.machine_id,
        "magic": res.bitness,
        "image_base": res.image_base,
        "subsystem": res.subsystem,
        "sections": [s["name"] for s in res.sections],
        "imports": [i["dll"] for i in res.imports],
    })
    return sha256_text(core)[:16]


def _detect_anomalies(res: PeResult) -> list[str]:
    anomalies: list[str] = []

    high_ent = [s["name"] for s in res.sections
                if s["entropy"] is not None and s["entropy"] > 7.2 and s["raw_size"] > 0]
    if high_ent:
        anomalies.append(
            f"high-entropy sections (possible packed/encrypted): {high_ent}")

    hollow = [s["name"] for s in res.sections
              if s["raw_size"] == 0 and s["virtual_size"] > 0]
    if hollow:
        anomalies.append(
            f"metadata-only sections (raw==0, virtual>0): {hollow}")

    ep = res.entry_point
    ep_section = None
    if ep:
        for s in res.sections:
            span = max(s["virtual_size"], s["raw_size"])
            if s["virtual_address"] <= ep < s["virtual_address"] + span:
                ep_section = s
                break
        if ep_section is None:
            anomalies.append(f"entry point 0x{ep:x} is outside every section")
        elif ep_section["writable"] and not ep_section["executable"]:
            anomalies.append(
                f"entry point lives in a writable, non-executable section "
                f"({ep_section['name']})")

    names_set = {f.lower() for i in res.imports for f in i["functions"]}
    triad = {"virtualallocex", "writeprocessmemory", "createremotethread"}
    present = triad & names_set
    if len(present) >= 2:
        anomalies.append(
            f"suspicious memory-injection import triad: {sorted(present)}")

    if res.timestamp is not None and not _plausible_year(res.timestamp):
        anomalies.append(
            f"implausible build timestamp {res.timestamp} (possible timestamp spoofing)")

    if res.overlay_size > 0:
        anomalies.append(
            f"trailing overlay of {res.overlay_size} bytes (possible packed payload)")

    if not res.checksum_ok and res.timestamp:
        anomalies.append("checksum mismatch (unsigned/distributed build)")

    return anomalies


def _lief_cross_check(path: str | Path, res: PeResult, file_size: int | None) -> dict:
    """Dual-backend cross-validation vs lief (A.8.28). Size-bounded (memory.md)."""
    if not _HAVE_LIEF:
        return {"lief_available": False}
    if file_size is not None and file_size > LIEF_CROSSCHECK_MAX_BYTES:
        return {"lief_available": True, "skipped": f"size > {LIEF_CROSSCHECK_MAX_BYTES}"}
    try:
        binary = lief.PE.parse(str(path))
        if binary is None:
            return {"lief_available": True, "error": "lief parse returned None"}
        lsec = len(binary.sections)
        psec = len(res.sections)
        limports = sorted({i.name.upper() for i in binary.imports if i.name})
        pimports = sorted({i["dll"].upper() for i in res.imports})
        ok_sections = lsec == psec
        ok_imports = limports == pimports
        if not ok_sections or not ok_imports:
            res.anomalies.append(
                "lief/pefile cross-check mismatch "
                f"(sections_match={ok_sections}, imports_match={ok_imports})")
        return {"lief_available": True, "sections_match": ok_sections,
                "imports_match": ok_imports, "lief_sections": lsec}
    except Exception as exc:
        return {"lief_available": True, "error": str(exc)[:200]}