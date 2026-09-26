"""PE header parsing built on pefile, plus a lightweight Rich header decoder."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Optional

import pefile

from .entropy import classify_entropy, shannon_entropy
from .model import PEInfo, PESectionInfo

pefile.DIRECTORY_ENTRY  # ensure pefile datadirs are still imported

_MACHINE = "UNKNOWN"
_SUBSYSTEM = "UNKNOWN"
_DLL_CHARS = "UNKNOWN"


def _fmt_ts(unix: int) -> str:
    return (
        datetime.fromtimestamp(unix, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        if unix
        else "0 (not set)"
    )


def _human_dll_chars(value: int) -> str:
    bits: list[str] = []
    named = {
        0x0020: "High Entropy VA",
        0x0040: "Dynamic Base (ASLR)",
        0x0080: "Force Integrity",
        0x0100: "NX Compat (DEP)",
        0x0200: "No Isolation",
        0x0400: "No SEH",
        0x0800: "No Bind",
        0x1000: "AppContainer",
        0x2000: "WDM Driver",
        0x4000: "Guard CF",
        0x8000: "Terminal Server Aware",
    }
    for bit, label in named.items():
        if value & bit:
            bits.append(label)
    if not bits:
        bits.append("none")
    return ", ".join(bits)


def parse_rich_header(data: bytes, pe_offset: int) -> Optional[str]:
    """Best-effort Rich header decode -> 'key=0x…, prod:build(count), …'."""
    try:
        marker = data.rfind(b"Rich", 0x40, pe_offset)
        if marker < 0:
            return None
        key = int.from_bytes(data[marker - 4 : marker], "little")
        if key == 0:
            return None
        start = 0x40
        comps: list[str] = []
        i = start
        while i < marker - 4:
            raw_v = int.from_bytes(data[i : i + 4], "little") ^ key
            raw_n = int.from_bytes(data[i + 4 : i + 8], "little") ^ key
            prod_id = raw_v >> 16
            build_id = raw_v & 0xFFFF
            if prod_id or build_id or raw_n:
                comps.append(f"{prod_id}.{build_id} x{raw_n}")
            i += 8
        return f"key=0x{key:08x} | " + ", ".join(comps[:40]) if comps else None
    except Exception:
        return None


def parse_pe(path: str) -> PEInfo:
    """Parse a file as PE. Never raises for malformed files; returns PEInfo()."""
    info = PEInfo(valid=False)
    try:
        with open(path, "rb") as f:
            head = f.read(4096)
            f.seek(0, 2)
            total = f.tell()
    except OSError:
        info.warnings.append("unreadable file")
        return info

    if total < 0x40 or head[:2] != b"MZ":
        info.warnings.append("no MZ signature - not a PE file")
        return info

    pe_offset = int.from_bytes(head[0x3C:0x40], "little")
    if pe_offset <= 0 or pe_offset + 6 > total:
        info.warnings.append("corrupt PE offset (e_lfanew)")
        return info

    try:
        pe = pefile.PE(path, fast_load=False)
    except pefile.PEFormatError as e:
        info.warnings.append(f"PEFormatError: {e}")
        return info
    except Exception as e:  # noqa: BLE001
        info.warnings.append(f"parse error: {e}")
        return info

    try:
        _fill(pe, path, info, total)
        info.valid = True
        info.is_pe = True
    except Exception as e:  # noqa: BLE001
        info.warnings.append(f"post-parse error: {e}")
        info.valid = True
        info.is_pe = True
    finally:
        try:
            pe.close()
        except Exception:
            pass
    return info


def _fill(pe: pefile.PE, path: str, info: PEInfo, total: int) -> None:
    fh = pe.FILE_HEADER
    oh = pe.OPTIONAL_HEADER

    info.machine = hex(fh.Machine)
    info.magic = "PE64+" if oh.Magic == 0x20B else "PE32" if oh.Magic == 0x10B else f"0x{oh.Magic:X}"
    info.number_of_sections = fh.NumberOfSections
    info.timestamp = _fmt_ts(fh.TimeDateStamp)
    info.characteristics = f"0x{fh.Characteristics:04X}"
    info.linker_version = f"{oh.MajorLinkerVersion}.{oh.MinorLinkerVersion}"
    info.image_base = oh.ImageBase
    info.entry_point = oh.AddressOfEntryPoint
    info.is_dll = bool(fh.Characteristics & 0x2000)
    info.is_driver = bool(fh.Characteristics & 0x1000)

    try:
        info.subsystem = pefile.SUBSYSTEM_TYPE.get(oh.Subsystem, f"0x{oh.Subsystem:X}")
    except Exception:
        info.subsystem = f"0x{oh.Subsystem:X}"
    try:
        info.dll_characteristics = _human_dll_chars(oh.DllCharacteristics)
    except Exception:
        info.dll_characteristics = "n/a"
    try:
        info.debug_type = str(pe.DIRECTORY_ENTRY_DEBUG[0].entry.Type) if hasattr(pe, "DIRECTORY_ENTRY_DEBUG") else None
    except Exception:
        info.debug_type = None
    try:
        info.tls_callbacks = len(pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks) if hasattr(pe, "DIRECTORY_ENTRY_TLS") else 0
    except Exception:
        info.tls_callbacks = 0

    # sections -----------------------------------------------------------------
    with open(path, "rb") as f:
        fastest = pe.__data__ if hasattr(pe, "__data__") else None
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin-1", "replace")
        raw = s.get_data()
        ent = shannon_entropy(raw)
        info.sections.append(
            PESectionInfo(
                name=name,
                virtual_address=s.VirtualAddress,
                virtual_size=s.Misc_VirtualSize,
                raw_size=s.SizeOfRawData,
                entropy=round(ent, 3),
                flags_hex=hex(s.Characteristics),
                flags_readable=pefile.SECTION_CHARACTERISTICS_NAMES.get(s.Characteristics, ""),
                sha256=hashlib.sha256(raw).hexdigest(),
            )
        )

    # imports / exports / resources -------------------------------------------
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                funcs = [imp.name.decode("latin-1") if imp.name else f"ord-{imp.ordinal}" for imp in entry.imports[:200]]
                info.imports.append((entry.dll.decode("latin-1"), funcs))
    except Exception as e:
        info.warnings.append(f"imports: {e}")

    try:
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                nm = exp.name.decode("latin-1") if exp.name else f"ord-{exp.ordinal}"
                info.exports.append(nm)
    except Exception as e:
        info.warnings.append(f"exports: {e}")

    try:
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            for rtype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                try:
                    info.resources.append(pefile.RESOURCE_TYPE.get(rtype.id, f"type-{rtype.id}"))
                except Exception:
                    info.resources.append("unknown")
    except Exception:
        pass

    # data directories ----------------------------------------------------------
    try:
        for dd in oh.DATA_DIRECTORY:
            name = getattr(dd, "name", "")
            if dd.VirtualAddress or dd.Size:
                info.data_directories.append((name, dd.VirtualAddress))
    except Exception:
        pass

    # signing --------------------------------------------------------------------
    if hasattr(pe, "DIRECTORY_ENTRY_SECURITY"):
        try:
            sec = pe.DIRECTORY_ENTRY_SECURITY
            info.certificate_present = bool(sec.Size > 0)
        except Exception:
            info.certificate_present = False
    try:
        info.is_signed = bool(pe.is_signed())
    except Exception:
        info.is_signed = False
    # surface WinVerifyTrust isn't available cross-platform; use parsed signature dirs
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_SECURITY") and hasattr(pe.DIRECTORY_ENTRY_SECURITY, "content"):
            c = pe.DIRECTORY_ENTRY_SECURITY.content
            if c:
                sigs = pefile.crypto.signature_attr_getabuslist(c) if hasattr(pefile, "crypto") else None
                info.cert_signers = list(sigs) if sigs else []
    except Exception:
        pass

    # overlay --------------------------------------------------------------------
    try:
        ov = pe.get_overlay_data_start_offset()
        info.overlay_offset = ov
        info.overlay_size = max(0, total - ov) if ov and ov < total else 0
        if info.overlay_size > 0 and ov is not None:
            with open(path, "rb") as f:
                f.seek(ov)
                blob = f.read(min(info.overlay_size, 4 * 1024))
            info.overlay_pe_embedded = blob[:2] == b"MZ"
    except Exception:
        info.overlay_size = 0

    # rich header -----------------------------------------------------------------
    try:
        with open(path, "rb") as f:
            data = f.read(min(total, pe_offset + 0x100))
        info.rich_header = parse_rich_header(data, pe_offset)
    except Exception:
        info.rich_header = None

    # convenience: also carry entropy classification for the top section
    for s in info.sections:
        s.flags_readable = s.flags_readable or classify_entropy(s.entropy)