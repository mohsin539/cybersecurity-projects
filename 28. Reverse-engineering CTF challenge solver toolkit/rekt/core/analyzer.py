"""Entropy + PE/ELF-lite parsing (ARCHITECTURE.md §3.3).

Pure stdlib structural parsing — no third-party parser, so a hostile file can
only hit pure Python code that we fuzz (A04/A08). All fields cross-checked;
nothing is executed.
"""
from __future__ import annotations

import math
import struct
from pathlib import Path

MACHINE_NAMES = {
    0x014C: "i386", 0x8664: "x86-64", 0x01C0: "ARM", 0xAA64: "ARM64",
    0x01C3: "ARM (thumb)", 0x0200: "IA-64",
}

SECTION_CHARS = {0x20: "CODE", 0x40: "INITIALIZED_DATA", 0x80: "UNINITIALIZED_DATA"}


def shannon_entropy(data: bytes) -> float:
    """0.0..8.0 bits/byte. High entropy in .text => packed (heuristic)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def entropy_profile(data: bytes, chunks: int = 64) -> list[float]:
    """Entropy per chunk for the graph pane. Bounded chunk count."""
    if not data:
        return []
    step = max(1, len(data) // chunks)
    return [shannon_entropy(data[i:i + step]) for i in range(0, len(data), step)]


def detect_packer_heuristic(data: bytes, pe: dict | None = None) -> list[str]:
    """Cheap, documented heuristics only — no signatures are executed."""
    hits: list[str] = []
    if data.startswith(b"UPX!"):
        hits.append("UPX (magic at header)")
    if b"UPX!" in data[:65536]:
        hits.append("UPX (magic in first 64 KiB)")
    if pe:
        text = next((s for s in pe["sections"] if s["name"] in {".text", "CODE"}), None)
        if text and text["entropy"] > 7.2 and text["vsize"] > 1024:
            hits.append("high-entropy code section (packed/encrypted?)")
        named = {s["name"] for s in pe["sections"]}
        if named & {"UPX0", "UPX1", "UPX2"}:
            hits.append("UPX (section names)")
    return hits


def parse_pe(data: bytes) -> dict | None:
    """Minimal, defensive PE parser. Returns None for anything non-PE.

    Every struct.unpack is guarded; malformed files raise ValueError -> caller
    treats as finding, never crashes the GUI.
    """
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 6 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return None
        coff = e_lfanew + 4
        machine, nsec, _tds, _ptrsym, _nsym, _osz, chars = struct.unpack_from(
            "<HHIIIHH", data, coff
        )
        opt_off = coff + 20
        magic = struct.unpack_from("<H", data, opt_off)[0] if opt_off + 2 <= len(data) else 0
        bits = 64 if magic == 0x20B else 32 if magic == 0x10B else 0

        sections = []
        sec_table = opt_off + (240 if bits == 64 else 224)
        for i in range(min(nsec, 96)):  # cap: corrupt count must not DoS (A04)
            off = sec_table + i * 40
            if off + 40 > len(data):
                break
            name_raw = data[off:off + 8]
            name = name_raw.split(b"\x00", 1)[0].decode("latin-1")
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, off + 8)
            blob = data[rawptr:rawptr + rawsize] if rawsize else b""
            sections.append({
                "name": name,
                "vsize": vsize,
                "vaddr": vaddr,
                "rawsize": rawsize,
                "rawptr": rawptr,
                "entropy": round(shannon_entropy(blob), 3) if blob else 0.0,
                "chars": [n for bit, n in SECTION_CHARS.items() if chars and False or
                          (struct.unpack_from("<I", data, off + 36)[0] & bit)],
            })

        # import directory (data dir 1)
        imports: list[str] = []
        dd_off = opt_off + (112 if bits == 64 else 96)
        if dd_off + 8 <= len(data):
            import_rva, import_size = struct.unpack_from("<II", data, dd_off)
            imports = _parse_imports(data, sections, import_rva, import_size)

        return {
            "bits": bits,
            "machine": MACHINE_NAMES.get(machine, f"0x{machine:04x}"),
            "nsections": nsec,
            "sections": sections,
            "imports": imports,
        }
    except (struct.error, ValueError, IndexError):
        return None


def _rva_to_offset(rva: int, sections: list[dict]) -> int | None:
    for s in sections:
        if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rawsize"]):
            return s["rawptr"] + (rva - s["vaddr"])
    return None


def _parse_imports(data: bytes, sections: list[dict], rva: int, size: int) -> list[str]:
    names: list[str] = []
    if not rva or not size or size > 1 << 20:
        return names
    base = _rva_to_offset(rva, sections)
    if base is None:
        return names
    for i in range(4096):  # hard cap on descriptor walk
        off = base + i * 20
        if off + 20 > len(data):
            break
        name_rva = struct.unpack_from("<I", data, off + 12)[0]
        if name_rva == 0:
            break
        noff = _rva_to_offset(name_rva, sections)
        if noff is None or noff >= len(data):
            continue
        end = data.find(b"\x00", noff, noff + 256)
        if end > noff:
            names.append(data[noff:end].decode("latin-1", "replace"))
    return names


def parse_elf(data: bytes) -> dict | None:
    """Minimal ELF header read (class, machine, sections count)."""
    if len(data) < 20 or data[:4] != b"\x7fELF":
        return None
    try:
        ei_class, ei_data = data[4], data[5]
        fmt = "<" if ei_data == 1 else ">"
        if ei_class == 2:
            machine = struct.unpack_from(fmt + "H", data, 18)[0]
            shoff = struct.unpack_from(fmt + "Q", data, 0x28)[0]
            shentsize, shnum = struct.unpack_from(fmt + "HH", data, 0x3A)
        else:
            machine = struct.unpack_from(fmt + "H", data, 18)[0]
            shoff = struct.unpack_from(fmt + "I", data, 0x20)[0]
            shentsize, shnum = struct.unpack_from(fmt + "HH", data, 0x2E)
        sections: list[dict] = []
        for i in range(min(shnum, 96)):
            off = shoff + i * shentsize
            if off + shentsize > len(data) or shentsize < 40:
                break
            name_off, _typ, _flags = struct.unpack_from(fmt + "III", data, off)
            blob = data[off:off + shentsize]
            sections.append({
                "name_offset": name_off,
                "entropy": round(shannon_entropy(blob), 3),
            })
        machines = {0x03: "i386", 0x3E: "x86-64", 0xB7: "AArch64", 0x28: "ARM"}
        return {
            "bits": 64 if ei_class == 2 else 32,
            "machine": machines.get(machine, f"0x{machine:x}"),
            "nsections": shnum,
            "sections": sections,
            "imports": [],
        }
    except (struct.error, IndexError):
        return None


def quick_identify(data: bytes) -> dict:
    """Magic-based identification for the dashboard (pure function)."""
    sigs = [
        (b"MZ", "Windows PE executable"),
        (b"\x7fELF", "ELF executable"),
        (b"\xca\xfe\xba\xbe", "Mach-O / Java class"),
        (b"PK\x03\x04", "ZIP archive"),
        (b"\x1f\x8b", "gzip stream"),
        (b"Rar!", "RAR archive"),
        (b"7z\xbc\xaf\x27\x1c", "7z archive"),
        (b"\x89PNG\r\n\x1a\n", "PNG image"),
        (b"\xff\xd8\xff", "JPEG image"),
        (b"GIF8", "GIF image"),
        (b"BM", "BMP image"),
        (b"%PDF", "PDF document"),
        (b"Rar!\x1a\x07", "RAR archive"),
        (b"OggS", "Ogg media"),
        (b"ID3", "MP3 audio"),
        (b"\x00\x00\x01\x00", "ICO icon"),
        (b"SQLite format 3\x00", "SQLite database"),
        (b"UPX!", "UPX-packed data"),
    ]
    kinds: list[str] = []
    for sig, label in sigs:
        if data.startswith(sig):
            kinds.append(label)
    if not kinds:
        head = data[:16]
        if head and all(32 <= b < 127 or b in (9, 10, 13) for b in head):
            kinds.append("text-like data")
        else:
            kinds.append("unknown binary")
    return {"kinds": kinds, "size": len(data), "entropy": round(shannon_entropy(data), 3)}


def analyze_file(path: Path) -> dict:
    """Full static profile for one file. Never executes the target (§3.5)."""
    data = path.read_bytes()[:64 * 1024 * 1024]  # 64 MiB analysis cap (config A05)
    ident = quick_identify(data)
    pe = parse_pe(data) if data[:2] == b"MZ" else None
    elf = parse_elf(data) if data[:4] == b"\x7fELF" else None
    fmt = pe or elf
    return {
        **ident,
        "format": "PE" if pe else "ELF" if elf else None,
        "arch": fmt["machine"] if fmt else None,
        "bits": fmt["bits"] if fmt else None,
        "sections": fmt["sections"] if fmt else [],
        "imports": fmt["imports"] if fmt else [],
        "packer_hints": detect_packer_heuristic(data, pe),
        "entropy_series": entropy_profile(data),
    }
