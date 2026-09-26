"""Capstone disassembler (ARCHITECTURE.md §3.3, M2).

Pure function of (data, options) — no I/O, no execution. The GUI renders the
returned rows; the sandbox child computes them so hostile bytes never parse in
the GUI process (§2 layer rule).

Two modes:
  linear    — flat sweep of the code section (fast, always terminates)
  recursive — CFG-following with a visited set + instruction budget (bounded)
"""
from __future__ import annotations

import struct

try:
    import capstone as _cs
    _HAS_CAPSTONE = True
except ImportError:  # pragma: no cover - guarded at call sites
    _HAS_CAPSTONE = False

MAX_INSTRUCTIONS = 20_000      # per-mode budget (A04: bounded work)
MAX_ROWS_GUI = 2_000           # render cap; full list stays available to jobs

_ARCH_MAP = {
    ("i386", 32): ("CS_ARCH_X86", "CS_MODE_32"),
    ("x86-64", 64): ("CS_ARCH_X86", "CS_MODE_64"),
    ("ARM", 32): ("CS_ARCH_ARM", "CS_MODE_ARM"),
    ("AArch64", 64): ("CS_ARCH_ARM64", "CS_MODE_LITTLE_ENDIAN"),
}


def _make_engine(arch: str, bits: int):
    if not _HAS_CAPSTONE:
        return None
    pair = _ARCH_MAP.get((arch, bits))
    if pair is None:
        return None
    arch_c, mode_c = pair
    md = _cs.Cs(getattr(_cs, arch_c), getattr(_cs, mode_c))
    md.detail = False
    return md


def _code_region(data: bytes) -> tuple[int, bytes]:
    """Best code region: first executable PE section, else ELF .text-ish, else head."""
    from rekt.core.analyzer import parse_elf, parse_pe

    if data[:2] == b"MZ":
        pe = parse_pe(data)
        if pe:
            for s in pe["sections"]:
                if s["vsize"] and "CODE" in (s["chars"] or []) or s["name"] == ".text":
                    blob = data[s["rawptr"]:s["rawptr"] + min(s["rawsize"], 4 * 1024 * 1024)]
                    if blob:
                        return s["vaddr"], blob
            s0 = pe["sections"][0] if pe["sections"] else None
            if s0 and s0["rawsize"]:
                return s0["vaddr"], data[s0["rawptr"]:s0["rawptr"] + min(s0["rawsize"], 4 * 1024 * 1024)]
        return 0x401000, data[0x400:0x400 + 64 * 1024]  # heuristic fallback
    if data[:4] == b"\x7fELF":
        elf = parse_elf(data)
        if elf:
            return 0x400000, data[0x1000:0x1000 + 2 * 1024 * 1024]
    # raw blob: disassemble from the top
    return 0, data[:64 * 1024]


def _fmt(md, insn) -> dict:
    return {
        "addr": insn.address,
        "size": insn.size,
        "bytes": insn.bytes.hex(),
        "mnemonic": insn.mnemonic,
        "op_str": insn.op_str,
        "text": f"{insn.mnemonic} {insn.op_str}",
    }


def linear_disasm(data: bytes, arch: str, bits: int) -> list[dict]:
    md = _make_engine(arch, bits)
    if md is None:
        return []
    base, region = _code_region(data)
    rows: list[dict] = []
    for insn in md.disasm(region, base):
        rows.append(_fmt(md, insn))
        if len(rows) >= MAX_INSTRUCTIONS:
            break
    return rows


def recursive_disasm(data: bytes, arch: str, bits: int) -> list[dict]:
    """Recursive-descent from entry + call/jmp targets, bounded."""
    md = _make_engine(arch, bits)
    if md is None:
        return []
    base, region = _code_region(data)
    visited: set[int] = set()
    pending: list[int] = [base]
    rows_by_addr: dict[int, dict] = {}

    while pending and len(rows_by_addr) < MAX_INSTRUCTIONS:
        start = pending.pop()
        if start in visited:
            continue
        visited.add(start)
        off = start - base
        if off < 0 or off >= len(region):
            continue
        count = 0
        for insn in md.disasm(region[off:], start):
            if len(rows_by_addr) >= MAX_INSTRUCTIONS or count >= 4096:
                break
            if insn.address in rows_by_addr:
                break  # merged with an earlier sweep
            row = _fmt(md, insn)
            rows_by_addr[insn.address] = row
            count += 1
            m = insn.mnemonic
            if m.startswith("ret") or m.startswith(("hlt", "ud2")):
                break
            if m.startswith("call") or m.startswith("jmp"):
                target = insn.op_str.strip()
                if target.startswith("0x"):
                    try:
                        pending.append(int(target, 16))
                    except ValueError:
                        pass
                if m.startswith("jmp"):
                    break
            if m.startswith("j"):  # conditional branch: fallthrough continues
                target = insn.op_str.strip()
                if target.startswith("0x"):
                    try:
                        pending.append(int(target, 16))
                    except ValueError:
                        pass

    return [rows_by_addr[a] for a in sorted(rows_by_addr)]


def entry_disasm(data: bytes, arch: str, bits: int, mode: str = "recursive") -> list[dict]:
    """API used by the child task: mode picks the traversal strategy."""
    if mode == "linear":
        return linear_disasm(data, arch, bits)
    return recursive_disasm(data, arch, bits)


def pe_entry_rva(data: bytes) -> int | None:
    """Entry point RVA from a PE32/PE32+ header (for 'start here' navigation)."""
    if data[:2] != b"MZ" or len(data) < 0x40:
        return None
    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return None
        opt_off = e_lfanew + 4 + 20
        magic = struct.unpack_from("<H", data, opt_off)[0]
        entry_off = opt_off + (16 if magic == 0x20B else 16)
        return struct.unpack_from("<I", data, entry_off)[0]
    except (struct.error, IndexError):
        return None
