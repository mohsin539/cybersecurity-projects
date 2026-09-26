"""High-performance strings extractor: ASCII + UTF-16LE runs plus interest flags."""

from __future__ import annotations

import re
import struct
from typing import Optional

from .model import StringHit

_PRINTABLE_ASCII = frozenset(
    bytes(range(0x20, 0x7F)) + b"\t\n\r"
)  # printable + common whitespace

# UTF-16LE units (little-endian) that are printable ASCII / whitespace.
_PRINTABLE_16 = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def _ascii_runs(data: bytes, min_len: int) -> list[tuple[int, bytes]]:
    runs: list[tuple[int, bytes]] = []
    start: Optional[int] = None
    for i, b in enumerate(data):
        if b in _PRINTABLE_ASCII:
            if start is None:
                start = i
        elif start is not None:
            if i - start >= min_len:
                runs.append((start, data[start:i]))
            start = None
    if start is not None and len(data) - start >= min_len:
        runs.append((start, data[start:]))
    return runs


def _unicode_runs(data: bytes, min_len: int) -> list[tuple[int, bytes]]:
    """Find UTF-16LE printable runs using little-endian 16-bit units.

    Each unit must be a printable ASCII codepoint (0x20..0x7E) or whitespace,
    so pure-ASCII bytes do not confuse the scan (GNU 'strings -el' semantics).
    """
    runs: list[tuple[int, list[int]]] = []
    for base in (0, 1):  # both byte alignments
        start: Optional[int] = None
        units: list[int] = []
        chunk = data[base:] if base else data
        # pad so iter_unpack covers trailing single byte harmlessly
        chunk += b"\x00" if len(chunk) % 2 else b""
        for idx, (u,) in enumerate(struct.iter_unpack("<H", chunk)):
            if u in _PRINTABLE_16:
                if start is None:
                    start = idx
                units.append(u)
            elif start is not None:
                if len(units) >= min_len:
                    runs.append((base + start * 2, units))
                start = None
                units = []
        if start is not None and len(units) >= min_len:
            runs.append((base + start * 2, units))
    return runs


_RE_URL = re.compile(
    r"(?i)\b(?:https?|ftp)://[^\s\"'<>]{5,}",
)
_RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b")
_RE_GUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_RE_REG = re.compile(
    r"(?i)\b(HKLM|HKCU|HKCR|HKU|Software\\|Microsoft\\Windows\\CurrentVersion\\(Run|RunOnce))\b"
)
_RE_BASE64 = re.compile(r"^[A-Za-z0-9+/]{24,}={0,2}$")

_SUSPICIOUS_TOKENS = (
    "CreateRemoteThread",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "SetWindowsHookEx",
    "GetAsyncKeyState",
    "keylogger",
    "powershell",
    "cmd.exe /c",
    "wscript",
    "cscript",
    "mshta",
    "schtasks",
    "reg add",
    "net user",
    "net localgroup",
    "persistence",
    "mimikatz",
    "seclogon",
    "CurrentVersion\\Run",
    "Winlogon",
    "Rundll32",
    "CertUtil",
    "bitsadmin",
    "curl http",
    "wget http",
    "powershell -enc",
    "IEX(",
    "FromBase64String",
)


def _flag_string(value: str, start: int, end: int) -> list[str]:
    flags: list[str] = []
    h = value
    if _RE_URL.search(h):
        flags.append("url")
    if _RE_IP.search(h):
        flags.append("ip")
    if _RE_EMAIL.search(h):
        flags.append("email")
    if _RE_GUID.search(h):
        flags.append("guid")
    if _RE_REG.search(h):
        flags.append("registry")
    low = h.lower()
    for tok in _SUSPICIOUS_TOKENS:
        if tok.lower() in low:
            flags.append("suspicious")
            break
    if _RE_BASE64.match(h):
        flags.append("base64")
    return flags


def extract_strings(
    data: bytes,
    min_len: int = 4,
    include_unicode: bool = True,
    only_flagged: bool = False,
) -> list[StringHit]:
    """Extract ASCII (and UTF-16LE) printable runs with offsets and interest flags."""
    hits: list[StringHit] = []

    for start, run in _ascii_runs(data, min_len):
        try:
            value = run.decode("ascii", "strict").rstrip()
        except Exception:  # noqa: BLE001
            continue
        if not value:
            continue
        flags = _flag_string(value, start, start + len(run))
        if only_flagged and not flags:
            continue
        hits.append(StringHit(offset=start, encoding="ascii", value=value, flags=flags))

    if include_unicode:
        for abs_offset, units in _unicode_runs(data, min_len):
            try:
                value = "".join(chr(u) for u in units).rstrip()
            except Exception:  # noqa: BLE001
                continue
            if not value:
                continue
            flags = _flag_string(value, abs_offset, abs_offset + len(units) * 2)
            if only_flagged and not flags:
                continue
            hits.append(StringHit(offset=abs_offset, encoding="unicode", value=value, flags=flags))
    hits.sort(key=lambda h: h.offset)
    return hits


def concatenated_offset_strings(hits: list[StringHit], limit: int = 60000) -> bytes:
    """Compacted ordered string blob used for full-dump strings export."""
    return (
        "".join(f"{h.encoding}:{h.offset}: {h.value}\n" for h in hits[:limit])
    ).encode("utf-8", "replace")