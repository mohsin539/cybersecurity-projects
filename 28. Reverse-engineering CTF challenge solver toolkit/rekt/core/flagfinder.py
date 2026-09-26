"""Flag-candidate detection — strings/n-gram heuristics (ARCHITECTURE.md §3.3)."""
from __future__ import annotations

import re

# Common CTF flag formats. Deliberately allow-list style to cut false positives.
DEFAULT_PATTERNS: list[tuple[str, str]] = [
    ("flag{...}", r"(?:flag|FLAG)\{[^}\n]{1,128}\}"),
    ("ctf{...}",  r"(?:ctf|CTF)\{[^}\n]{1,128}\}"),
    ("picoCTF{...}", r"picoCTF\{[^}\n]{1,128}\}"),
    ("HTB{...}",  r"HTB\{[^}\n]{1,128}\}"),
    ("THM{...}",  r"THM\{[^}\n]{1,128}\}"),
]

_BASE64ISH = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEXISH = re.compile(r"\b[0-9a-fA-F]{32,64}\b")


def extract_strings(data: bytes, min_len: int = 4, max_len: int = 4096) -> list[tuple[int, str, str]]:
    """Extract ASCII and UTF-16LE strings. Bounded output (max_len cap per string)."""
    out: list[tuple[int, str, str]] = []
    ascii_re = re.compile(rb"[\x20-\x7e]{%d,%d}" % (min_len, max_len))
    for m in ascii_re.finditer(data):
        out.append((m.start(), "ascii", m.group().decode("ascii")))
    utf16_re = re.compile(rb"(?:[\x20-\x7e]\x00){%d,%d}" % (min_len, max_len))
    for m in utf16_re.finditer(data):
        out.append((m.start(), "utf-16le", m.group().decode("utf-16-le")))
    out.sort(key=lambda t: t[0])
    return out


def find_flags(data: bytes, patterns: list[tuple[str, str]] | None = None) -> list[dict]:
    """Return ordered, deduplicated flag candidates."""
    pats = patterns or DEFAULT_PATTERNS
    hits: list[dict] = []
    seen: set[str] = set()
    for label, pat in pats:
        for m in re.finditer(pat.encode("latin-1"), data):
            s = m.group().decode("latin-1")
            if s not in seen:
                seen.add(s)
                hits.append({"rule": label, "offset": m.start(), "value": s})
    return hits


def find_interesting_strings(data: bytes, limit: int = 200) -> list[dict]:
    """Long base64-ish blobs and hex strings worth a second look."""
    out: list[dict] = []
    for m in _BASE64ISH.finditer(data.decode("latin-1")):
        s = m.group()
        if any(c.isdigit() for c in s) and any(c.isupper() for c in s) \
                and any(c.islower() for c in s):
            out.append({"kind": "base64ish", "offset": m.start(), "value": s[:256]})
    for m in _HEXISH.finditer(data.decode("latin-1")):
        out.append({"kind": "hexblob", "offset": m.start(), "value": m.group()[:256]})
    return out[:limit]
