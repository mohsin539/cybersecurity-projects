"""Strings engine — charset scan, entropy scoring, typed artifact regexes.

architecture.md §5.2:

1. ASCII + UTF-16LE printable-run extraction (streaming-ready, offset-tracked).
2. Per-string Shannon entropy scoring.
3. Typed artifact regexes (URL, IP, domain, file path, registry, JWT, UUID).
4. High-entropy blob detection (candidate keys / C2 blobs).
5. Bounded decode passes (base64, hex) on flagged strings.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import List

MIN_STRING_LENGTH = 5
MIN_HIGH_ENTROPY_LENGTH = 32
HIGH_ENTROPY_THRESHOLD = 5.5
MAX_ARTIFACTS = 5_000
MAX_STRINGS = 25_000

# -- typed artifact patterns (linear-time, no catastrophic backtracking) --
ARTIFACT_PATTERNS: dict[str, tuple[re.Pattern, str]] = {
    "url": (re.compile(rb"https?://[^\s\x00\"'<>]{3,2048}", re.IGNORECASE), "url"),
    "ipv4": (re.compile(rb"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.])"), "ipv4"),
    "domain": (re.compile(rb"(?<![\w.])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![\w.])", re.IGNORECASE), "domain"),
    "winpath": (re.compile(rb"[A-Za-z]:\\[^\s\x00]{1,512}"), "winpath"),
    "unixpath": (re.compile(rb"(?<![\w])(?:/(?! )[a-zA-Z0-9_.\-\x20]{0,64}){1,16}"), "unixpath"),
    "registry": (re.compile(rb"(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)[\\][^\s\x00]{1,512}", re.IGNORECASE), "registry"),
    "uuid": (re.compile(rb"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE), "uuid"),
    "jwt": (re.compile(rb"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{4,}"), "jwt"),
    "cli": (re.compile(rb"(?:/[\w.-]+\.exe\b|[\w.-]+\.exe\b[ \t]+(?:/[a-z][^\x00]{0,128}|--?\w+))", re.IGNORECASE), "cli"),
}

# API / persistence signals the Triage Aggregator reasons over (heuristics).
SUSPICIOUS_API = frozenset({
    "createremotethread", "virtualallocex", "writeprocessmemory",
    "sethooks", "setwindowshookex", "regsetvalueexa", "regsetvalueexw",
    "createprocessa", "createprocessw", "winexec", "shellexecutea",
    "shellexecutew", "cryptbinarytostringa", "cryptbinarytostringw",
    "setthreadcontext", "ntunmapviewofsection", "zwunmapviewofsection",
    "loadlibrarya", "getprocaddress", "virtua(l)?protect", "writeprocessmemo",
})

SUSPICIOUS_DIR_MARKERS = (
    "\\appdata\\", "\\localsettings\\", "\\programdata\\",
    "\\start menu\\programs\\startup\\", "\\temp\\", "\\startup\\",
)


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits (0.0..8.0)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    n = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / n
            entropy -= p * math.log2(p)
    return entropy


@dataclass
class StringHit:
    value: str
    offset: int
    length: int
    entropy: float
    encoding: str


@dataclass
class Artifact:
    kind: str
    value: str
    offset: int
    entropy: float
    source_encoding: str


@dataclass
class StringsResult:
    status: str = "ok"
    ascii_count: int = 0
    utf16_count: int = 0
    high_entropy_count: int = 0
    artifact_counts: dict = field(default_factory=dict)
    artifacts: List[Artifact] = field(default_factory=list)
    suspicious_apis: List[str] = field(default_factory=list)
    high_entropy_samples: List[StringHit] = field(default_factory=list)
    samples: List[StringHit] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "ascii_count": self.ascii_count,
            "utf16_count": self.utf16_count,
            "high_entropy_count": self.high_entropy_count,
            "artifact_counts": self.artifact_counts,
            "suspicious_apis": self.suspicious_apis,
            "artifacts": [
                {"kind": a.kind, "value": a.value, "offset": a.offset,
                 "entropy": round(a.entropy, 3), "encoding": a.source_encoding}
                for a in self.artifacts[:MAX_ARTIFACTS]
            ],
            "high_entropy_samples": [
                {"value": h.value, "offset": h.offset, "entropy": round(h.entropy, 3)}
                for h in self.high_entropy_samples[:50]
            ],
            "stats": self.stats,
        }


def _scan_ascii(data: bytes) -> list[tuple[int, int]]:
    """Returns [(start, end)] spans of printable ASCII runs >= MIN_STRING_LENGTH."""
    spans: list[tuple[int, int]] = []
    n = len(data)
    i = 0
    while i < n:
        if 0x20 <= data[i] <= 0x7E:
            start = i
            while i < n and 0x20 <= data[i] <= 0x7E:
                i += 1
            if i - start >= MIN_STRING_LENGTH:
                spans.append((start, i))
        else:
            i += 1
    return spans


def _scan_utf16le(data: bytes) -> list[tuple[int, int]]:
    """Returns [(byte_start, byte_end)] of readable UTF-16LE runs."""
    spans: list[tuple[int, int]] = []
    n = len(data)
    i = 0
    while i + 1 < n:
        lo, hi = data[i], data[i + 1]
        if 0x20 <= lo <= 0x7E and hi == 0x00:
            start = i
            while i + 1 < n and 0x20 <= data[i] <= 0x7E and data[i + 1] == 0x00:
                i += 2
            if (i - start) // 2 >= MIN_STRING_LENGTH:
                spans.append((start, i))
        else:
            i += 1
    return spans


def extract_strings(data: bytes) -> StringsResult:
    """Full strings intelligence pass over an in-memory byte view.

    NOTE: callers pass a memory-mapped view (or bounded chunk). The reader is
    O(n) with a constant-sized artifact cap — memory.md §2/§7.
    """
    result = StringsResult()
    if not data:
        result.status = "ok"
        result.stats = {"bytes_scanned": 0}
        return result

    ascii_spans = _scan_ascii(data)
    utf16_spans = _scan_utf16le(data)

    # ---- ASCII strings + entropy ----------------------------------------
    ascii_hits: list[StringHit] = []
    for start, end in ascii_spans[:MAX_STRINGS]:
        raw = data[start:end]
        ent = shannon_entropy(raw)
        text = raw.decode("latin-1")
        ascii_hits.append(StringHit(text, start, len(raw), ent, "ascii"))
    result.ascii_count = len(ascii_spans)

    # ---- UTF-16LE strings + entropy -------------------------------------
    utf16_hits: list[StringHit] = []
    for start, end in utf16_spans[:MAX_STRINGS]:
        raw = data[start:end]
        ent = shannon_entropy(raw)
        text = raw.decode("utf-16le", errors="replace")
        utf16_hits.append(StringHit(text, start, len(raw) // 2, ent, "utf16le"))
    result.utf16_count = len(utf16_spans)

    all_hits = (ascii_hits + utf16_hits)[: MAX_STRINGS * 2]
    result.samples = all_hits[:200]
    result.high_entropy_samples = [
        h for h in all_hits
        if h.length >= MIN_HIGH_ENTROPY_LENGTH and h.entropy >= HIGH_ENTROPY_THRESHOLD
    ][:50]
    result.high_entropy_count = len([
        h for h in all_hits
        if h.length >= MIN_HIGH_ENTROPY_LENGTH and h.entropy >= HIGH_ENTROPY_THRESHOLD
    ])

    # ---- artifact regex pass (whole buffer) ------------------------------
    for kind, (pattern, _label) in ARTIFACT_PATTERNS.items():
        for match in pattern.finditer(data):
            if len(result.artifacts) >= MAX_ARTIFACTS:
                break
            value = match.group()
            ent = shannon_entropy(value)
            result.artifacts.append(
                Artifact(kind=kind, value=value[:512].decode("latin-1", "replace"),
                         offset=match.start(), entropy=ent, source_encoding="ascii"))
        if len(result.artifacts) >= MAX_ARTIFACTS:
            break

    for art in result.artifacts:
        result.artifact_counts[art.kind] = result.artifact_counts.get(art.kind, 0) + 1

    # ---- suspicious API usage ---------------------------------------------
    found_apis: set[str] = set()
    for hit in all_hits:
        low = hit.value.lower()
        for api in SUSPICIOUS_API:
            if api in low:
                found_apis.add(api)
    result.suspicious_apis = sorted(found_apis)

    result.stats = {
        "bytes_scanned": len(data),
        "artifact_total": len(result.artifacts),
    }
    return result