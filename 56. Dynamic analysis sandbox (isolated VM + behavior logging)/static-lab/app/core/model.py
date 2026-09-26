"""Data model for the static analysis pipeline."""

from __future__ import annotations

import dataclasses
import time
from dataclasses import dataclass, field
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Verdict model
# ---------------------------------------------------------------------------

VERDICT_LEVELS = (
    ("clean", "Clean"),
    ("suspicious", "Suspicious"),
    ("malicious", "Malicious"),
    ("malicious_hc", "Malicious (High Confidence)"),
)


def verdict_from_score(score: int) -> tuple[str, str]:
    """Map a 0..100 score to a (verb_key, label) verdict."""
    if score >= 80:
        return "malicious_hc", "Malicious (High Confidence)"
    if score >= 50:
        return "malicious", "Malicious"
    if score >= 20:
        return "suspicious", "Suspicious"
    return "clean", "Clean"


def _score_color(score: int) -> str:
    if score >= 50:
        return "crimson"
    if score >= 20:
        return "#e08a00"
    return "#2ea043"


# ---------------------------------------------------------------------------
# Hash bundle
# ---------------------------------------------------------------------------


@dataclass
class HashBundle:
    md5: str
    sha1: str
    sha256: str
    sha512: str
    imphash: Optional[str] = None
    authentihash: Optional[str] = None
    entropy: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# PE structures
# ---------------------------------------------------------------------------


@dataclass
class PESectionInfo:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    entropy: float
    flags_hex: str
    flags_readable: str
    sha256: str

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class PEInfo:
    valid: bool
    is_pe: bool = False

    machine: Optional[str] = None
    magic: Optional[str] = None  # PE32 | PE32+
    number_of_sections: int = 0
    timestamp: Optional[str] = None
    characteristics: Optional[str] = None
    linker_version: Optional[str] = None

    image_base: Optional[int] = None
    entry_point: Optional[int] = None
    subsystem: Optional[str] = None
    dll_characteristics: Optional[str] = None
    is_dll: bool = False
    is_driver: bool = False

    sections: list[PESectionInfo] = field(default_factory=list)
    imports: list[tuple[str, list[str]]] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    data_directories: list[tuple[str, int]] = field(default_factory=list)
    rich_header: Optional[str] = None
    certificate_present: bool = False
    is_signed: bool = False
    overlay_offset: Optional[int] = None
    overlay_size: int = 0
    overlay_pe_embedded: bool = False
    warnings: list[str] = field(default_factory=list)

    # optional deep fields
    cert_signers: list[str] = field(default_factory=list)
    tls_callbacks: int = 0
    debug_type: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        d = dataclasses.asdict(self)
        d["imports"] = [{"dll": a, "functions": b} for a, b in self.imports]
        d["sections"] = [s.to_dict() for s in self.sections]
        return d


# ---------------------------------------------------------------------------
# Strings
# ---------------------------------------------------------------------------


@dataclass
class StringHit:
    offset: int
    encoding: str  # "ascii" | "unicode"
    value: str
    flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# Threat lookups
# ---------------------------------------------------------------------------


@dataclass
class ThreatReport:
    provider: str
    status: str  # ok | error | no_key
    sha256: str
    message: str = ""
    score: Optional[int] = None       # 0..100 normalized
    summary: dict[str, Any] = field(default_factory=dict)
    url: Optional[str] = None         # permalink to the provider

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# Final result
# ---------------------------------------------------------------------------


@dataclass
class AnalysisResult:
    analysis_id: str
    file_path: str
    file_name: str
    file_size: int
    magic_hint: Optional[str]
    stat_created: Optional[str] = None
    stat_modified: Optional[str] = None
    tls_url: str = "sha256"

    hashes: Optional[HashBundle] = None
    pe: Optional[PEInfo] = None
    strings: list[StringHit] = field(default_factory=list)
    suspicious_strings: list[StringHit] = field(default_factory=list)
    lookups: list[ThreatReport] = field(default_factory=list)

    score: int = 0
    verdict_key: str = "clean"
    verdict_label: str = "Clean"
    score_color: str = "#2ea043"

    stages: list[tuple[str, float]] = field(default_factory=list)
    audit_chain_hash: Optional[str] = None
    audit_verified: Optional[bool] = None

    # ------------------------------------------------------------------
    def stage(self, name: str) -> "AnalysisResult":
        self.stages.append((name, round(time.time() * 1000, 3)))
        return self

    def finalize(self) -> None:
        self.score = max(0, min(100, self.score))
        self.verdict_key, self.verdict_label = verdict_from_score(self.score)
        self.score_color = _score_color(self.score)

    # ------------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "analysis_id": self.analysis_id,
            "file": {
                "path": self.file_path,
                "name": self.file_name,
                "size": self.file_size,
                "magic_hint": self.magic_hint,
                "created": self.stat_created,
                "modified": self.stat_modified,
            },
            "hashes": self.hashes.to_dict() if self.hashes else None,
            "pe": self.pe.to_dict() if self.pe else None,
            "strings_total": len(self.strings),
            "suspicious_strings": [s.to_dict() for s in self.suspicious_strings[:500]],
            "threat_lookups": [t.to_dict() for t in self.lookups],
            "verdict": {
                "score": self.score,
                "verdict_key": self.verdict_key,
                "verdict_label": self.verdict_label,
                "color": self.score_color,
            },
            "stages_ms": self.stages,
            "audit": {
                "chain_hash": self.audit_chain_hash,
                "verified": self.audit_verified,
            },
        }