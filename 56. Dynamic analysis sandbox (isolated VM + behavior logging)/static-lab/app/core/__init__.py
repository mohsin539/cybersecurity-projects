"""Core analysis modules: model, hashing, entropy, PE parsing, strings, lookups, audit, pipeline."""

from .model import (
    AnalysisResult,
    HashBundle,
    PEInfo,
    PESectionInfo,
    StringHit,
    ThreatReport,
    VERDICT_LEVELS,
    verdict_from_score,
)

__all__ = [
    "AnalysisResult",
    "HashBundle",
    "PEInfo",
    "PESectionInfo",
    "StringHit",
    "ThreatReport",
    "VERDICT_LEVELS",
    "verdict_from_score",
]