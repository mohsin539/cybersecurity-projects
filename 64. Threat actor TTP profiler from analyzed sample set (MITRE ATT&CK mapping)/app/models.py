"""TTPProfiler :: core models (DTOs)"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class EvidenceRecord:
    """A single normalized piece of artifact evidence from one sample."""
    sample_sha256: str
    source: str                      # static / dynamic / network / yara
    kind: str                        # string / registry / filepath / process / c2 / ioctag
    text: str = ""
    tags: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def to_text(self) -> str:
        parts = [self.text]
        parts.extend(self.tags)
        parts.extend(str(v) for v in (self.meta or {}).values() if isinstance(v, str))
        return "\n".join(p for p in parts if p) or ""


@dataclass
class Sample:
    sha256: str
    filename: str
    family: str = ""
    verdict: str = "unknown"         # malicious | suspicious | clean | unknown
    meta: dict[str, Any] = field(default_factory=dict)
    evidence: list[EvidenceRecord] = field(default_factory=list)
    yara_rules: list[str] = field(default_factory=list)
    av_names: list[str] = field(default_factory=list)
    network_domains: list[str] = field(default_factory=list)
    network_ips: list[str] = field(default_factory=list)
    file_paths: list[str] = field(default_factory=list)
    registry_keys: list[str] = field(default_factory=list)
    process_names: list[str] = field(default_factory=list)
    strings: list[str] = field(default_factory=list)

    @property
    def all_text(self) -> str:
        comps = []
        comps.extend(self.yara_rules)
        comps.extend(self.av_names)
        comps.extend(self.network_domains)
        comps.extend(self.network_ips)
        comps.extend(self.file_paths)
        comps.extend(self.registry_keys)
        comps.extend(self.process_names)
        comps.extend(self.strings)
        comps.extend(e.text for e in self.evidence)
        comps.extend(t for e in self.evidence for t in e.tags)
        return "\n".join(c for c in comps if c) or ""


@dataclass
class TechniqueMapping:
    technique_id: str
    evidence_ids: list[str] = field(default_factory=list)
    evidence_strength: float = 0.0
    sample_coverage: float = 0.0
    score: float = 0.0

    def to_dict(self) -> dict:
        return {
            "technique_id": self.technique_id,
            "evidence_ids": self.evidence_ids,
            "evidence_strength": round(self.evidence_strength, 3),
            "sample_coverage": round(self.sample_coverage, 3),
            "score": round(self.score, 3),
        }


@dataclass
class ActorMatch:
    group_id: str
    name: str
    aliases: str
    confidence: float            # 0..100
    matched_techniques: list[str]
    unmatched_group_techniques: list[str]
    software_hits: list[str] = field(default_factory=list)
    similarity: float = 0.0
    evidence_delta: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "group_id": self.group_id,
            "name": self.name,
            "aliases": self.aliases,
            "confidence": round(self.confidence, 1),
            "similarity": round(self.similarity, 3),
            "matched_techniques": self.matched_techniques,
            "unmatched_group_techniques": self.unmatched_group_techniques,
            "software_hits": self.software_hits,
        }


@dataclass
class ActorProfile:
    id: str
    created_at: str = field(default_factory=utcnow)
    sample_set_id: str = ""
    sample_count: int = 0
    tactic_scores: dict[str, float] = field(default_factory=dict)
    techniques: list[TechniqueMapping] = field(default_factory=list)
    actor_ranking: list[ActorMatch] = field(default_factory=list)
    top_actor: ActorMatch | None = None
    intel_grade: str = "D"
    confidence: float = 0.0

    def summary(self) -> dict:
        return {
            "id": self.id,
            "sample_set_id": self.sample_set_id,
            "sample_count": self.sample_count,
            "confidence": round(self.confidence, 1),
            "intel_grade": self.intel_grade,
            "tactic_scores": {k: round(v, 2) for k, v in self.tactic_scores.items()},
            "techniques": [t.to_dict() for t in sorted(self.techniques, key=lambda t: -t.score)],
            "actors": [a.to_dict() for a in self.actor_ranking],
            "top_actor": self.top_actor.to_dict() if self.top_actor else None,
        }


@dataclass
class AuditEntry:
    action: str
    detail: str = ""
    ts: str = field(default_factory=utcnow)
    who: str = "local-user"
    prev_hash: str = ""
    hash: str = ""