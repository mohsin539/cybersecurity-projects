"""Lookup service — ordered, cached, throttled intel resolution.

Pipeline stage order: LocalBloom+facts (always) -> opted-in HTTP sources ->
cached results (Redis/Parquet-like JSON store in the sandbox, TTL'd). All
egress events are recorded to the audit ledger, and the raw sample is never
sent anywhere (hashes only, architecture.md §8.2).
"""
from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from sap.intel.bloom import BloomFilter
from sap.intel.sources import (
    AbuseSource,
    IntelHit,
    IntelSource,
    LocalBloomSource,
    MISPSource,
    SimulatedIntelSource,
    VirusTotalSource,
)
from sap.security.audit import ACTION_INTEL_EGRESS, AuditLedger
from sap.security.policy import EgressGate, PolicyViolation

CACHE_TTL_SECONDS = 90 * 24 * 3600  # 90-day TTL per cached sha256 result


class IntelCache:
    """Simple JSONL cache keyed by sha256 (per sandbox; memory-ish, bounded)."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._rows: dict[str, dict] = {}
        self._load()
        self._prune()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            for line in self.path.read_text("utf-8").splitlines():
                if line.strip():
                    row = json.loads(line)
                    self._rows[row["sha256"]] = row
        except Exception:
            self._rows = {}

    def _prune(self) -> None:
        now = time.time()
        expired = [k for k, v in self._rows.items() if now - v.get("ts", 0) > CACHE_TTL_SECONDS]
        for k in expired:
            del self._rows[k]

    def get(self, sha256_hex: str) -> Optional[dict]:
        return self._rows.get(sha256_hex.lower())

    def put(self, sha256_hex: str, hit: dict) -> None:
        self._rows[sha256_hex.lower()] = {**hit, "sha256": sha256_hex.lower(),
                                          "ts": time.time()}
        # write-through append (best-effort persistence)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(self._rows[sha256_hex.lower()], sort_keys=True) + "\n")

    def __len__(self) -> int:
        return len(self._rows)


@dataclass
class LookupResult:
    hits: List[IntelHit] = field(default_factory=list)
    egress_used: int = 0
    sources_consulted: List[str] = field(default_factory=list)
    cached: bool = False

    def to_dict(self) -> dict:
        return {
            "hits": [h.to_dict() for h in self.hits],
            "egress_used": self.egress_used,
            "sources_consulted": self.sources_consulted,
            "cached": self.cached,
            "highest_verdict": self.highest_verdict(),
        }

    def highest_verdict(self) -> str:
        rank = {"benign": 0, "unknown": 1, "suspicious": 2, "malicious": 3}
        best = "unknown"
        for h in self.hits:
            if rank.get(h.verdict, 0) > rank[best]:
                best = h.verdict
        return best


class LookupService:
    """Orders memoization + local + remote and records audit + egress events."""

    def __init__(
        self,
        sandbox_root: str | Path,
        bloom: BloomFilter,
        ledger: AuditLedger,
        egress: EgressGate | None = None,
        actor: str = "sap",
        cache: IntelCache | None = None,
    ):
        self.root = Path(sandbox_root)
        self.ledger = ledger
        self.ego = egress or EgressGate()
        self.actor = actor
        self.cache = cache or IntelCache(self.root / "intel" / "cache.jsonl")
        facts_path = self.root / "intel" / "ioc_facts.json"

        self.sources: list[IntelSource] = [
            LocalBloomSource(bloom, facts_path, self.ego),
            SimulatedIntelSource(self.ego),
            VirusTotalSource(self.ego),
            MISPSource(self.ego),
            AbuseSource(self.ego),
        ]

    def consult(self, digests: dict) -> LookupResult:
        sha = digests.get("sha256", "")
        result = LookupResult()
        if not sha:
            return result

        cached = self.cache.get(sha)
        if cached:
            self._replay_cache(sha, cached, result)
            result.cached = True
            return result

        for source in self.sources:
            try:
                hit = source.check(sha)
            except PolicyViolation as exc:
                self.ledger.log(self.actor, "INTEL_EGRESS_DENIED",
                                {"source": source.name, "reason": str(exc)})
                continue
            except Exception:
                continue
            if hit is None:
                continue
            result.sources_consulted.append(source.name)
            result.hits.append(hit)
            if source.name == "virustotal":
                result.egress_used += 1
                self.ledger.log(self.actor, ACTION_INTEL_EGRESS,
                                {"host": "api.virustotal.com", "digest": sha})
                self.cache.put(sha, hit.to_dict())
        return result

    def _replay_cache(self, sha: str, row: dict, result: LookupResult) -> None:
        result.cached = True
        result.egress_used = 0
        result.sources_consulted.append("cache")
        result.hits.append(IntelHit(
            digest=sha, source=row.get("source", "cache"),
            verdict=row.get("verdict", "unknown"), detections=row.get("detections", 0),
            total=row.get("total", 0), reference=row.get("reference", "cached"),
            detail={"engine": "cached"}))