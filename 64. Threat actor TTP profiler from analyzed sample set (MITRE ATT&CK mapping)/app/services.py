"""TTPProfiler :: core services
Import orchestrator + ATT&CK mapping engine + weighting + attribution.
Pure-Python/NumPy, fully headless-testable.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass
from pathlib import Path

from . import data as D
from .models import ActorMatch, ActorProfile, EvidenceRecord, Sample, TechniqueMapping
from .security import normalize_schema, safe_join

_HASH_RE = re.compile(r"^[0-9a-fA-F]{64}$")


# ---------------------------------------------------------------------------
# 1. INGESTION
# ---------------------------------------------------------------------------
class ImportError_(Exception):
    pass


@dataclass
class ImportResult:
    set_id: str
    namespace: str
    samples: list[Sample]
    errors: list[str]


class Importer:
    SUPPORTED = {".json", ".jsonl", ".txt"}

    def __init__(self, store, audit, namespace: str, verdict_threshold: str = "suspicious"):
        self.store = store
        self.audit = audit
        self.namespace = namespace
        self.verdict_threshold = verdict_threshold

    def scan_dir(self, root: str | Path) -> list[Path]:
        return sorted(p for p in Path(root).iterdir() if p.suffix.lower() in self.SUPPORTED)

    def ingest_directory(self, root: str | Path, set_id: str, set_name: str) -> ImportResult:
        files = self.scan_dir(root)
        if not files:
            raise ImportError_(f"No supported report files found in {root}")
        samples: list[Sample] = []
        errors: list[str] = []
        for path in files:
            try:
                samples.append(self._parse_file(safe_join(Path(root), path.name), set_id))
            except Exception as exc:  # noqa: BLE001 - quarantine parser failures
                errors.append(f"{path.name}: {exc}")
        samples = self._dedupe(samples)
        if not samples:
            raise ImportError_("No valid samples parsed")
        self.store.save_sample_set(set_id, set_name, f"Imported from {root}", "")
        for s in samples:
            self.store.save_sample(s)
        self.audit.record(
            "IMPORT",
            f"set={set_id} files={len(files)} samples={len(samples)} errors={len(errors)}",
        )
        return ImportResult(set_id=set_id, namespace=self.namespace, samples=samples, errors=errors)

    def _parse_file(self, path: Path, set_id: str) -> Sample:
        if path.suffix.lower() == ".jsonl":
            parsed = [json.loads(line) for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]
        else:
            parsed = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        if isinstance(parsed, list):
            items = parsed
        else:
            items = [parsed]
        if items:
            return self._build_sample(items[0], path.name, set_id)
        raise ImportError_("empty report")

    def _build_sample(self, raw: dict, origin: str, set_id: str) -> Sample:
        data = normalize_schema(raw)
        filename = str(data.get("filename") or origin)
        sha256 = str(data.get("sha256") or "").lower()
        if not _HASH_RE.match(sha256):
            sha256 = hashlib.sha256(origin.encode("utf-8")).hexdigest()
        family = str(data.get("family") or "")
        verdict = str(data.get("verdict") or "unknown")
        yara = [str(x) for x in (data.get("yara_rules") or [])]
        av = [str(x) for x in (data.get("av_names") or [])]
        net = data.get("network") or {}
        domains = [str(x).lower() for x in net.get("domains") or []]
        ips = [str(x) for x in net.get("ips") or []]
        files = data.get("files") or []
        file_paths: list[str] = []
        for f in files:
            fp = f.get("path") or f.get("name") or ""
            if fp:
                file_paths.append(str(fp))
                for s in (f.get("strings") or []):
                    if isinstance(s, str):
                        domains.append(s.lower())
        registry = [str(x) for x in (data.get("registry") or [])]
        processes = [str(x) for x in (data.get("processes") or [])]
        strings = [str(x) for x in (data.get("strings") or [])]
        behaviors = [str(x).lower() for x in (data.get("behaviors") or [])]
        meta = dict(data.get("meta") or {})
        meta["origin"] = origin
        meta["set_id"] = set_id

        sample = Sample(
            sha256=sha256, filename=filename or origin, family=family, verdict=verdict,
            meta=meta, yara_rules=yara, av_names=av,
            network_domains=domains, network_ips=ips, file_paths=file_paths,
            registry_keys=registry, process_names=processes, strings=strings,
        )
        sample.evidence = self._evidence_from(sample, behaviors, files)
        return sample

    def _evidence_from(self, s: Sample, behaviors: list[str], files: list) -> list[EvidenceRecord]:
        evs = [
            EvidenceRecord(s.sha256, "static", "yara", text=r, tags=["yara"]) for r in s.yara_rules
        ]
        evs += [
            EvidenceRecord(s.sha256, "network", "c2_domain", text=d, tags=["c2:domain"])
            for d in s.network_domains
        ]
        evs += [
            EvidenceRecord(s.sha256, "network", "c2_ip", text=i, tags=["c2:ip"])
            for i in s.network_ips
        ]
        evs += [
            EvidenceRecord(s.sha256, "static", "filepath", text=p, tags=["file:path"])
            for p in s.file_paths
        ]
        evs += [
            EvidenceRecord(s.sha256, "static", "registry", text=k, tags=["registry:key"])
            for k in s.registry_keys
        ]
        evs += [
            EvidenceRecord(s.sha256, "dynamic", "process", text=p, tags=["process:name"])
            for p in s.process_names
        ]
        evs += [
            EvidenceRecord(s.sha256, "static", "string", text=t, tags=["static:string"])
            for t in s.strings[:200]
        ]
        evs += [
            EvidenceRecord(s.sha256, "dynamic", "behavior", text=b, tags=[b])
            for b in behaviors
        ]
        for f in files:
            for key in ("apis", "imports", "pattern_matches"):
                for item in (f.get(key) or []):
                    evs.append(EvidenceRecord(s.sha256, "static", "api", text=str(item), tags=[key]))
        return evs

    def _dedupe(self, samples: list[Sample]) -> list[Sample]:
        seen: dict[str, Sample] = {}
        for s in samples:
            if s.sha256 in seen:
                seen[s.sha256].verdict = _worst(seen[s.sha256].verdict, s.verdict)
                seen[s.sha256].yara_rules = _merge_unique(seen[s.sha256].yara_rules, s.yara_rules)
                seen[s.sha256].evidence += s.evidence
            else:
                seen[s.sha256] = s
        return list(seen.values())


# ---------------------------------------------------------------------------
# 2. MITRE ATT&CK MAPPING
# ---------------------------------------------------------------------------
class AttackMapper:
    def __init__(self, rules: list[dict] | None = None):
        self.rules = rules or D.RULES

    def map_sample(self, sample: Sample) -> dict[str, list[str]]:
        """Return {technique_id: [evidence_text matching]} for a sample."""
        text = sample.all_text.lower()
        matches: dict[str, list[str]] = {}
        for rule in self.rules:
            hits: list[str] = []
            for pat in rule.get("patterns", []):
                if pat.lower() in text:
                    hits.append(f"pattern:{pat}")
            for beh in rule.get("behaviors", []):
                if self._tagged(sample, beh):
                    hits.append(f"behavior:{beh}")
            if hits:
                matches.setdefault(rule["technique"], []).extend(hits)
        return matches

    @staticmethod
    def _tagged(sample: Sample, behavior: str) -> bool:
        for ev in sample.evidence:
            if ev.kind == "behavior" or behavior in ev.tags:
                if behavior in ev.tags or behavior == ev.text:
                    return True
        return False


class Scorer:
    """Weighted confidence for techniques & tactics."""

    def __init__(self, max_signal: float = 1.6):
        self.max_signal = max_signal

    def technique_map(self, sample_maps: list[dict[str, list[str]]], total_samples: int) -> list[TechniqueMapping]:
        agg: dict[str, dict] = {}
        for sm in sample_maps:
            for tid, hits in sm.items():
                entry = agg.setdefault(tid, {"hits": [], "samples": 0})
                entry["hits"].extend(hits)
                entry["samples"] += 1
        out: list[TechniqueMapping] = []
        for tid, info in agg.items():
            hits = info["hits"]
            coverage = info["samples"] / max(total_samples, 1)
            strength = min(self.max_signal, len(hits) * 0.35)
            score = min(1.0, strength * (0.5 + coverage))
            out.append(TechniqueMapping(
                technique_id=tid,
                evidence_ids=list(dict.fromkeys(hits))[:50],
                evidence_strength=strength,
                sample_coverage=coverage,
                score=score,
            ))
        return out

    @staticmethod
    def tactic_scores(techniques: list[TechniqueMapping]) -> dict[str, float]:
        tac: dict[str, float] = {}
        for tm in techniques:
            for tshort in D.TECHNIQUE_TACTICS.get(tm.technique_id, []):
                tac[tshort] = tac.get(tshort, 0.0) + tm.score
        return tac

    @staticmethod
    def profile_confidence(tactic_scores: dict[str, float], technique_count: int) -> float:
        if not tactic_scores:
            return 0.0
        total = sum(tactic_scores.values())
        breadth = min(1.0, technique_count / 8.0)
        return min(100.0, round((total / max(len(tactic_scores), 1)) * 100.0 * 0.7 + breadth * 100.0 * 0.3, 1))


# ---------------------------------------------------------------------------
# 3. ATTRIBUTION (threat actor clustering)
# ---------------------------------------------------------------------------
class Attributor:
    """k-NN style ranking against the public group dataset (pure NumPy)."""

    def __init__(self, groups: dict | None = None):
        self.groups = groups or D.GROUPS
        self.software = D.SOFTWARE

    def rank(self, technique_ids: set[str]) -> list[ActorMatch]:
        if not technique_ids:
            return []
        results: list[ActorMatch] = []
        for gid, group in self.groups.items():
            gset = set(group["techniques"])
            inter = technique_ids & gset
            if not inter:
                continue
            union = technique_ids | gset
            jac = len(inter) / max(len(union), 1)
            recall = len(inter) / max(len(gset), 1)
            sim = 0.6 * jac + 0.4 * recall
            software_hits = [
                s["id"] + " " + s["name"] for s in self.software.values()
                if s.get("group") == gid and (set(s["techniques"]) & technique_ids)
            ]
            conf = 100.0 * min(1.0, sim * (1.0 + 0.15 * len(software_hits)))
            unmatched = sorted(gset - technique_ids)
            delta = [{"technique": t, "status": "matched" if t in inter else "missing"} for t in sorted(inter | (gset - technique_ids))]
            results.append(ActorMatch(
                group_id=gid, name=group["name"], aliases=", ".join(group.get("aliases", [])),
                confidence=round(min(conf, 99.9), 1), matched_techniques=sorted(inter),
                unmatched_group_techniques=unmatched, software_hits=software_hits,
                similarity=round(sim, 3), evidence_delta=delta,
            ))
        results.sort(key=lambda a: (-a.confidence, -a.similarity))
        return results


# ---------------------------------------------------------------------------
# 4. ORCHESTRATION
# ---------------------------------------------------------------------------
class ProfilerEngine:
    """Single entry to: import → map → score → attribute → persist."""

    def __init__(self, store, audit):
        self.store = store
        self.audit = audit
        self.mapper = AttackMapper()
        self.scorer = Scorer()
        self.attributor = Attributor()

    def build_profile(self, set_id: str, namespace: str = "local") -> ActorProfile | None:
        samples = self.store.load_samples(set_id)
        if not samples:
            return None
        sample_maps = [self.mapper.map_sample(s) for s in samples]
        techniques = self.scorer.technique_map(sample_maps, len(samples))
        tactic_scores = self.scorer.tactic_scores(techniques)
        tech_ids = {t.technique_id for t in techniques}
        ranking = self.attributor.rank(tech_ids)
        confidence = self.scorer.profile_confidence(tactic_scores, len(techniques))
        top = ranking[0] if ranking else None
        grade = _intel_grade(confidence, top)
        profile = ActorProfile(
            id=f"{namespace}-{uuid.uuid4().hex[:12]}", sample_set_id=set_id,
            sample_count=len(samples), tactic_scores=tactic_scores,
            techniques=techniques, actor_ranking=ranking, top_actor=top,
            intel_grade=grade, confidence=confidence,
        )
        self.store.save_profile(profile)
        self.audit.record(
            "PROFILE_BUILT",
            f"profile={profile.id} set={set_id} techniques={len(techniques)} "
            f"top_actor={top.name if top else 'none'} conf={confidence}",
        )
        return profile


def _intel_grade(confidence: float, top: ActorMatch | None) -> str:
    if confidence >= 80 and top:
        return "A"
    if confidence >= 60:
        return "B"
    if confidence >= 40:
        return "C"
    return "D"


def _worst(a: str, b: str) -> str:
    order = {"clean": 0, "unknown": 1, "suspicious": 2, "malicious": 3}
    return a if order.get(a, 1) >= order.get(b, 1) else b


def _merge_unique(a: list[str], b: list[str]) -> list[str]:
    return list(dict.fromkeys([*a, *b]))