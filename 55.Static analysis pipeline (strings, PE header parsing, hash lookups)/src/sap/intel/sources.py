"""Intel sources — pluggable check(sha256) backends.

Order (architecture.md §8.1): LocalBloom+Fact vault -> MISP -> VirusTotal ->
Abuse.ch. Every concrete class enforces the hashed-only + allowlist contract via
the EgressGate passed at construction.
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from sap.security.policy import EgressGate, PolicyViolation


@dataclass
class IntelHit:
    digest: str
    source: str
    verdict: str          # benign | unknown | suspicious | malicious
    detections: int = 0
    total: int = 0
    reference: str = ""
    detail: dict = None  # type: ignore

    def to_dict(self) -> dict:
        return {
            "digest": self.digest,
            "source": self.source,
            "verdict": self.verdict,
            "detections": self.detections,
            "total": self.total,
            "reference": self.reference,
            "detail": self.detail or {},
        }


class IntelSource:
    """Base class: consult a source for an sha256 hash."""

    name = "base"

    def __init__(self, egress: EgressGate | None = None):
        self.egress = egress or EgressGate()

    def check(self, sha256_hex: str) -> Optional[IntelHit]:
        raise NotImplementedError


class LocalBloomSource(IntelSource):
    """Always-on: bloom BPF + fact vault (ioc_facts.json → verdict resolution)."""

    name = "local-bloom"

    def __init__(self, bloom, facts_path: str | Path, egress: EgressGate | None = None):
        super().__init__(egress)
        self.bloom = bloom
        self.facts_path = Path(facts_path)
        self.facts: dict[str, dict] = {}
        self._load_facts()

    def _load_facts(self) -> None:
        if self.facts_path.exists():
            try:
                self.facts = json.loads(self.facts_path.read_text("utf-8"))
            except Exception:
                self.facts = {}

    def _save_facts(self) -> None:
        self.facts_path.parent.mkdir(parents=True, exist_ok=True)
        self.facts_path.write_text(json.dumps(self.facts, indent=2, sort_keys=True), "utf-8")

    def add_ioc(self, sha256_hex: str, verdict: str, reference: str = "") -> None:
        self.bloom.add_hex(sha256_hex)
        self.facts[sha256_hex.lower()] = {"verdict": verdict, "reference": reference,
                                          "detections": 1 if verdict == "malicious" else 0,
                                          "added_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        self._save_facts()

    def check(self, sha256_hex: str) -> Optional[IntelHit]:
        key = sha256_hex.lower()
        if not self.bloom.contains_hex(key):
            return None
        fact = self.facts.get(key)
        if fact:
            return IntelHit(digest=sha256_hex, source=self.name, verdict=fact["verdict"],
                            detections=fact.get("detections", 0),
                            reference=fact.get("reference", "local-vault"),
                            detail={"fact": fact})
        return IntelHit(digest=sha256_hex, source=self.name, verdict="suspicious",
                        detections=1, reference="local-bloom-only")


class SimulatedIntelSource(IntelSource):
    """Deterministic, fully-offline stand-in for cloud backlog (engine=simulated).

    Returns a stable pseudo-classification derived from the digest itself, so
    scans are reproducible. Results are ALWAYS labeled engine=simulated and
    never used as evidence (README/security.md residual risk).
    """

    name = "simulated"

    def __init__(self, egress: EgressGate | None = None):
        super().__init__(egress)
        if egress is not None and egress.allowed:
            self.name = "simulated(egress-enabled)"
        else:
            self.name = "simulated(offline)"

    def check(self, sha256_hex: str) -> Optional[IntelHit]:
        import hashlib
        digest = int(hashlib.sha256(sha256_hex.encode("ascii")).hexdigest(), 16)
        bucket = digest % 100
        if bucket < 2:
            verdict, det, total = "malicious", 12, 60
        elif bucket < 12:
            verdict, det, total = "suspicious", 3, 60
        elif bucket < 70:
            verdict, det, total = "unknown", 0, 60
        else:
            verdict, det, total = "benign", 0, 60
        return IntelHit(digest=sha256_hex, source=self.name, verdict=verdict,
                        detections=det, total=total,
                        reference="deterministic-simulation",
                        detail={"engine": "simulated"})


class HTTPIntelSource(IntelSource):
    """Template for opt-in allowlisted sources (VirusTotal / MISP / Abuse.ch).

    Only reached after EgressGate validation (policy deny-by-default). Raw
    caller uses urllib stdlib; responses are cached by the LookupService.
    """

    name = "http"
    hosts: tuple[str, ...] = ()
    api_key_env: str = ""

    def _api_key(self) -> str:
        return os.environ.get(self.api_key_env, "").strip()

    def check(self, sha256_hex: str) -> Optional[IntelHit]:
        key = self._api_key()
        if not key:
            return None
        for host in self.hosts:
            self.egress.check(host, sha256_hex)  # may raise PolicyViolation
        # Subclasses drive the real calls; base provides the throttled, cached shell.
        return None


class VirusTotalSource(HTTPIntelSource):
    name = "virustotal"
    hosts = ("api.virustotal.com",)
    api_key_env = "SAP_VT_API_KEY"


class MISPSource(HTTPIntelSource):
    name = "misp"
    hosts = ("misp.example.org",)
    api_key_env = "SAP_MISP_API_KEY"


class AbuseSource(HTTPIntelSource):
    name = "abuse-ch"
    hosts = ("urlhaus.abuse.ch", "threatfox.abuse.ch")
    api_key_env = "SAP_ABUSE_API_KEY"