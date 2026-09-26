"""Analysis engine: Parse & Normalize -> layers 1-3 -> fusion (ARCHITECTURE.md 4.1)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from . import layers, normalize
from .layers import Det


@dataclass
class ParamFinding:
    parameter: normalize.ParameterValue
    dets: List[Det] = field(default_factory=list)
    score: float = 0.0
    severity: str = "INFO"
    verdict: str = "CLEAN"
    injection_types: List[str] = field(default_factory=list)
    db_flavors: List[str] = field(default_factory=list)

    @property
    def is_flagged(self) -> bool:
        return self.verdict in ("MONITOR", "FLAG", "BLOCK")


@dataclass
class AnalysisReport:
    meta: Dict[str, str]
    findings: List[ParamFinding]
    url: str = ""

    @property
    def flagged(self) -> List[ParamFinding]:
        return [f for f in self.findings if f.is_flagged]

    @property
    def max_severity(self) -> str:
        order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        best = "INFO"
        for f in self.findings:
            if order.index(f.severity) > order.index(best):
                best = f.severity
        return best


def analyze_target(
    target: str, raw_request: bool = False, modifiers: Dict[str, float] | None = None
) -> AnalysisReport:
    params, meta = normalize.extract_parameters(target, raw_request=raw_request)
    findings: List[ParamFinding] = []
    for p in params:
        dets: List[Det] = []
        dets += layers.layer1_signature(p.decoded)
        dets += layers.layer2_grammar(p.decoded)
        dets += layers.layer3_heuristics(p.decoded, p.expected_type)
        fused = layers.fuse(dets, modifiers)
        findings.append(ParamFinding(
            parameter=p, dets=dets,
            score=fused["score"], severity=fused["severity"],
            verdict=fused["verdict"],
            injection_types=fused["injection_types"],
            db_flavors=fused["db_flavors"]))
    return AnalysisReport(meta=meta, findings=findings, url=target)


def inline_analyze(param_name: str, value: str, expected_type: str = "string") -> ParamFinding:
    """Analyze a single inline (proxy/agent-style) parameter value."""
    dec, seen = normalize.deep_decode(value)
    p = normalize.ParameterValue(
        name=param_name, source="inline",
        expected_type=expected_type, decoded=dec, encodings_seen=seen).finalize()
    dets: List[Det] = []
    dets += layers.layer1_signature(p.decoded)
    dets += layers.layer2_grammar(p.decoded)
    dets += layers.layer3_heuristics(p.decoded, p.expected_type)
    fused = layers.fuse(dets)
    return ParamFinding(parameter=p, dets=dets, score=fused["score"],
                        severity=fused["severity"], verdict=fused["verdict"],
                        injection_types=fused["injection_types"],
                        db_flavors=fused["db_flavors"])


def findings_to_rows(report: AnalysisReport) -> List[Dict[str, str]]:
    rows = []
    for f in report.findings:
        rows.append({
            "param": f.parameter.name,
            "source": f.parameter.source,
            "severity": f.severity,
            "verdict": f.verdict,
            "score": f"{f.score:.2f}",
            "types": ",".join(f.injection_types) or "-",
            "db": ",".join(f.db_flavors) or "-",
            "dets": str(len(f.dets)),
            "digest": f.parameter.digest[:12],
        })
    return rows