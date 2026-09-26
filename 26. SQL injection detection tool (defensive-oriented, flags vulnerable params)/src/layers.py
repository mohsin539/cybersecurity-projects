"""Detection layers 1-3 plus fusion (ARCHITECTURE.md sections 6.1-6.3, 5.3).

Detectors are independent; each emits Dets; the engine fuses them with
contextual modifiers into a single confidence + severity verdict.
"""
from __future__ import annotations

import re as _re
from dataclasses import dataclass
from typing import List, Optional

from . import rules
from . import tokenizer


@dataclass
class Det:
    rule_id: str
    name: str
    weight: float
    layer: int
    injection_type: str
    db_flavor: str
    cwe: str
    owasp: str
    evidence: str


def layer1_signature(decoded: str) -> List[Det]:
    """Layer 1 - signature/rule engine over the normalized value."""
    out: List[Det] = []
    for r, rx in rules.compiled_rules():
        m = rx.search(decoded)
        if m:
            out.append(Det(rule_id=r.rid, name=r.name, weight=r.weight, layer=1,
                           injection_type=r.injection_type, db_flavor=r.db_flavor,
                           cwe=r.cwe, owasp=r.owasp,
                           evidence=(decoded[max(0, m.start() - 24): m.end() + 24]
                                     or "<match>")))
    return out


def layer2_grammar(decoded: str) -> List[Det]:
    """Layer 2 - SQL-aware structural grammar detection."""
    out: List[Det] = []
    for hit in tokenizer.detect_structure(decoded):
        out.append(Det(rule_id="L2", name=hit.reason, weight=hit.confidence, layer=2,
                       injection_type="generic", db_flavor=hit.db_flavor,
                       cwe="CWE-89", owasp="A03", evidence=hit.reason))
    return out


def layer3_heuristics(decoded: str, expected_type: str = "string") -> List[Det]:
    """Layer 3 - heuristic behavioral detectors (type-contract, character profile)."""
    out: List[Det] = []
    v = decoded.strip()

    # Type-contract violation: numeric param carrying SQL syntax
    if expected_type in ("int",) and not tokenizer.is_numeric(v):
        risky = any(ch in v for ch in "'\"=<>();-/*#%")
        if risky:
            out.append(Det(rule_id="H-001", name="type-contract violation",
                           weight=0.85, layer=3, injection_type="generic",
                           db_flavor="ANY", cwe="CWE-89", owasp="A03",
                           evidence=f"int-typed param got non-numeric value w/ SQL chars"))

    # Quote density anomaly (>= 2 quotes or 1 quote in non-text param)
    q = v.count("'") + v.count('"')
    if expected_type in ("int", "date-candidate", "uuid"):
        base = 0
    elif expected_type == "string":
        base = 1
    else:
        base = 1
    if q > base + 1:
        out.append(Det(rule_id="H-002", name="quote-density anomaly",
                       weight=0.6, layer=3, injection_type="error",
                       db_flavor="ANY", cwe="CWE-89", owasp="A03",
                       evidence=f"quote count {q} exceeds type baseline"))

    # Semicolon density (stacked-query opportunity)
    sc = v.count(";")
    if sc >= 1:
        out.append(Det(rule_id="H-003", name="semicolon delimiter present",
                       weight=0.5, layer=3, injection_type="stacked",
                       db_flavor="ANY", cwe="CWE-89", owasp="A03",
                       evidence=f"{sc} semicolons in param value"))

    # Hex blob / encoded payload indicator
    if _re.search(r"0x[0-9a-fA-F]{4,}", v):
        out.append(Det(rule_id="H-004", name="hex blob payload",
                       weight=0.7, layer=3, injection_type="union",
                       db_flavor="ANY", cwe="CWE-89", owasp="A03",
                       evidence="long hex-escaped blob (CHAR(0x...) style)"))

    return out


def fuse(dets: List[Det], modifiers: Optional[dict] = None) -> dict:
    """Fusion engine (ARCHITECTURE.md section 5.3)."""
    modifiers = modifiers or {}
    if not dets:
        score = 0.0
    else:
        total = sum(d.weight for d in dets)
        # Cap so 2 strong hits saturate; avoids tiny-noise accumulation.
        score = min(1.0, total / 1.5)

    # Contextual modifiers
    score += modifiers.get("baseline_deviation", 0.0)
    score += modifiers.get("source_reputation", 0.0)
    score += modifiers.get("correlation", 0.0)
    score = max(0.0, min(1.0, score))

    severity = (
        "INFO" if score == 0 else
        "LOW" if score < 0.35 else
        "MEDIUM" if score < 0.6 else
        "HIGH" if score < 0.85 else
        "CRITICAL"
    )
    verdict = (
        "CLEAN" if score < 0.2 else
        "MONITOR" if score < 0.5 else
        "FLAG" if score < 0.8 else
        "BLOCK"
    )
    strengths = sorted({d.injection_type for d in dets})
    db = sorted({d.db_flavor for d in dets})
    return {
        "score": round(score, 3),
        "severity": severity,
        "verdict": verdict,
        "injection_types": strengths,
        "db_flavors": db,
        "detector_count": len(dets),
        "detectors": [d.rule_id for d in dets],
    }