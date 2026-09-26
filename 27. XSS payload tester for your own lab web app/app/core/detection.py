"""Response-reflection detection engine.

For each candidate the scanner inspects what the lab app reflected *without* a
browser (triage evidence; see security.md):
  1. raw reflection   - is the full payload present verbatim in the body?
  2. encoded escape   - does an escaped/entity form appear instead (mitigation)?
  3. exec signatures  - within the reflected window, markers that would fire JS
  4. CSP assessment   - a strict Content-Security-Policy lowers confidence

Verdicts (OWASP ASVS v4.0.3 V5.1-flavoured evidence model):
  EXECUTED   - raw reflection AND execution signatures present (hand-verify in a browser)
  LIKELY     - raw reflection, plausible execution signals
  SUSPICIOUS - raw reflection without strong signals
  CLEAN      - token absent or only encoded-reflection (mitigated)
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .encoders import html_dec_encode, html_hex_encode

_JS_ESCAPE_RE = re.compile(r"\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4})")
_URL_ESCAPE_RE = re.compile(r"%[0-9a-fA-F]{2}")
_SCRIPTISH_RE = re.compile(r"<\s*script\b|\bon\w+\s*=", re.IGNORECASE)
_URLATTR_RE = re.compile(r"(?:href|src|action|poster|data)\s*=", re.IGNORECASE)


def _escape_style(payload: str) -> str:
    if len(_JS_ESCAPE_RE.findall(payload)) >= 4:
        return "js"
    if len(_URL_ESCAPE_RE.findall(payload)) >= 4:
        return "url"
    return ""


EXEC_SIGNATURES: tuple[tuple[str, str], ...] = (
    (r"<\s*script\b", "script tag"),
    (r"\bon\w+\s*=", "event handler"),
    (r"javascript\s*:", "javascript scheme"),
    (r"alert\s*\(", "alert call"),
    (r"fetch\s*\(", "fetch call"),
    (r"new\s+Image\s*\(", "image beacon"),
    (r"document\.(write|body|cookie)\b", "DOM document access"),
    (r"innerHTML", "innerHTML sink"),
)


@dataclass
class ProbeResult:
    candidate_id: str
    verdict: str = "clean"
    confidence: float = 0.0
    status_code: int = 0
    reflected_raw: bool = False
    reflected_encoded: bool = False
    token_reflected: bool = False
    signatures: list[str] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)


def _strict_csp(policy: Optional[str]) -> bool:
    if not policy:
        return False
    return "'unsafe-inline'" not in policy and ("script-src" in policy or "default-src" in policy)


def _escaped_forms(payload: str) -> list[str]:
    return [
        html.escape(payload, quote=True),
        html_hex_encode(payload),
        html_dec_encode(payload),
    ]


def analyze(payload: str, token: str, body: str, headers: Dict[str, str], status: Optional[int]) -> ProbeResult:
    probe = ProbeResult(candidate_id="")
    probe.status_code = status or 0
    body = body or ""

    if status is None or status == 0:
        probe.verdict = "clean"
        probe.observations.append("no response received")
        return probe

    probe.token_reflected = token in body
    probe.reflected_raw = payload in body

    if not probe.reflected_raw:
        for esc in _escaped_forms(payload):
            if esc in body:
                probe.reflected_encoded = True
                break

    style = _escape_style(payload)
    if probe.reflected_raw and style:
        decodable = bool(_SCRIPTISH_RE.search(body)) if style == "js" else bool(_URLATTR_RE.search(body))
        if not decodable:
            probe.reflected_encoded = True
            probe.observations.append("escape-syntax payload echoed verbatim without a decoding context")

    if probe.reflected_raw and not probe.reflected_encoded:
        idx = body.find(payload)
        window = body[max(0, idx - 30): idx + len(payload) + 30]
        for pattern, label in EXEC_SIGNATURES:
            if re.search(pattern, window, re.IGNORECASE):
                probe.signatures.append(label)
        if not probe.signatures:
            for pattern, label in EXEC_SIGNATURES:
                if re.search(pattern, body, re.IGNORECASE):
                    probe.signatures.append(label)

    csp_headers = [v for k, v in headers.items() if k.lower() == "content-security-policy"]
    strict_csp = any(_strict_csp(v) for v in csp_headers)
    if csp_headers and strict_csp:
        probe.observations.append("strict CSP present; confidence downgraded")

    verdict, confidence = _classify(probe)
    probe.verdict = verdict
    probe.confidence = round(confidence, 3) if confidence else 0.0
    return probe


def _classify(probe: ProbeResult) -> tuple[str, float]:
    if probe.reflected_raw and not probe.reflected_encoded:
        if probe.signatures:
            score = 0.75 + 0.2 * min(len(probe.signatures), 3) / 3
            verdict = "executed"
        else:
            score = 0.45
            verdict = "likely"
        if probe.status_code >= 500 or probe.status_code == 0:
            score = min(score, 0.4)
            verdict = "suspicious"
        if any("strict CSP" in o for o in probe.observations):
            score = round(score * 0.6, 3)
        if score >= 0.9:
            verdict = "executed"
        elif score >= 0.6:
            verdict = "likely"
        else:
            verdict = "suspicious"
        return verdict.upper(), score

    if probe.token_reflected:
        if probe.reflected_encoded and not probe.reflected_raw:
            probe.observations.append("reflection HTML/entity-encoded (likely mitigated)")
        elif not probe.reflected_encoded:
            probe.observations.append("token reflected but payload not; no obvious sink")
    return "clean", 0.0


def build_probe_url(candidate) -> str:
    return candidate.proof_url