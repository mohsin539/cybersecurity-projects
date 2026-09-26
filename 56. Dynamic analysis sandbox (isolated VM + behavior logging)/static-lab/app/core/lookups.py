"""Threat-intelligence hash lookups: VirusTotal, MalwareBazaar, OTX, Hybrid Analysis.

Network calls are made with stdlib `urllib` (TLS 1.2+ via system trust store).
Every provider degrades gracefully: no key -> status="no_key"; network/API error -> status="error".
"""

from __future__ import annotations

import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Optional

from .model import ThreatReport

USER_AGENT = "StaticLab/1.0 (portable static-analysis sandbox)"

_CTX = ssl.create_default_context()
# Enforce modern TLS and never fall back to legacy protocols.
_CTX.minimum_version = ssl.TLSVersion.TLSv1_2

TIMEOUT = 10


def _request(
    url: str,
    *,
    method: str = "GET",
    headers: Optional[dict[str, str]] = None,
    data: Optional[dict] = None,
) -> bytes:
    hdrs = {"User-Agent": USER_AGENT, **(headers or {})}
    if data is not None and method == "POST":
        body = urllib.parse.urlencode(data).encode()
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    else:
        body = None
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    with urllib.request.urlopen(req, timeout=TIMEOUT, context=_CTX) as resp:
        return resp.read()


def _guard(fn: Callable[[], ThreatReport]) -> ThreatReport:
    try:
        return fn()
    except urllib.error.HTTPError as e:
        return ThreatReport(provider="?", status="error", sha256="?", message=f"HTTP {e.code} {e.reason}")
    except (urllib.error.URLError, socket.timeout, ssl.SSLError, TimeoutError) as e:
        return ThreatReport(provider="?", status="error", sha256="?", message=f"network: {e}")
    except Exception as e:  # noqa: BLE001
        return ThreatReport(provider="?", status="error", sha256="?", message=str(e)[:200])


def _norm_score(stats: dict) -> int:
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    harmless = int(stats.get("undetected", 0) or 0) + int(stats.get("harmless", 0) or 0)
    total = malicious + suspicious + harmless
    if total <= 0:
        return 0
    return min(100, round((malicious + 0.5 * suspicious) / total * 100))


# ---------------------------------------------------------------------------
# VirusTotal v3
# ---------------------------------------------------------------------------


def virus_total(sha256: str, api_key: Optional[str]) -> ThreatReport:
    if not api_key:
        return ThreatReport("virustotal", "no_key", sha256, "API key not configured")
    raw = _request(
        f"https://www.virustotal.com/api/v3/files/{sha256}",
        headers={"x-apikey": api_key},
    )
    js = json.loads(raw)
    attrs = js.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    stats.pop("type-unsupported", None)
    score = _norm_score(stats)
    malicious = int(stats.get("malicious", 0) or 0)
    return ThreatReport(
        "virustotal",
        "ok",
        sha256,
        f"{malicious} engine(s) flagged",
        score,
        summary={
            "reputation": attrs.get("reputation"),
            "harmless": stats.get("harmless"),
            "malicious": malicious,
            "suspicious": stats.get("suspicious"),
            "undetected": stats.get("undetected"),
            "meaningful_name": attrs.get("meaningful_name"),
        },
        url=f"https://www.virustotal.com/gui/file/{sha256}",
    )


# ---------------------------------------------------------------------------
# MalwareBazaar
# ---------------------------------------------------------------------------


def malware_bazaar(sha256: str, api_key: Optional[str] = None) -> ThreatReport:
    headers = {}
    if api_key:
        headers["API-KEY"] = api_key
    raw = _request(
        "https://mb-api.abuse.ch/api/v1/",
        method="POST",
        headers=headers,
        data={"query": "get_info", "hash": sha256},
    )
    js = json.loads(raw)
    if js.get("query_status") != "ok":
        return ThreatReport("malwarebazaar", "error", sha256, js.get("query_status", "no result"))
    rows = js.get("data") or []
    if not rows:
        return ThreatReport("malwarebazaar", "ok", sha256, "no record", 0, {}, "https://bazaar.abuse.ch/sample/")
    r = rows[0]
    tags = r.get("tags") or []
    signature = r.get("signature") or "unknown"
    return ThreatReport(
        "malwarebazaar",
        "ok",
        sha256,
        f"signature={signature}",
        min(100, 35 + 10 * (int(r.get("intelligence", {}).get("clicks", 0) or 0) > 0)),
        summary={"signature": signature, "tags": tags, "file_type": r.get("file_type"), "first_seen": r.get("first_seen")},
        url=f"https://bazaar.abuse.ch/sample/{sha256}/",
    )


# ---------------------------------------------------------------------------
# AlienVault OTX
# ---------------------------------------------------------------------------


def otx(sha256: str, api_key: Optional[str]) -> ThreatReport:
    if not api_key:
        return ThreatReport("otx", "no_key", sha256, "API key not configured")
    raw = _request(
        f"https://otx.alienvault.com/api/v1/indicators/file/{sha256}/general",
        headers={"X-OTX-API-KEY": api_key},
    )
    js = json.loads(raw)
    pulses = js.get("pulse_info", {}).get("pulses") or []
    count = len(pulses)
    return ThreatReport(
        "otx",
        "ok",
        sha256,
        f"{count} related pulse(s)",
        min(100, int((int(js.get("validation", 0) or 0)) * 0 if False else (count * 15 + int((js.get("pulse_info", {}) or {}).get("count", 0) or 0) * 20))),
        summary={
            "pulse_count": js.get("pulse_info", {}).get("count", 0),
            "related": [p.get("name") for p in pulses[:8]],
            "validation": js.get("validation"),
        },
        url=f"https://otx.alienvault.com/indicator/file/{sha256}",
    )


# ---------------------------------------------------------------------------
# Hybrid Analysis
# ---------------------------------------------------------------------------


def hybrid_analysis(sha256: str, api_key: Optional[str], secret: Optional[str]) -> ThreatReport:
    if not api_key or not secret:
        return ThreatReport("hybridanalysis", "no_key", sha256, "API key (key:secret) not configured")
    raw = _request(
        "https://www.hybrid-analysis.com/api/v2/search/hash",
        method="POST",
        headers={
            "api-key": api_key,
            "accept": "application/json",
            "user-agent": USER_AGENT,
        },
        data={"hash": sha256},
    )
    js = json.loads(raw)
    if not isinstance(js, list) or not js:
        return ThreatReport("hybridanalysis", "ok", sha256, "no record", 0, {}, "https://www.hybrid-analysis.com/search?query=hash%3A")
    r = js[0]
    verdict = r.get("verdict")
    vmap = {"malicious": 100, "suspicious": 70, "no specific threat": 15, "clean": 0}
    score = vmap.get(verdict, 30)
    return ThreatReport(
        "hybridanalysis",
        "ok",
        sha256,
        f"verdict={verdict}",
        score,
        summary={"threat_score": r.get("threat_score"), "domain": r.get("domains"), "hosts": r.get("hosts")},
        url=f"https://www.hybrid-analysis.com/sample/{sha256}",
    )


# ---------------------------------------------------------------------------
# Provider registry
# ---------------------------------------------------------------------------


PROVIDERS: dict[str, Callable[[str, dict], ThreatReport]] = {
    "virustotal": lambda sha, cfg: virus_total(sha, cfg.get("virustotal")),
    "malwarebazaar": lambda sha, cfg: malware_bazaar(sha, cfg.get("malwarebazaar")),
    "otx": lambda sha, cfg: otx(sha, cfg.get("otx")),
    "hybridanalysis": lambda sha, cfg: hybrid_analysis(sha, cfg.get("hybridanalysis"), cfg.get("hybridanalysis_secret")),
}

REQUIRES_ENTRYPOINT = object()  # placeholder for future dynamic loads


def run_lookups(
    sha256: str,
    config: dict,
    enabled: Optional[list[str]] = None,
    progress: Optional[Callable[[str, str], None]] = None,
) -> list[ThreatReport]:
    """Run enabled lookups (thread-safe: each returns its own ThreatReport)."""
    results: list[ThreatReport] = []
    if enabled is None:
        enabled = [name for name, _ in PROVIDERS.items() if config.get(name)]
    for name in enabled:
        fn = PROVIDERS.get(name)
        if not fn:
            continue
        report = _guard(lambda fn=fn, sha=sha256, cfg=config: fn(sha, cfg))
        report.provider = name
        report.sha256 = sha256
        if progress:
            progress(name, report.status)
        results.append(report)
    return results