"""Scan orchestration — the safety-critical core.

Enforces (fail-closed, order matters):
  1. target host must be in the configured ALLOWED_TARGET_HOSTS allowlist
     (ISO 27001 A.8.22 / A.13.1, NIST SC-7 / AU; prevents the tool from
     being misused against third parties)
  2. non-loopback targets must use HTTPS when REQUIRE_HTTPS_FOR_NON_LOCAL
  3. payload budget capped (settings.scan_max_payloads)
  4. per-user daily quota enforced upstream (ratelimit.enforce_scan_quota)
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.config import settings
from app.db.models import Finding, Report, Scan, ScanStatus
from app.engine.contexts import Context
from app.engine.detection import BeaconRegistry, RedisBeaconRegistry, Scanner
from app.engine.payloads import build_candidates
from app.engine.remediation import csp_recommendation, remediate
from app.engine.reporting import assemble_findings, build_summary
import json as _json

logger = logging.getLogger("xtester.scan")

class ScanPolicyError(Exception):
    """Raised when a scan violates the security policy (fail-closed)."""


def validate_scan_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ScanPolicyError("only http/https targets are supported")
    if not parsed.hostname:
        raise ScanPolicyError("target URL must include a host")
    host = parsed.hostname.lower()
    if not settings.host_allowed(host):
        raise ScanPolicyError(
            f"host '{host}' is not in the scan allowlist (ALLOWED_TARGET_HOSTS). "
            "Only your own lab endpoints may be scanned."
        )
    is_loopback = host in ("localhost", "127.0.0.1", "::1") or host.startswith("127.")
    if not is_loopback and settings.require_https_for_non_local and parsed.scheme != "https":
        raise ScanPolicyError("non-loopback targets must be scanned over HTTPS")


def _registry() -> BeaconRegistry:
    if settings.celery_task_always_eager or settings.app_env in ("test", "development"):
        from app.engine.detection import memory_registry

        return memory_registry
    try:
        from redis import Redis

        client = Redis.from_url(settings.celery_broker_url)
        return RedisBeaconRegistry(client)
    except Exception:  # pragma: no cover
        from app.engine.detection import memory_registry

        return memory_registry


def run_scan_sync(scan: Scan, db: Session) -> Scan:
    """Execute a scan end-to-end. Runs inline (blocking)."""
    validate_scan_url(scan.scan_url)
    scan.status = ScanStatus.running
    scan.started_at = datetime.now(timezone.utc)
    db.add(scan)
    db.commit()

    context_kinds = _parse_contexts(scan.context)
    beacon_base = f"{settings.public_base_url.rstrip('/')}/collect/{scan.id}"
    candidates = build_candidates(
        context_kinds=context_kinds,
        base_url=scan.scan_url,
        beacon_base=beacon_base,
        max_payloads=settings.scan_max_payloads,
    )
    scan.payload_count = len(candidates)
    db.add(scan)
    db.commit()
    if not candidates:
        scan.status = ScanStatus.failed
        scan.error = "no candidates generated for the requested context"
        scan.finished_at = datetime.now(timezone.utc)
        db.add(scan)
        db.commit()
        return scan

    scanner = Scanner(registry=_registry())
    probes = asyncio.run(
        scanner.run(candidates, scan.id, progress=lambda c, p: None)
    )

    findings = assemble_findings(candidates, probes)
    headers = _fetch_headers_light(scan.scan_url)
    summary = build_summary(findings, len(candidates), scan.scan_url, headers)

    for f in findings:
        db.add(
            Finding(
                scan_id=scan.id,
                payload=f.candidate.payload,
                vector_name=f.candidate.vector_name,
                vector_category=f.candidate.category,
                context=f.candidate.context.kind.value,
                evasion=f.candidate.strategy,
                url=f.candidate.proof_url,
                verdict=f.probe.verdict,
                evidence=_json.dumps(
                    {"dialogs": f.probe.dialogs, "errors": f.probe.errors,
                     "beacon": f.probe.beacon_hit, "dom_token": f.probe.dom_contains_token}
                ),
                severity=f.severity,
                cvss_score=f.cvss,
                poc=f.candidate.proof_url,
                remediation=remediate(f.candidate.context),
            )
        )

    db.add(
        Report(
            scan_id=scan.id,
            summary=_json.dumps(summary),
            security_headers=_json.dumps(headers or {}),
            csp_recommendation=csp_recommendation(),
        )
    )

    retained_days = 90
    scan.executed_count = summary["executed"]
    scan.safe_count = summary["clean"]
    scan.max_severity = summary["max_severity"]
    scan.cvss_score = summary["max_cvss"]
    scan.status = ScanStatus.completed
    scan.finished_at = datetime.now(timezone.utc)
    scan.retained_until = scan.finished_at + timedelta(days=retained_days)
    db.add(scan)
    db.commit()

    logger.info("scan %s completed: %d findings (max %s)", scan.id, len(findings), summary["max_severity"])
    return scan


def _parse_contexts(raw: str | Context | list) -> list[Context]:
    if isinstance(raw, Context):
        return [raw]
    if isinstance(raw, list):
        return [Context(c) if isinstance(c, str) else c for c in raw]
    value = raw if isinstance(raw, str) else ""
    if value == "auto" or value in ("", "all"):
        return [Context.HTML, Context.ATTR, Context.SCRIPT, Context.URL, Context.DOM]
    try:
        return [Context(value)]
    except ValueError:
        return [Context.HTML, Context.ATTR, Context.SCRIPT, Context.URL, Context.DOM]


def _fetch_headers_light(url: str) -> dict[str, str] | None:
    """Best-effort header snapshot for the report (no full browser needed)."""
    try:
        import urllib.request

        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "xtester-lab"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return {k.lower(): v for k, v in resp.headers.items()}
    except Exception:  # noqa: BLE001
        return None