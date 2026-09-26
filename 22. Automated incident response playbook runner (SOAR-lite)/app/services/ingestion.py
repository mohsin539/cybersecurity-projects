"""Alert ingestion: normalization, dedup fingerprinting, task scoring.

ISO 27001 A.16 / NIST SP 800-61 detection & analysis phase. Incoming alerts are
mapped to a canonical OCSF-inspired model, PII is redacted before storage, and
duplicates are folded into a prior alert/case.
"""
from __future__ import annotations

import hashlib
import json
import datetime as dt
from dataclasses import dataclass

from sqlalchemy import select

from app.core.redact import redact_payload
from app.db.models import Alert

SEVERITY_MAP = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "info": 1,
    "unknown": 3,
    "": 3,
    None: 3,
}
ASSET_WEIGHT = {
    "domain-controller": 1.0,
    "vault": 1.0,
    "database": 0.8,
    "application": 0.6,
    "endpoint": 0.4,
    "unknown": 0.2,
}


@dataclass
class NormalizedAlert:
    source: str
    category: str
    subcategory: str | None
    title: str
    description: str | None
    vendor_severity: str | None
    severity: int
    asset_id: str | None
    attack_tactic: str | None
    attack_technique: str | None
    indicators: list
    external_id: str | None
    raw: dict
    canonical_hash: str


def fingerprint(payload: dict) -> str:
    """Deterministic fingerprint: normalized minimal fields + IOC set."""
    keys = ["source", "category", "title", "asset_id"]
    iocs = sorted((i.get("type", "") + ":" + i.get("value", "")) for i in payload.get("indicators", []) or [])
    signature = {k: payload.get(k) for k in keys}
    signature["iocs"] = iocs
    return hashlib.sha256(json.dumps(signature, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def normalize_payload(payload: dict) -> NormalizedAlert:
    """Validate + normalize an inbound alert payload."""
    source = str(payload.get("source", "unknown")).lower()[:64]
    indicators = _normalize_indicators(payload.get("indicators", []))

    vendor_sev = str(payload.get("severity", "unknown") or "unknown").lower()[:16]
    severity = int(payload.get("severity_score") or SEVERITY_MAP.get(vendor_sev, 3))

    asset_key = str(payload.get("asset_criticality", "unknown")).lower() or "unknown"
    weight = ASSET_WEIGHT.get(asset_key, 0.5)
    score = min(5.0, severity * (0.7 + weight))

    return NormalizedAlert(
        source=source,
        category=str(payload.get("category", "")).lower()[:64],
        subcategory=str(payload.get("subcategory") or "")[:128] or None,
        title=str(payload.get("title") or "")[:512],
        description=str(payload.get("description") or "")[:4000] or None,
        vendor_severity=vendor_sev or None,
        severity=severity,
        asset_id=str(payload.get("asset_id") or "")[:255] or None,
        attack_tactic=str(payload.get("attack_tactic") or "")[:128] or None,
        attack_technique=str(payload.get("attack_technique") or "")[:128] or None,
        indicators=indicators,
        external_id=str(payload.get("external_id") or "")[:255] or None,
        raw=redact_payload(payload),
        canonical_hash=fingerprint(payload),
    )


def _normalize_indicators(raw: list) -> list:
    out = []
    if not isinstance(raw, list):
        return out
    for ind in raw:
        if not isinstance(ind, dict):
            continue
        itype = str(ind.get("type", "unknown"))[:32]
        value = str(ind.get("value", ""))[:512]
        if not value:
            continue
        out.append({"type": itype, "value": value})
    return out


def find_duplicate(db, canonical_hash: str, window_hours: int = 72) -> Alert | None:
    since = dt.datetime.utcnow() - dt.timedelta(hours=window_hours)
    stmt = select(Alert).where(
        Alert.canonical_hash == canonical_hash,
        Alert.created_at >= since,
    ).order_by(Alert.created_at.asc())
    dup = db.execute(stmt).scalars().all()
    return dup[0] if dup else None


def create_alert(db, payload: dict) -> Alert:
    na = normalize_payload(payload)
    dup = find_duplicate(db, na.canonical_hash)

    alert = Alert(
        external_id=na.external_id,
        source=na.source,
        category=na.category,
        subcategory=na.subcategory,
        title=na.title,
        description=na.description,
        vendor_severity=na.vendor_severity,
        severity=na.severity,
        score=na.score,
        asset_id=na.asset_id,
        attack_tactic=na.attack_tactic,
        attack_technique=na.attack_technique,
        indicators=na.indicators,
        raw_json=na.raw,
        canonical_hash=na.canonical_hash,
        is_duplicate_of=dup.id if dup else None,
        status="suppressed" if dup else "open",
        redacted=True,
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert