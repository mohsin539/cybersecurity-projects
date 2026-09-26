"""Trust-tier decision engine + lifecycle evaluator + rollback (architecture §2.4).

Tier policy:
  critical : ≥2 vetted feeds or high conf → block immediately
  high     : confidence above configurable floor → block
  median   : single 3rd-party / medium conf → 24h quarantine for approval
  suspected: low conf → store only
"""
from __future__ import annotations

import datetime as _dt
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from .normalize import IOC, dedupe_key, promote_ok


def _now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _parse_ts(ts: str) -> Optional[_dt.datetime]:
    try:
        return _dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


@dataclass
class BlocklistRecord:
    key: str
    value: str
    ioc_type: str
    tier: str                     # critical | high | median | suspected
    sources: List[str] = field(default_factory=list)
    confidence: float = 0.0
    status: str = "active"        # active | quarantined | expiring | retired
    added_at: str = ""
    expires_at: str = "2099-12-31T23:59:59Z"
    approved_by: str = "auto"
    rollback_plan: str = "remove from consumers on retire"

    def to_dict(self) -> dict:
        import dataclasses
        return dataclasses.asdict(self)


class Blocklist:
    """In-memory + JSONL state for the blocklist, tiered + auditable."""

    def __init__(self, state_dir: Path):
        state_dir = Path(state_dir)
        state_dir.mkdir(parents=True, exist_ok=True)
        self.path = state_dir / "blocklist.jsonl"
        self.records: dict[str, BlocklistRecord] = {}
        self._audit = (state_dir / "blocklist_audit.jsonl").open("a", encoding="utf-8")
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    d = json.loads(line)
                    self.records[d["key"]] = BlocklistRecord(**{k: d.get(k) for k in BlocklistRecord.__dataclass_fields__})
                except (json.JSONDecodeError, TypeError, KeyError):
                    continue

    def _log(self, rec: BlocklistRecord, action: str, why: str) -> None:
        self._audit.write(json.dumps({
            "ts": _now_utc(),
            "action": action, "key": rec.key, "value": rec.value,
            "ioc_type": rec.ioc_type, "tier": rec.tier, "why": why,
        }) + "\n")
        self._audit.flush()

    def _persist(self, rec: BlocklistRecord) -> None:
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec.to_dict()) + "\n")

    @staticmethod
    def _changed(a: "BlocklistRecord", b: "BlocklistRecord") -> bool:
        for f in ("value", "ioc_type", "tier", "status", "confidence",
                  "expires_at", "sources", "approved_by", "rollback_plan"):
            if getattr(a, f) != getattr(b, f):
                return True
        return False

    def apply(self, ioc: IOC, feed_cfg: dict, sources: Optional[list] = None) -> Optional[BlocklistRecord]:
        key = dedupe_key(ioc)
        sources = list(sources) if sources else ([ioc.feed_id] if ioc.feed_id else [])
        existing = self.records.get(key)

        existing_sources = existing.sources if isinstance(existing, BlocklistRecord) else []
        merged_sources = list(dict.fromkeys(existing_sources + sources))

        # already enforced and this report adds no new provenance -> no re-trigger
        if (isinstance(existing, BlocklistRecord)
                and existing.tier in ("critical", "high")
                and existing.status in ("active", "expiring")
                and merged_sources == existing.sources):
            return existing

        conf = ioc.confidence
        n_sources = len(merged_sources)
        auto = feed_cfg.get("auto_confidence", 0.7)
        quar = feed_cfg.get("quarantine_confidence", 0.4)

        if n_sources >= 2 or conf >= auto:
            tier = "critical" if n_sources >= 2 else "high"
            status = "active"
        elif conf >= quar:
            tier, status = "median", "quarantined"
        else:
            tier, status = "suspected", "suspected"

        if status == "active" and not promote_ok(ioc, feed_cfg.get("ip_feed_tlp", "white")):
            # guards reject; downgrade to suspected only
            tier, status = "suspected", "suspected"

        rec = BlocklistRecord(
            key=key, value=ioc.normalized, ioc_type=ioc.ioc_type,
            tier=tier, sources=merged_sources,
            confidence=round(conf, 2), status=status,
            added_at=_now_utc(),
            expires_at=ioc.expires_at,
            approved_by=existing.approved_by if isinstance(existing, BlocklistRecord) else "auto",
            rollback_plan=existing.rollback_plan if isinstance(existing, BlocklistRecord)
                else "remove from consumers on retire",
        )

        if isinstance(existing, BlocklistRecord):
            # keep the record's birth-time so TTL/lifecycle math is stable
            rec.added_at = existing.added_at
            if not self._changed(existing, rec):
                return existing  # idempotent: nothing to write

        self.records[key] = rec
        self._persist(rec)
        self._log(rec, "apply", f"{tier}/{status} conf={conf} sources={n_sources}")
        return rec

    def approve(self, key: str, by: str = "gui") -> Optional[BlocklistRecord]:
        """Promote a quarantined/suspected record onto the enforced blocklist."""
        rec = self.records.get(key)
        if not rec or rec.status in ("active", "expiring"):
            return rec
        rec.tier = "high"
        rec.status = "active"
        rec.approved_by = by
        self._persist(rec)
        self._log(rec, "approve", f"approved by {by}")
        return rec

    def drop(self, key: str, by: str = "gui") -> Optional[BlocklistRecord]:
        """Retire a record (auto-rollback: consumer removes it on next sync)."""
        rec = self.records.get(key)
        if not rec or rec.status == "retired":
            return rec
        rec.status = "retired"
        rec.approved_by = by
        self._persist(rec)
        self._log(rec, "retire", f"dropped by {by}")
        return rec

    def evaluate_lifecycle(self, now: str) -> List[dict]:
        """active→expiring (past 75% TTL)→retired (expired/rollback). Returns retired list."""
        retired = []
        for rec in list(self.records.values()):
            if rec.status not in ("active", "expiring"):
                continue
            if rec.expires_at <= now:
                rec.status = "retired"
                self._persist(rec)
                self._log(rec, "retire", "expired")
                retired.append(rec.to_dict())
                continue
            if rec.status == "active" and self._past_ttl_75(rec, now):
                rec.status = "expiring"
                self._persist(rec)
                self._log(rec, "expiring", "past 75% TTL")
        return retired

    @staticmethod
    def _past_ttl_75(rec: BlocklistRecord, now: str) -> bool:
        added = _parse_ts(rec.added_at)
        exp = _parse_ts(rec.expires_at)
        now_dt = _parse_ts(now)
        if not (added and exp and now_dt) or exp <= added:
            return False
        fraction = (now_dt - added) / (exp - added)
        return fraction >= 0.75

    def active_entries(self) -> List[BlocklistRecord]:
        return [r for r in self.records.values() if r.status in ("active", "expiring")]

    def records_sorted(self) -> List[BlocklistRecord]:
        order = {"active": 0, "expiring": 1, "quarantined": 2, "suspected": 3, "retired": 4}
        return sorted(
            self.records.values(),
            key=lambda r: (order.get(r.status, 9), r.value.lower()))

    def close(self) -> None:
        self._audit.close()