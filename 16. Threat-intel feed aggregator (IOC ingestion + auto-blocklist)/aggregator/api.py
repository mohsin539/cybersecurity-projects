"""Reusable pipeline API shared by the CLI (main.py) and the GUI (gui.py).

Only stdlib. Designed to be driven from a single background worker thread.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import List, Optional

from .consumers import make_driver
from .decision import Blocklist, BlocklistRecord
from .ingest import ingest_csv, ingest_fixture_json, ingest_honeypot_event
from .normalize import IOC

DEFAULT_CONFIG = "config/feeds.json"
DEFAULT_STATE = "data"


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def load_config(path: Optional[Path] = None) -> dict:
    p = Path(path) if path else Path(DEFAULT_CONFIG)
    if not p.exists():
        return {"auto_confidence": 0.7, "quarantine_confidence": 0.4,
                "consumer": "json", "consumer_dest": "", "feeds": {}}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    data.setdefault("feeds", {})
    data.setdefault("auto_confidence", 0.7)
    data.setdefault("quarantine_confidence", 0.4)
    data.setdefault("consumer", "json")
    data.setdefault("consumer_dest", "")
    return data


def save_config(config: dict, path: Optional[Path] = None) -> Path:
    p = Path(path) if path else Path(DEFAULT_CONFIG)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return p


def feed_settings(config: dict, feed_id: Optional[str]) -> dict:
    """Per-feed policy merged over global defaults.

    Fixes the old bug where main.run() looked up config.get("auto_confidence")
    (a float) and dropped the per-feed overrides entirely.
    """
    merged = {
        "auto_confidence": config.get("auto_confidence", 0.7),
        "quarantine_confidence": config.get("quarantine_confidence", 0.4),
        "ip_feed_tlp": "white",
        "consumer": config.get("consumer", "json"),
    }
    per = {}
    if feed_id:
        feeds = config.get("feeds", {})
        per = feeds.get(feed_id, {}) if isinstance(feeds, dict) else {}
    merged.update(per if isinstance(per, dict) else {})
    return merged


def consumer_dest(config: dict, state_dir: Path) -> str:
    override = config.get("consumer_dest")
    if override:
        return str(override)
    kind = config.get("consumer", "json")
    return str(Path(state_dir) / ("blocklist.json" if kind != "pf" else "blocklist.table"))


def ioc_from_dict(d: dict) -> IOC:
    return IOC(
        value=str(d.get("value", "")).strip(),
        ioc_type=d.get("ioc_type", "ipv4"),
        confidence=float(d.get("confidence", 0.5)),
        tlp=d.get("tlp", "white"),
        expires_at=d.get("expires_at", "2099-12-31T23:59:59Z"),
        tags=d.get("tags", []),
        feed_id=d.get("feed_id", "manual"),
        first_seen=d.get("first_seen", ""),
        sources=d.get("sources", []),
    )


def run_pipeline(config: dict, state_dir: Path,
                 iocs: Optional[List[IOC]] = None,
                 fixture: Optional[Path] = None,
                 honeypot_events: Optional[List[dict]] = None,
                 sync: bool = True) -> dict:
    """Ingest → normalize → tier → consumer sync → lifecycle. One-shot pipeline.

    `sync=False` only mutates the blocklist store (no consumer release write).
    """
    state_dir = Path(state_dir)
    bl = Blocklist(state_dir)

    to_apply: List[IOC] = list(iocs or [])
    if fixture and Path(fixture).exists():
        to_apply += ingest_fixture_json(Path(fixture))
    for ev in honeypot_events or []:
        to_apply += ingest_honeypot_event(ev)

    applied: List[BlocklistRecord] = []
    for ioc in to_apply:
        cfg = feed_settings(config, ioc.feed_id)
        rec = bl.apply(ioc, cfg)
        if rec:
            applied.append(rec)

    pushed = removed = 0
    driver_name = "-"
    dest = "-"
    consumer_ok = True
    if sync:
        dest = consumer_dest(config, state_dir)
        driver = make_driver(config.get("consumer", "json"), dest)
        result = driver.sync(bl.active_entries())
        if hasattr(driver, "finalize"):
            driver.finalize()
        driver_name = driver.name
        pushed, removed, consumer_ok = result.pushed, result.removed, result.ok

    retired = bl.evaluate_lifecycle(now_utc())
    bl.close()

    return {
        "config": config,
        "state_dir": str(state_dir),
        "ingested": [r.value for r in to_apply],
        "applied": [r.to_dict() for r in applied],
        "consumer": driver_name,
        "consumer_dest": dest,
        "pushed": pushed,
        "removed": removed,
        "consumer_ok": consumer_ok,
        "retired": retired,
        "synced": sync,
    }


def sync_consumer(config: dict, state_dir: Path) -> dict:
    """Run consumer diff-sync only (no ingest)."""
    state_dir = Path(state_dir)
    bl = Blocklist(state_dir)
    dest = consumer_dest(config, state_dir)
    driver = make_driver(config.get("consumer", "json"), dest)
    result = driver.sync(bl.active_entries())
    if hasattr(driver, "finalize"):
        driver.finalize()
    bl.close()
    return {"consumer": driver.name, "dest": dest, "pushed": result.pushed,
            "removed": result.removed, "ok": result.ok}


def list_records(state_dir: Path) -> List[dict]:
    bl = Blocklist(state_dir)
    out = [r.to_dict() for r in bl.records_sorted()]
    bl.close()
    return out


def approve_record(state_dir: Path, key: str, by: str = "gui") -> Optional[dict]:
    bl = Blocklist(state_dir)
    rec = bl.approve(key, by=by)
    out = rec.to_dict() if rec else None
    bl.close()
    return out


def drop_record(state_dir: Path, key: str, by: str = "gui") -> Optional[dict]:
    bl = Blocklist(state_dir)
    rec = bl.drop(key, by=by)
    out = rec.to_dict() if rec else None
    bl.close()
    return out


def retire_expired(state_dir: Path) -> List[dict]:
    bl = Blocklist(state_dir)
    out = bl.evaluate_lifecycle(now_utc())
    bl.close()
    return out


def tail_audit(state_dir: Path, n: int = 200) -> List[dict]:
    p = Path(state_dir) / "blocklist_audit.jsonl"
    if not p.exists():
        return []
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    out = []
    for line in lines[-n:]:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def tail_release(config: dict, state_dir: Path, n: int = 500) -> str:
    """Human-readable consumer release file (for the GUI viewer)."""
    dest = Path(consumer_dest(config, state_dir))
    if not dest.exists():
        return "(release file not generated yet)"
    text = dest.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    return "\n".join(lines[-n:])


def ingest_from_file(path: Path) -> List[IOC]:
    suffix = Path(path).suffix.lower()
    if suffix == ".csv":
        return ingest_csv(path)
    raw = path.read_text(encoding="utf-8", errors="replace").strip()
    if raw.startswith("[") or raw.startswith("{"):
        # fixture list OR a single honeypot-style event
        data = json.loads(raw)
        if isinstance(data, list):
            return ingest_fixture_json(path)
        if isinstance(data, dict) and data.get("source") == "honeypot":
            return ingest_honeypot_event(data)
    return ingest_fixture_json(path)