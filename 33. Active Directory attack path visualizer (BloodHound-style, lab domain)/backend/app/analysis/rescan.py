"""Scheduled re-scan with baseline diffing.

Runs the findings scan periodically (or on demand), diffs the result against
the last persisted baseline, and records the delta — so an analyst (or the
portable exe) sees exactly which findings appeared, disappeared, or changed
since the previous run. The baseline is a JSON file, so diffs survive exe
restarts even though the in-memory graph does not.

Data dir resolution:
- SG_DATA_DIR env (tests / explicit deployments)
- frozen exe: %LOCALAPPDATA%/SentinelGraph (set via SG_FROZEN_EXE by run.py)
- dev: ./data under the working directory
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import Any

from app.core import audit
from app.findings import rules as findings_engine
from app.graph.store import GraphStore, STORE

_LOCK = threading.RLock()
_STOP = threading.Event()
_THREAD: threading.Thread | None = None
_HISTORY_LIMIT = 20

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ------------------------------------------------------------- persistence --
def _data_dir() -> Path:
    d = os.environ.get("SG_DATA_DIR")
    if d:
        p = Path(d)
    elif getattr(sys, "frozen", False):
        # Portable exe: persist the baseline next to the user's profile so
        # diffs survive restarts without any configuration.
        base = os.environ.get("LOCALAPPDATA") or str(Path.home())
        p = Path(base) / "SentinelGraph"
    else:
        p = Path("data")
    p.mkdir(parents=True, exist_ok=True)
    return p


def _baseline_path() -> Path:
    return _data_dir() / "scan-baseline.json"


def _load_baseline() -> dict[str, Any]:
    try:
        with open(_baseline_path(), encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict) and isinstance(data.get("findings"), dict):
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return {"version": 1, "saved_at": None, "findings": {}, "history": []}


def _save_baseline(findings: dict[str, Any], history: list[dict[str, Any]]) -> str:
    saved_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    payload = {"version": 1, "saved_at": saved_at,
               "findings": findings, "history": history}
    tmp = _baseline_path().with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=1)
    os.replace(tmp, _baseline_path())  # atomic on same filesystem
    return saved_at


# ---------------------------------------------------------------- snapshot --
def snapshot_findings(store: GraphStore) -> dict[str, dict[str, Any]]:
    """Canonical per-finding snapshot keyed by rule id, with a stable
    content fingerprint for change detection."""
    out: dict[str, dict[str, Any]] = {}
    for f in findings_engine.run_all_rules(store):
        affected_ids = sorted(a.get("id", "") for a in f.affected)
        payload = {
            "id": f.id, "title": f.title, "severity": f.severity,
            "category": f.category, "mitre": f.mitre,
            "affected_ids": affected_ids,
        }
        fp = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]
        out[f.id] = {**payload, "affected_count": len(affected_ids),
                     "fingerprint": fp}
    return out


def _sev(f: dict[str, Any]) -> int:
    return _SEV_ORDER.get(f.get("severity", "info"), 9)


def diff_snapshots(old: dict[str, Any],
                   new: dict[str, Any]) -> dict[str, Any]:
    """Diff two snapshots keyed by finding id; fingerprint = content change."""
    old_ids, new_ids = set(old), set(new)
    added = sorted((new[i] for i in new_ids - old_ids), key=_sev)
    resolved = sorted((old[i] for i in old_ids - new_ids), key=_sev)
    changed = [
        {"finding_id": i,
         "old_severity": old[i]["severity"],
         "new_severity": new[i]["severity"],
         "old_affected": old[i]["affected_count"],
         "new_affected": new[i]["affected_count"]}
        for i in sorted(old_ids & new_ids)
        if old[i]["fingerprint"] != new[i]["fingerprint"]
    ]
    return {
        "new": added,
        "resolved": resolved,
        "changed": changed,
        "counts": {
            "new": len(added), "resolved": len(resolved),
            "changed": len(changed),
            "unchanged": len(new) - len(added) - len(changed),
            "total": len(new),
        },
        "critical_new": sum(1 for f in added if f["severity"] == "critical"),
    }


# ------------------------------------------------------------------ runs ----
def run_scan_now(store: GraphStore = STORE, *, trigger: str = "manual",
                 actor: str = "system") -> dict[str, Any]:
    """Scan, diff against baseline, persist new baseline. Lock-protected so
    manual and scheduled runs never interleave."""
    with _LOCK:
        baseline = _load_baseline()
        new_snap = snapshot_findings(store)
        diff = diff_snapshots(baseline.get("findings", {}), new_snap)
        history = list(baseline.get("history", []))
        history.insert(0, {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "trigger": trigger, "actor": actor,
            **diff["counts"], "critical_new": diff["critical_new"],
        })
        saved_at = _save_baseline(new_snap, history[:_HISTORY_LIMIT])
        audit.record("rescan.run", actor=actor, trigger=trigger,
                     outcome="success",
                     new=diff["counts"]["new"],
                     resolved=diff["counts"]["resolved"],
                     changed=diff["counts"]["changed"],
                     severity="alert" if diff["critical_new"] else "info")
        return {"ran_at": saved_at, "trigger": trigger, **diff}


def status(interval_minutes: int) -> dict[str, Any]:
    with _LOCK:
        baseline = _load_baseline()
        return {
            "enabled": interval_minutes > 0,
            "interval_minutes": interval_minutes,
            "last_run": baseline.get("saved_at"),
            "baseline_findings": len(baseline.get("findings", {})),
            "history": baseline.get("history", [])[:10],
        }


def reset_baseline() -> None:
    with _LOCK:
        try:
            os.unlink(_baseline_path())
        except FileNotFoundError:
            pass
        audit.record("rescan.baseline_reset")


# -------------------------------------------------------------- scheduler ---
def start_scheduler(interval_minutes: int,
                    store: GraphStore = STORE) -> None:
    """Start the periodic re-scan daemon (no-op when disabled/running)."""
    global _THREAD
    if interval_minutes <= 0:
        return
    if _THREAD and _THREAD.is_alive():
        return
    _STOP.clear()

    def _loop() -> None:
        while not _STOP.wait(interval_minutes * 60):
            try:
                run_scan_now(store, trigger="scheduled", actor="scheduler")
            except Exception:
                audit.record("rescan.error", severity="alert",
                             outcome="failure")

    _THREAD = threading.Thread(target=_loop, daemon=True, name="sg-rescan")
    _THREAD.start()
    audit.record("rescan.scheduler_started", interval_minutes=interval_minutes)


def stop_scheduler() -> None:
    _STOP.set()
