"""Persistence layer for the local-first state store.

State is kept in a single JSON file (`state.json`) with atomic writes and
corruption-safe recovery (the corrupted copy is quarantined to `state.json.corrupt-N`).
"""
from __future__ import annotations

import json
import os
import shutil
import threading
import time
from pathlib import Path
from typing import Any

from .model import Device, ScanResult, device_from_dict, new_id, now_iso
from .policy import default_policy, policy_from_store

SCHEMA_VERSION = "1.0.0"


class StateStore:
    def __init__(self, path: str | Path | None = None):
        self._lock = threading.RLock()
        self.path = Path(path) if path else default_store_path()
        self._data: dict = {}
        self._load()

    # ------------------------------------------------------------------ load/save
    def _load(self) -> None:
        raw: dict | None = None
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception as e:  # noqa: BLE001
                self._quarantine = f"{self.path}.corrupt-{int(time.time())}"
                try:
                    shutil.copy2(self.path, self._quarantine)
                except OSError:
                    self._quarantine = ""
                self.log("critical", "state_load_corrupt", f"State file corrupt ({e}); quarantined and reset.")
                raw = None
        if not raw:
            self._data = self._fresh()
            self.save()
        else:
            self._data = self._normalize(raw)

    def _fresh(self) -> dict:
        return {
            "schemaVersion": SCHEMA_VERSION,
            "meta": {
                "createdAt": now_iso(),
                "updatedAt": now_iso(),
                "instanceId": new_id("inst"),
                "totalScans": 0,
            },
            "policy": default_policy(),
            "devices": [],
            "securityLog": [],
            "settings": {"alertOnNonCompliant": True, "maxLogEntries": 500},
        }

    def _normalize(self, raw: dict) -> dict:
        devices = []
        for d in raw.get("devices", []):
            try:
                devices.append(device_from_dict(d).to_dict())
            except Exception:  # noqa: BLE001
                continue
        meta = dict(raw.get("meta", {}))
        meta.setdefault("createdAt", now_iso())
        meta.setdefault("instanceId", new_id("inst"))
        meta.setdefault("totalScans", 0)
        meta["updatedAt"] = now_iso()
        return {
            "schemaVersion": raw.get("schemaVersion", SCHEMA_VERSION),
            "meta": meta,
            "policy": policy_from_store(raw.get("policy", default_policy())),
            "devices": devices,
            "securityLog": raw.get("securityLog", [])[-500:],
            "settings": dict(raw.get("settings", {"alertOnNonCompliant": True, "maxLogEntries": 500})),
        }

    def save(self) -> None:
        with self._lock:
            self._data["meta"]["updatedAt"] = now_iso()
            tmp = self.path.with_suffix(".tmp")
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(self._data, indent=2, default=str), encoding="utf-8")
            if self.path.exists():
                self.path.unlink()
            os.replace(tmp, self.path)

    # ------------------------------------------------------------------ accessors
    @staticmethod
    def _with_status(device: dict) -> dict:
        """Return a copy of a device dict including the derived status field."""
        sc = device.get("scan")
        out = json.loads(json.dumps(device, default=str))
        out["status"] = sc.get("status", "PENDING") if sc else "PENDING"
        return out

    def snapshot(self) -> dict:
        with self._lock:
            snap = json.loads(json.dumps(self._data, default=str))
            snap["devices"] = [self._with_status(d) for d in snap.get("devices", [])]
            return snap

    def policy(self) -> dict:
        return self._data["policy"]

    def set_policy(self, policy: dict, changed_by: str = "admin") -> dict:
        with self._lock:
            from .policy import validate_device_policy

            validated = validate_device_policy(policy)
            validated["updatedAt"] = now_iso()
            self._data["policy"] = validated
            self.log("info", "policy_update", f"Policy '{changed_by}' updated to v{validated['version']} ({len(validated['rules'])} rules).")
            self._touch(scan_all=True)
            self.save()
            return self._data["policy"]

    def reset_policy(self) -> dict:
        with self._lock:
            self._data["policy"] = default_policy()
            self._data["policy"]["updatedAt"] = now_iso()
            self.log("warn", "policy_reset", "Policy reset to MDM-Lite Baseline.")
            self._touch(scan_all=True)
            self.save()
            return self._data["policy"]

    def devices(self) -> list[dict]:
        with self._lock:
            return [self._with_status(d) for d in self._data["devices"]]

    def device(self, device_id: str) -> Device | None:
        for d in self._data["devices"]:
            if d["id"] == device_id:
                return device_from_dict(d)
        return None

    def add_device(self, payload: dict) -> Device:
        with self._lock:
            platform = payload.get("platform", "android")
            dev = Device(
                id=payload.get("id") or new_id(),
                name=payload.get("name", "Unnamed device"),
                platform=platform if platform in ("android", "ios") else "android",
                model=payload.get("model", ""),
                owner=payload.get("owner", ""),
                department=payload.get("department", ""),
                enrolled_at=now_iso(),
                last_seen="",
            )
            self._data["devices"].append(dev.to_dict())
            self.log("info", "device_enroll", f"Enrolled {dev.name} ({dev.platform}) as {dev.id}.", device_id=dev.id)
            self.save()
            return dev

    def remove_device(self, device_id: str) -> bool:
        with self._lock:
            before = len(self._data["devices"])
            self._data["devices"] = [d for d in self._data["devices"] if d["id"] != device_id]
            removed = len(self._data["devices"]) != before
            if removed:
                self.log("warn", "device_remove", f"Removed device {device_id}.", device_id=device_id)
                self.save()
            return removed

    def apply_scan(self, device_id: str, telemetry: dict, result: ScanResult, mode: str) -> Device | None:
        with self._lock:
            result.mode = mode
            for d in self._data["devices"]:
                if d["id"] == device_id:
                    prev = d.get("scan")
                    if prev:
                        d.setdefault("history", []).append(prev)
                        d["history"] = d["history"][-20:]
                    d["telemetry"] = telemetry
                    d["scan"] = result.to_dict()
                    d["last_seen"] = now_iso()
                    self._data["meta"]["totalScans"] = self._data["meta"].get("totalScans", 0) + 1
                    self.log(
                        "info",
                        "device_scan",
                        f"{d['name']} scan -> {result.status} (score {result.score:.1f}%, {result.pass_count} pass / {result.fail_count} fail).",
                        device_id=device_id,
                    )
                    self.save()
                    return device_from_dict(d)
        return None

    def set_telemetry(self, device_id: str, telemetry: dict) -> Device | None:
        with self._lock:
            for d in self._data["devices"]:
                if d["id"] == device_id:
                    d["telemetry"] = telemetry
                    d["scan"] = None
                    self.save()
                    return device_from_dict(d)
        return None

    def logs(self, limit: int = 100) -> list[dict]:
        return self._data["securityLog"][-limit:][::-1]

    def log(self, level: str, event: str, message: str, device_id: str = "") -> None:
        with self._lock:
            entry = {"at": now_iso(), "level": level, "event": event, "message": message, "deviceId": device_id}
            self._data["securityLog"].append(entry)
            max_entries = int(self._data.get("settings", {}).get("maxLogEntries", 500))
            self._data["securityLog"] = self._data["securityLog"][-max_entries:]

    def _touch(self, scan_all: bool = False) -> None:
        # identity: policy changed invalidates previous scan statuses for truthfulness
        if scan_all:
            for d in self._data["devices"]:
                d["scan"] = None

    def export_report(self, device_id: str = "") -> dict:
        """Aggregate current state for reporting (does not mutate)."""
        with self._lock:
            data = json.loads(json.dumps(self._data, default=str))
            if device_id:
                data["devices"] = [d for d in data.get("devices", []) if d.get("id") == device_id]
            data["devices"] = [self._with_status(d) for d in data.get("devices", [])]
            return data

    def clear_logs(self) -> None:
        with self._lock:
            self._data["securityLog"] = []
            self.save()


def default_store_path() -> Path:
    """Portable default: store state next to the executable / source tree."""
    if getattr(__import__("sys"), "frozen", False):
        base = Path(getattr(__import__("sys"), "_MEIPASS", "."))
        exe = __import__("sys").executable
        return Path(exe).with_name("mdm-lite-state.json")
    return Path(__file__).resolve().parent.parent.parent / "mdm-lite-state.json"