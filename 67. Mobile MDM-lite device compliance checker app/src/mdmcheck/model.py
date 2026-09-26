"""Core domain model: policy rules, devices, telemetry and scan results."""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any


def now_epoch() -> float:
    return time.time()


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def new_id(prefix: str = "dev") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


PLATFORMS = ("android", "ios")
VERDICTS = ("PASS", "FAIL", "NA")
STATUSES = ("PENDING", "COMPLIANT", "NON_COMPLIANT", "ERROR")

SEVERITY_WEIGHT = {"low": 1, "medium": 2, "high": 3, "critical": 4}
PASS_THRESHOLD = 0.80  # weighted pass ratio required for COMPLIANT


@dataclass
class Rule:
    """A single compliance check definition."""

    id: str
    group: str            # os | apps | security | settings
    platform: str         # android | ios | both
    label: str
    description: str
    severity: str         # low | medium | high | critical
    kind: str             # version_gte | boolean | allowlist | denylist | list_contains
    expected: Any
    remediation: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class RuleResult:
    rule_id: str
    group: str
    label: str
    description: str
    severity: str
    verdict: str            # PASS | FAIL | NA
    actual: Any = None
    expected: Any = None
    remediation: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    at: str
    mode: str               # demo | adb | manual
    status: str
    score: float
    pass_count: int
    fail_count: int
    na_count: int
    results: list = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


@dataclass
class Device:
    id: str
    name: str
    platform: str
    model: str = ""
    owner: str = ""
    department: str = ""
    enrolled_at: str = ""
    last_seen: str = ""
    telemetry: dict = field(default_factory=dict)
    scan: ScanResult | None = None
    history: list = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status
        return d

    @property
    def status(self) -> str:
        if self.scan is None:
            return "PENDING"
        return self.scan.status


def device_from_dict(data: dict) -> Device:
    scan = data.get("scan")
    scan_obj = ScanResult(**scan) if scan else None
    return Device(
        id=data.get("id", new_id()),
        name=data.get("name", "Unnamed device"),
        platform=data.get("platform", "android"),
        model=data.get("model", ""),
        owner=data.get("owner", ""),
        department=data.get("department", ""),
        enrolled_at=data.get("enrolled_at", now_iso()),
        last_seen=data.get("last_seen", ""),
        telemetry=data.get("telemetry", {}),
        scan=scan_obj,
        history=data.get("history", []),
    )


def telemetry_sample() -> dict:
    """Shape of the device telemetry payload collected by the agent."""
    return {
        "os": {"version": "13.0", "sdk": 33, "build": "TQ3A.230901.001"},
        "hardware": {"model": "Pixel 7", "brand": "Google", "serial": ""},
        "apps": {"installed": [], "running": []},
        "security": {
            "rooted": False,
            "unknown_sources": False,
            "encryption": True,
            "screen_lock": True,
            "play_protect": True,
            "side_loading": False,
            "verifier_status": "ENABLED",
            "biometric": True,
        },
        "network": {"vpn": False, "geofenced": True},
        "agent": {"version": "1.0.0", "uptime_sec": 0},
    }