"""Policy definitions and validation."""
from __future__ import annotations

from typing import Any

from .model import PLATFORMS, PASS_THRESHOLD, Rule

DEFAULT_POLICY_NAME = "MDM-Lite Baseline Policy"
DEFAULT_POLICY_VERSION = "1.0.0"


def _rules() -> list[dict]:
    return [
        # ---------------- Android ----------------
        {
            "id": "android.os.version",
            "group": "os",
            "platform": "android",
            "label": "Android OS version",
            "description": "Device OS must be at least Android 12 (API 31).",
            "severity": "high",
            "kind": "version_gte",
            "expected": "12.0",
            "remediation": "Update the OS to Android 12 or newer via System > System update.",
        },
        {
            "id": "android.security.root",
            "group": "security",
            "platform": "android",
            "label": "Root / jailbreak detection",
            "description": "Device runtime must not be rooted.",
            "severity": "critical",
            "kind": "boolean",
            "expected": False,
            "remediation": "Unroot the device or re-flash stock firmware before re-enrolling.",
        },
        {
            "id": "android.security.encryption",
            "group": "security",
            "platform": "android",
            "label": "Full-disk / file encryption",
            "description": "Storage encryption must be enabled.",
            "severity": "high",
            "kind": "boolean",
            "expected": True,
            "remediation": "Enable encryption from Settings > Security > Encryption.",
        },
        {
            "id": "android.security.screenlock",
            "group": "security",
            "platform": "android",
            "label": "Screen lock enforced",
            "description": "A lock screen (PIN/pattern/biometric) must be configured.",
            "severity": "medium",
            "kind": "boolean",
            "expected": True,
            "remediation": "Configure a screen lock under Settings > Security > Screen lock.",
        },
        {
            "id": "android.security.unknownsources",
            "group": "security",
            "platform": "android",
            "label": "Unknown sources blocked",
            "description": "Installation from unknown sources must be disabled.",
            "severity": "high",
            "kind": "boolean",
            "expected": False,
            "remediation": "Turn off 'Install unknown apps' for all browsers and file managers.",
        },
        {
            "id": "android.security.playprotect",
            "group": "security",
            "platform": "android",
            "label": "Google Play Protect",
            "description": "Play Protect scanning must be active.",
            "severity": "medium",
            "kind": "boolean",
            "expected": True,
            "remediation": "Re-enable Play Protect under Play Store > Play Protect.",
        },
        {
            "id": "android.apps.required",
            "group": "apps",
            "platform": "android",
            "label": "Required apps installed",
            "description": "All governed applications must be installed on the device.",
            "severity": "critical",
            "kind": "allowlist",
            "expected": ["com.google.android.gms"],
            "remediation": "Install the missing governed application from the corporate catalog.",
        },
        {
            "id": "android.apps.denylist",
            "group": "apps",
            "platform": "android",
            "label": "Forbidden apps absent",
            "description": "Blacklisted applications must not be present on the device.",
            "severity": "high",
            "kind": "denylist",
            "expected": [
                "com.example.roguespy",
                "org.torproject.android",
                "com.mxtech.videoplayer.ad",
            ],
            "remediation": "Uninstall the forbidden application from the device.",
        },
        # ---------------- iOS ----------------
        {
            "id": "ios.os.version",
            "group": "os",
            "platform": "ios",
            "label": "iOS version",
            "description": "Device OS must be at least iOS 15.",
            "severity": "high",
            "kind": "version_gte",
            "expected": "15.0",
            "remediation": "Update the device to iOS 15 or newer via Settings > General > Software Update.",
        },
        {
            "id": "ios.security.jailbreak",
            "group": "security",
            "platform": "ios",
            "label": "Jailbreak detection",
            "description": "Device must not be jailbroken.",
            "severity": "critical",
            "kind": "boolean",
            "expected": False,
            "remediation": "Restore the device to a non-jailbroken state and re-enroll.",
        },
        {
            "id": "ios.security.encryption",
            "group": "security",
            "platform": "ios",
            "label": "Data protection",
            "description": "Full device encryption / Data Protection must be active.",
            "severity": "high",
            "kind": "boolean",
            "expected": True,
            "remediation": "Enable a passcode; Data Protection activates automatically with one.",
        },
        {
            "id": "ios.security.passcode",
            "group": "security",
            "platform": "ios",
            "label": "Passcode enforced",
            "description": "A device passcode must be enabled.",
            "severity": "high",
            "kind": "boolean",
            "expected": True,
            "remediation": "Set a passcode under Settings > Face/Touch ID & Passcode.",
        },
        {
            "id": "ios.security.allowUntrusted",
            "group": "security",
            "platform": "ios",
            "label": "Untrusted certificates blocked",
            "description": "Trusting of untrusted enterprise/root certificates must be disabled.",
            "severity": "medium",
            "kind": "boolean",
            "expected": False,
            "remediation": "Remove untrusted profiles under Settings > General > VPN & Device Management.",
        },
        {
            "id": "ios.apps.denylist",
            "group": "apps",
            "platform": "ios",
            "label": "Forbidden apps absent",
            "description": "Restricted applications must not be installed.",
            "severity": "high",
            "kind": "denylist",
            "expected": ["com.example.roguespy"],
            "remediation": "Delete the forbidden application from the Home Screen.",
        },
    ]


DEFAULT_RULES = [Rule(**r) for r in _rules()]


def default_policy(name: str = DEFAULT_POLICY_NAME, version: str = DEFAULT_POLICY_VERSION) -> dict:
    return {
        "name": name,
        "version": version,
        "threshold": PASS_THRESHOLD,
        "rules": [r.to_dict() for r in DEFAULT_RULES],
        "updatedAt": "",
    }


def validate_device_policy(p: dict) -> dict:
    """Validate/normalize a policy document. Raises ValueError on problems."""
    if not isinstance(p, dict):
        raise ValueError("Policy must be a JSON object.")
    rules = p.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError("Policy requires a non-empty 'rules' array.")
    out = []
    for i, r in enumerate(rules):
        if not isinstance(r, dict):
            raise ValueError(f"rules[{i}] is not an object.")
        rid = r.get("id") or f"rule.{i}"
        platform = r.get("platform", "both")
        if platform not in ("android", "ios", "both"):
            raise ValueError(f"rule '{rid}': platform must be android|ios|both")
        severity = r.get("severity", "medium")
        if severity not in ("low", "medium", "high", "critical"):
            raise ValueError(f"rule '{rid}': invalid severity '{severity}'")
        kind = r.get("kind")
        if kind not in ("version_gte", "boolean", "allowlist", "denylist", "list_contains"):
            raise ValueError(f"rule '{rid}': invalid kind '{kind}'")
        expected = r.get("expected")
        if expected is None:
            raise ValueError(f"rule '{rid}': missing 'expected'")
        out.append(
            Rule(
                id=rid,
                group=r.get("group", "os"),
                platform=platform,
                label=r.get("label", rid),
                description=r.get("description", ""),
                severity=severity,
                kind=kind,
                expected=expected,
                remediation=r.get("remediation", ""),
            ).to_dict()
        )
    return {
        "name": p.get("name", "Custom Policy"),
        "version": p.get("version", "1.0.0"),
        "threshold": float(p.get("threshold", PASS_THRESHOLD)),
        "rules": out,
        "updatedAt": "",
    }


def policy_from_store(raw: dict) -> dict:
    """Load policy from persistent state (already validated at write time)."""
    rules = []
    for r in raw.get("rules", []):
        try:
            rules.append(Rule(**r).to_dict())
        except TypeError:
            continue
    return {
        "name": raw.get("name", DEFAULT_POLICY_NAME),
        "version": raw.get("version", DEFAULT_POLICY_VERSION),
        "threshold": float(raw.get("threshold", PASS_THRESHOLD)),
        "rules": rules,
        "updatedAt": raw.get("updatedAt", ""),
    }