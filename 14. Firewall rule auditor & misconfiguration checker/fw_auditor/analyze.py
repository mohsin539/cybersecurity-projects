"""Analysis probes (pure functions over rule lists) — architecture.md §2.3.

Each probe returns a list of Findings. Findings are dicts with rule ids,
kind, severity and evidence. No I/O inside probes.
"""
from __future__ import annotations

from typing import List

from .model import Rule, traffic_covered, traffic_identical, traffic_superset

ADMIN_PORTS = {22, 23, 3389, 5900, 5901, 8080, 8443, 7001, 7002, 9090}


def _is_admin_port_range(ports) -> bool:
    lo, hi = ports
    if ports == (-1, -1):
        return True
    return any(lo <= p <= hi for p in ADMIN_PORTS)


def probe_shadowed(rules: List[Rule]) -> List[dict]:
    """Earlier rule matches a superset of a later rule's traffic.

    - earlier allow covering later deny  => deny unreachable, security gap (high)
    - earlier deny covering later allow  => allow unreachable, loss of function (medium)
    """
    findings = []
    for j, later in enumerate(rules):
        for earlier in rules[:j]:
            if not traffic_covered(inner=later, outer=earlier):
                continue
            if earlier.action == "allow" and later.action == "deny":
                findings.append({
                    "kind": "shadowed",
                    "severity": "high",
                    "rule_id": later.id,
                    "earlier_id": earlier.id,
                    "device": later.device,
                    "evidence": f"rule {later.id} unreachable deny; allow {earlier.id} superset matches first",
                })
            elif earlier.action == "deny" and later.action == "allow":
                findings.append({
                    "kind": "shadowed",
                    "severity": "medium",
                    "rule_id": later.id,
                    "earlier_id": earlier.id,
                    "device": later.device,
                    "evidence": f"rule {later.id} unreachable allow; deny {earlier.id} fires first",
                })
    return findings


def probe_redundant(rules: List[Rule]) -> List[dict]:
    """Identical or subset rule with no effect (dead weight). Symmetric pairs
    reported once (a.id < b.id)."""
    findings = []
    for i, a in enumerate(rules):
        for b in rules:
            if a.id == b.id or a.id > b.id:
                continue
            if traffic_identical(a, b):
                findings.append({
                    "kind": "redundant",
                    "severity": "medium",
                    "rule_id": a.id,
                    "twin_id": b.id,
                    "device": a.device,
                    "evidence": f"rule {a.id} duplicates {b.id}",
                })
    return findings


def probe_broad(rules: List[Rule]) -> List[dict]:
    """0.0.0.0/0 allow to admin ports (any-port rules flagged by probe_any_any)."""
    findings = []
    for r in rules:
        if r.action != "allow":
            continue
        if r.port_any():
            continue  # fully unrestricted caught by probe_any_any
        if r.src_net() is None and _is_admin_port_range(r.ports):
            findings.append({
                "kind": "broad_exposure",
                "severity": "critical",
                "rule_id": r.id,
                "device": r.device,
                "evidence": f"rule {r.id} allows any source to admin port {r.ports}",
            })
    return findings


def probe_default_policy(rules: List[Rule]) -> List[dict]:
    """Policy smell: default-allow posture (explicit deny on port, no catch-all)."""
    findings = []
    denies = [r for r in rules if r.action == "deny"]
    if not denies:
        findings.append({
            "kind": "default_policy",
            "severity": "high",
            "rule_id": "policy-root",
            "device": rules[0].device if rules else "?",
            "evidence": "No explicit deny rules; default-allow posture assumed",
        })
    return findings


def probe_any_any(rules: List[Rule]) -> List[dict]:
    """Rules matching any source, any destination, any port = fully unrestricted."""
    return [{
        "kind": "any_any",
        "severity": "high",
        "rule_id": r.id,
        "device": r.device,
        "evidence": f"rule {r.id} is any->any (fully unrestricted)",
    } for r in rules if r.src_net() is None and r.dst_net() is None and r.port_any()]


def probe_logging(rules: List[Rule]) -> List[dict]:
    return [{
        "kind": "logging_disabled",
        "severity": "medium",
        "rule_id": r.id,
        "device": r.device,
        "evidence": f"allow rule {r.id} has log=false",
    } for r in rules if r.action == "allow" and not r.log]


PROBES = [probe_shadowed, probe_broad, probe_default_policy, probe_any_any, probe_logging, probe_redundant]