"""What-if remediation simulation.

Simulates fixing one or more findings by hiding the corresponding edges
(and, for flag-type fixes, substituting safe props) in a **filtered view**
over the live graph — the store itself is never mutated. Re-running the
tier classifier, blast radius, and findings scan on the view quantifies the
exact risk reduction of each remediation, producing a before/after delta for
GRC prioritization.
"""
from __future__ import annotations

from copy import copy
from dataclasses import dataclass, field
from typing import Any

from app.analysis import engine, tiers as tier_mod
from app.findings import rules as findings_engine
from app.graph.store import GraphStore


class FilteredStore(GraphStore):
    """Read-only view of a GraphStore with selected edges hidden and node
    props overridden. Delegates everything else to the base store."""

    def __init__(self, base: GraphStore,
                 removed_edges: set[tuple[str, str, str]],
                 prop_overrides: dict[str, dict[str, Any]] | None = None,
                 tier_overrides: dict[str, int] | None = None) -> None:
        self._base = base
        self._removed = removed_edges
        self._props = prop_overrides or {}
        self._tiers = tier_overrides or {}

    # -- mutation ops intentionally unsupported ---------------------------
    def add_node(self, node) -> None:
        raise NotImplementedError("FilteredStore is read-only")

    def add_edge(self, edge) -> None:
        raise NotImplementedError("FilteredStore is read-only")

    # -- queries -----------------------------------------------------------
    def node(self, node_id: str):
        n = self._base.node(node_id)
        if n is None:
            return None
        props = {**n.props, **self._props.get(node_id, {})}
        out = copy(n)
        out.props = props
        if node_id in self._tiers:
            out.tier = self._tiers[node_id]
        return out

    def nodes(self) -> list:
        return [self.node(n.id) for n in self._base.nodes()]

    def edges(self) -> list:
        return [e for e in self._base.edges()
                if (e.source, e.target, e.kind) not in self._removed]

    def out_edges(self, node_id: str) -> list:
        return [e for e in self._base.out_edges(node_id)
                if (e.source, e.target, e.kind) not in self._removed]

    def in_edges(self, node_id: str) -> list:
        return [e for e in self._base.in_edges(node_id)
                if (e.source, e.target, e.kind) not in self._removed]

    def stats(self) -> dict[str, Any]:
        base = self._base.stats()
        shown = len(self.edges())
        return {**base, "edges_total": shown}


# ---------------------------------------------------------------------------
# Mitigation map: finding id -> edge kinds + prop fixes to simulate.
# props_fix entries override node props when the finding is remediated.
MITIGATIONS: dict[str, dict[str, Any]] = {
    "F-DCSYNC-001": {"edge_kinds": ["dcsync"]},
    "F-KRB-001": {"edge_kinds": [],
                  "props_fix": {"spn": False}},          # gMSA migration
    "F-ASREP-001": {"edge_kinds": [],
                    "props_fix": {"no_preauth": False}},  # re-enable pre-auth
    "F-DELEG-001": {"edge_kinds": ["allowed_to_delegate"],
                    "props_fix": {"unconstrained": False}},
    "F-TIER-001": {"edge_kinds": ["force_change_pw"]},
    "F-RDP-001": {"edge_kinds": ["rdp_on"]},
    "F-GPP-001": {"edge_kinds": [], "props_fix": {"gpp_password": False}},
    "F-SESS-001": {"edge_kinds": ["has_session"]},
    "F-NEST-001": {"edge_kinds": ["member_of"]},
    "F-PWD-001": {"edge_kinds": []},
    # ADCS
    "F-ESC1-001": {"edge_kinds": ["enroll"]},
    "F-ESC2-001": {"edge_kinds": ["enroll"]},
    "F-ESC3-001": {"edge_kinds": ["enroll", "manage_certificates"]},
    "F-ESC4-001": {"edge_kinds": ["generic_write", "generic_all",
                                  "write_dacl", "write_owner",
                                  "all_extended_rights"]},
    "F-ESC5-001": {"edge_kinds": ["manage_ca", "manage_certificates",
                                  "generic_all"]},
    "F-ESC7-001": {"edge_kinds": ["manage_ca", "manage_certificates"]},
    "F-ESC9-001": {"edge_kinds": ["autoenroll"]},
    # Delegation
    "F-DELEG-002": {"edge_kinds": ["allowed_to_delegate"]},
    "F-DELEG-003": {"edge_kinds": ["allowed_to_delegate"]},
    "F-DELEG-004": {"edge_kinds": ["generic_write", "generic_all",
                                   "write_dacl", "write_owner",
                                   "all_extended_rights"]},
}


@dataclass(slots=True)
class WhatIfResult:
    finding_id: str
    title: str
    severity: str
    before: dict[str, Any]
    after: dict[str, Any]
    delta: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id, "title": self.title,
            "severity": self.severity,
            "before": self.before, "after": self.after, "delta": self.delta,
        }


def _metrics(store: GraphStore) -> dict[str, Any]:
    """Recompute the headline metrics on (a view of) the graph."""
    tier_mod.classify_tiers(store)
    summary = engine.domain_summary(store)
    findings = findings_engine.run_all_rules(store)
    fs = findings_engine.findings_summary(findings)
    tier0_exposed = len(summary["tier0_exposure"])
    return {
        # Uncapped raw score: a one-critical fix must register in the delta.
        "risk_index": fs["risk_raw"],
        "findings_total": fs["total"],
        "by_severity": fs["by_severity"],
        "tier0_exposed_principals": tier0_exposed,
        "tier_distribution": summary["tier_distribution"],
    }


def _plan_for(finding_id: str) -> dict[str, Any]:
    return MITIGATIONS.get(finding_id, {"edge_kinds": []})


def simulate_single(base: GraphStore, finding_id: str) -> WhatIfResult | None:
    """Simulate fixing exactly one finding; None if unknown id or no effect
    data (finding not currently present)."""
    rule = next((r for r in findings_engine.RULES if r.id == finding_id), None)
    if rule is None:
        return None
    plan = _plan_for(finding_id)
    before = _metrics(base)

    # Identify concrete edges to hide by kind (scoped, not global, for ACL
    # kinds where a global hide would over-state the effect).
    target_edges = {
        (e.source, e.target, e.kind) for e in base.edges()
        if e.kind in plan["edge_kinds"]
    }
    # Flag-type fixes: override props on every node carrying the flag.
    overrides: dict[str, dict[str, Any]] = {}
    affected_nodes: list[str] = []
    for n in base.nodes():
        patch = {k: v for k, v in plan.get("props_fix", {}).items()
                 if k in n.props}
        if patch:
            overrides[n.id] = patch
            affected_nodes.append(n.id)

    sim = FilteredStore(base, target_edges, overrides)
    after = _metrics(sim)
    delta = {
        "risk_index": round(after["risk_index"] - before["risk_index"], 1),
        "findings_total": after["findings_total"] - before["findings_total"],
        "tier0_exposed_principals":
            after["tier0_exposed_principals"] - before["tier0_exposed_principals"],
        "critical_removed": before["by_severity"].get("critical", 0)
        - after["by_severity"].get("critical", 0),
        "high_removed": before["by_severity"].get("high", 0)
        - after["by_severity"].get("high", 0),
        "edges_hidden": len(target_edges),
        "nodes_patched": len(overrides),
    }
    return WhatIfResult(rule.id, rule.title, rule.severity, before, after,
                        delta)


def simulate_batch(base: GraphStore,
                   finding_ids: list[str]) -> dict[str, Any]:
    """Simulate a remediation roadmap: cumulative effect in the given order
    plus per-finding single-shot deltas."""
    before = _metrics(base)
    cumulative_edges: set[tuple[str, str, str]] = set()
    cumulative_props: dict[str, dict[str, Any]] = {}
    steps: list[dict[str, Any]] = []
    singles: list[WhatIfResult] = []

    for fid in finding_ids:
        single = simulate_single(base, fid)
        if single:
            singles.append(single)
        plan = _plan_for(fid)
        for e in base.edges():
            if e.kind in plan["edge_kinds"]:
                cumulative_edges.add((e.source, e.target, e.kind))
        for n in base.nodes():
            patch = {k: v for k, v in plan.get("props_fix", {}).items()
                     if k in n.props}
            if patch:
                cumulative_props.setdefault(n.id, {}).update(patch)
        sim = FilteredStore(base, cumulative_edges, cumulative_props)
        after = _metrics(sim)
        steps.append({
            "finding_id": fid,
            "risk_index": after["risk_index"],
            "findings_total": after["findings_total"],
            "tier0_exposed": after["tier0_exposed_principals"],
        })

    final = steps[-1] if steps else before
    return {
        "before": before,
        "roadmap_steps": steps,
        "final": final,
        "total_delta": {
            "risk_index": round((final["risk_index"] if steps else 0)
                                - before["risk_index"], 1),
            "findings_total": (final["findings_total"] if steps else 0)
            - before["findings_total"],
        },
        "singles": [s.to_dict() for s in singles],
    }


def available_mitigations() -> dict[str, str]:
    """Map of finding id -> short mitigation description for the UI."""
    rule_titles = {r.id: r.title for r in findings_engine.RULES}
    return {fid: rule_titles.get(fid, fid)
            for fid in MITIGATIONS if fid in rule_titles}
