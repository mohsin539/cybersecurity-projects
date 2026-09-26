"""Tier-0 (control plane) classification per Microsoft's enterprise access
model — the core lens a bank's identity program is audited against."""
from __future__ import annotations

from app.graph.model import Node
from app.graph.store import GraphStore, STORE

TIER0_GROUP_PATTERNS = (
    "domain admins", "enterprise admins", "schema admins",
    "administrators", "account operators", "backup operators",
    "server operators", "print operators", "cert publishers",
    "key admins", "enterprise key admins",
)

TIER0_EDGE_KINDS = {"dcsync", "generic_all", "write_dacl", "write_owner",
                    "owns", "all_extended_rights"}


def classify_tiers(store: GraphStore = STORE) -> int:
    """Propagate Tier-0 status: groups by name pattern, members, DCs, domain.

    Returns number of Tier-0 nodes found.
    """
    count = 0
    for n in store.nodes():
        if n.kind == "domain":
            n.tier = 0
            count += 1
            continue
        if n.kind == "ca":
            n.tier = 0  # issuing CA = Tier-0 asset (forged certs ⇒ domain)
            count += 1
            continue
        if n.kind == "group" and any(
                p in n.label.lower() for p in TIER0_GROUP_PATTERNS):
            n.tier = 0
            count += 1
        if n.kind == "computer" and n.props.get("role") == "DC":
            n.tier = 0
            count += 1

    # Members of Tier-0 groups inherit Tier-0 (transitive, one pass suffices
    # for lab-size graphs; run twice for deep nesting).
    for _ in range(2):
        for e in store.edges():
            if e.kind != "member_of":
                continue
            src, dst = store.node(e.source), store.node(e.target)
            if src and dst and dst.tier == 0 and src.tier != 0:
                src.tier = 0
                count += 1
    return count


def tier0_nodes(store: GraphStore = STORE) -> list[Node]:
    return [n for n in store.nodes() if n.tier == 0 and n.kind != "domain"]
