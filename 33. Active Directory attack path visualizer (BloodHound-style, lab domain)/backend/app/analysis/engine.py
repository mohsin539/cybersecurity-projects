"""Attack-path analysis engine.

BFS over the directed AD privilege graph with risk-weighted scoring,
blast-radius computation, Tier-0 shortest paths, and choke-point (champion/
upstream) analysis — the analytics a bank's red/purple-team and identity
governance programs need. Storage-agnostic (works over GraphStore).
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any

from app.graph.model import EDGE_WEIGHTS, Node
from app.graph.store import GraphStore, STORE

# Edge kinds that represent "can act ON" (vs descriptive links).
PRIVILEGE_EDGES = {
    k for k, w in EDGE_WEIGHTS.items() if w > 0
} | {"has_session"}  # session edges chain paths in BloodHound semantics


@dataclass(slots=True)
class AttackPath:
    nodes: list[str]
    edges: list[dict[str, str]]
    hops: int
    risk: float                 # 0..100
    target_tier0: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": self.nodes,
            "edges": self.edges,
            "hops": self.hops,
            "risk": round(self.risk, 1),
            "target_tier0": self.target_tier0,
        }


@dataclass
class BlastRadius:
    node_id: str
    reachable_tier0: bool
    tier0_count: int
    total_reachable: int
    risk_score: float           # 0..100
    frontier: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "reachable_tier0": self.reachable_tier0,
            "tier0_count": self.tier0_count,
            "total_reachable": self.total_reachable,
            "risk_score": round(self.risk_score, 1),
            "frontier": self.frontier,
        }


def _edge_weight(edge_kind: str, store: GraphStore) -> float:
    if edge_kind == "member_of":
        return 0.0  # handled via target tier at scoring time
    if edge_kind == "has_session":
        return 0.4
    return EDGE_WEIGHTS.get(edge_kind, 0.1)


def _score_path(store: GraphStore, nodes: list[str],
                edges: list[dict[str, str]]) -> float:
    """Weighted, discount-per-hop path score in 0..100."""
    if not nodes:
        return 0.0
    weights = [_edge_weight(e["kind"], store) for e in edges]
    if not weights:
        return 15.0  # source-only path to Tier-0 identity
    base = sum(min(w, 1.0) for w in weights)
    avg_w = base / len(weights)
    # Discount by hop count; Tier-0 targets matter more (bank crown jewels).
    target = store.node(nodes[-1])
    tier0_bonus = 25.0 if (target and target.tier == 0) else 0.0
    src = store.node(nodes[0])
    src_kind_bonus = 10.0 if src and src.kind == "user" else 5.0
    score = 40 * avg_w + 30 / (1 + 0.35 * (len(weights) - 1)) + tier0_bonus \
        + src_kind_bonus
    return min(score, 100.0)


def find_attack_paths(store: GraphStore, source: str,
                      max_hops: int = 6, limit: int = 20,
                      tier0_only: bool = True) -> list[AttackPath]:
    """Bounded BFS from a source principal toward Tier-0 objectives."""
    start = store.node(source)
    if start is None:
        return []

    results: list[AttackPath] = []
    visited: set[str] = {source}
    # queue holds (node_id, path_nodes, path_edges)
    dq: deque[tuple[str, list[str], list[dict[str, str]]]] = deque()
    dq.append((source, [source], []))

    while dq and len(results) < limit:
        cur, pn, pe = dq.popleft()
        if len(pe) > max_hops:
            continue
        node = store.node(cur)
        if node is None:
            continue
        if cur != source and node.tier == 0 and start.tier != 0:
            results.append(AttackPath(pn, pe, len(pe),
                                      _score_path(store, pn, pe), True))
            continue  # do not expand beyond a Tier-0 objective

        for e in store.out_edges(cur):
            if e.target in visited:
                continue
            visited.add(e.target)
            dq.append((e.target, pn + [e.target],
                       pe + [{"source": e.source, "target": e.target,
                              "kind": e.kind}]))

    results.sort(key=lambda p: p.risk, reverse=True)
    return results


def blast_radius(store: GraphStore, source: str,
                 max_hops: int = 6) -> BlastRadius:
    """Everything a principal can reach + whether the crown jewels fall."""
    if store.node(source) is None:
        return BlastRadius(source, False, 0, 0, 0.0)

    visited = {source}
    dq: deque[tuple[str, int]] = deque([(source, 0)])
    tier0_hit = 0
    frontier: list[str] = []
    while dq:
        cur, depth = dq.popleft()
        if depth >= max_hops:
            continue
        for e in store.out_edges(cur):
            if e.target in visited:
                continue
            visited.add(e.target)
            n = store.node(e.target)
            if n and n.tier == 0 and n.kind != "domain":
                tier0_hit += 1
                frontier.append(e.target)
            dq.append((e.target, depth + 1))

    tier0_nodes = [n for n in visited
                   if (nn := store.node(n)) and nn.tier == 0
                   and nn.kind != "domain"]
    reachable_t0 = len(tier0_nodes)
    risk = min(100.0, 45.0 * (1 if reachable_t0 else 0)
               + 8.0 * min(reachable_t0, 5) + 2.0 * len(visited) ** 0.5)
    return BlastRadius(source, reachable_t0 > 0, reachable_t0,
                       len(visited) - 1, risk, sorted(set(frontier)))


def choke_points(store: GraphStore, top_n: int = 10) -> list[dict[str, Any]]:
    """Edges that unlock the most Tier-0 reach (champion/upstream analog).

    A bank fixes these first: they collapse many attack paths at once.
    """
    tier0 = {n.id for n in store.nodes()
             if n.tier == 0 and n.kind != "domain"}
    scores: dict[str, dict[str, Any]] = {}
    for src in [n for n in store.nodes()
                if n.kind in {"user", "group", "computer"} and n.tier != 0]:
        br = blast_radius(store, src.id, max_hops=5)
        scores[src.id] = {
            "node_id": src.id,
            "label": src.label,
            "kind": src.kind,
            "tier0_reachable": br.tier0_count,
            "reach": br.total_reachable,
            "risk": round(br.risk_score, 1),
        }
    ranked = sorted(scores.values(),
                    key=lambda d: (d["tier0_reachable"], d["risk"]),
                    reverse=True)
    return ranked[:top_n]


def shortest_paths_to_tier0(store: GraphStore, limit: int = 25) -> list[dict[str, Any]]:
    """For every Tier-0 asset: how many principals can reach it, and best path."""
    out: list[dict[str, Any]] = []
    t0 = [n for n in store.nodes() if n.tier == 0 and n.kind != "domain"]
    for t in t0[:limit]:
        reachers: list[str] = []
        for n in store.nodes():
            if n.id == t.id or n.tier == 0:
                continue
            paths = find_attack_paths(store, n.id, max_hops=5, limit=1,
                                      tier0_only=True)
            if paths and paths[0].nodes[-1] == t.id:
                reachers.append(n.id)
        out.append({"target": t.id, "label": t.label, "kind": t.kind,
                    "attacker_count": len(reachers),
                    "attackers": reachers[:10]})
    out.sort(key=lambda d: d["attacker_count"], reverse=True)
    return out


def domain_summary(store: GraphStore = STORE) -> dict[str, Any]:
    tiers = {"tier0": 0, "tier1": 0, "unclassified": 0}
    for n in store.nodes():
        if n.kind == "domain":
            continue
        if n.tier == 0:
            tiers["tier0"] += 1
        elif n.tier == 1:
            tiers["tier1"] += 1
        else:
            tiers["unclassified"] += 1
    brs = [blast_radius(store, n.id) for n in store.nodes()
           if n.kind in {"user", "computer"} and n.tier != 0]
    risky = sorted(brs, key=lambda b: b.risk_score, reverse=True)[:10]
    return {
        "tier_distribution": tiers,
        "tier0_exposure": sorted(
            [{"node": b.node_id, "risk": round(b.risk_score, 1),
              "tier0_targets": b.tier0_count} for b in brs
             if b.reachable_tier0],
            key=lambda d: d["risk"], reverse=True),
        "top_risk_principals": [
            {"node": b.node_id, "risk": round(b.risk_score, 1)}
            for b in risky],
    }
