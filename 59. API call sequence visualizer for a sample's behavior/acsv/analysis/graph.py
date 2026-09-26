"""Sequence/call-graph utilities for visualization."""

from __future__ import annotations

import collections


def build_graph(edges: list[tuple[str, str, int]]) -> dict:
    """Return {nodes: [{id,label,count}], edges: [{from,to,value}]}."""
    node_count: dict[str, int] = collections.Counter()
    result: dict[str, dict] = {}
    for src, dst, weight in edges:
        node_count[src] += 1
        node_count[dst] += 1
        key = (src, dst)
        if key not in result:
            result[key] = {"from": src, "to": dst, "value": weight}
        else:
            result[key]["value"] += weight
    nodes = [
        {"id": name, "label": name, "count": cnt}
        for name, cnt in node_count.most_common(120)
    ]
    return {"nodes": nodes, "edges": list(result.values())}


def aggregate_sessions(rows: list[dict]) -> dict[str, dict]:
    """Group events per thread for swimlane rendering: tid -> [(ts,sort,api,cat)]."""
    out: dict[int, list] = collections.defaultdict(list)
    for e in rows:
        out[e["tid"]].append((
            e["ts_ns"] / 1e9,
            e["pid"],
            e["api"],
            e["category"],
            e["status"],
            e["ret"],
        ))
    return dict(out)