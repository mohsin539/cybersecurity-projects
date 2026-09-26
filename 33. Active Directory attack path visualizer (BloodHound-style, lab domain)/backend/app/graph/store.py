"""Graph store interface + in-memory implementation (lab default).

Neo4jStore implements the same interface for production-scale labs, so the
analysis engine is storage-agnostic.
"""
from __future__ import annotations

import threading
from collections import defaultdict
from typing import Iterable

from app.graph.model import EDGE_KINDS, NODE_KINDS, Edge, Node


class GraphStore:
    def add_node(self, node: Node) -> None: ...
    def add_edge(self, edge: Edge) -> None: ...
    def node(self, node_id: str) -> Node | None: ...
    def nodes(self) -> list[Node]: ...
    def edges(self) -> list[Edge]: ...
    def out_edges(self, node_id: str) -> list[Edge]: ...
    def in_edges(self, node_id: str) -> list[Edge]: ...
    def stats(self) -> dict[str, int]: ...


class InMemoryStore(GraphStore):
    """Thread-safe in-memory graph, fast enough for lab domains (<50k nodes)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._nodes: dict[str, Node] = {}
        self._edges: list[Edge] = []
        self._out: dict[str, list[Edge]] = defaultdict(list)
        self._in: dict[str, list[Edge]] = defaultdict(list)

    # -- mutations --------------------------------------------------------
    def add_node(self, node: Node) -> None:
        if node.kind not in NODE_KINDS:
            raise ValueError(f"Unknown node kind: {node.kind}")
        with self._lock:
            self._nodes[node.id] = node

    def add_edge(self, edge: Edge) -> None:
        if edge.kind not in EDGE_KINDS:
            raise ValueError(f"Unknown edge kind: {edge.kind}")
        with self._lock:
            self._nodes.setdefault(edge.source, Node(edge.source, "container",
                                                     edge.source))
            self._nodes.setdefault(edge.target, Node(edge.target, "container",
                                                     edge.target))
            self._edges.append(edge)
            self._out[edge.source].append(edge)
            self._in[edge.target].append(edge)

    # -- queries ----------------------------------------------------------
    def node(self, node_id: str) -> Node | None:
        with self._lock:
            return self._nodes.get(node_id)

    def nodes(self) -> list[Node]:
        with self._lock:
            return list(self._nodes.values())

    def edges(self) -> list[Edge]:
        with self._lock:
            return list(self._edges)

    def out_edges(self, node_id: str) -> list[Edge]:
        with self._lock:
            return list(self._out.get(node_id, ()))

    def in_edges(self, node_id: str) -> list[Edge]:
        with self._lock:
            return list(self._in.get(node_id, ()))

    def stats(self) -> dict[str, int]:
        with self._lock:
            by_kind: dict[str, int] = defaultdict(int)
            for n in self._nodes.values():
                by_kind[n.kind] += 1
            by_edge: dict[str, int] = defaultdict(int)
            for e in self._edges:
                by_edge[e.kind] += 1
            return {
                "nodes_total": len(self._nodes),
                "edges_total": len(self._edges),
                "nodes_by_kind": dict(sorted(by_kind.items())),
                "edges_by_kind": dict(sorted(by_edge.items())),
            }

    def clear(self) -> None:
        """Reset the store (lab/testing convenience)."""
        with self._lock:
            self._nodes.clear()
            self._edges.clear()
            self._rebuild_index(())

    def prune_dangling(self) -> int:
        """Drop edges whose endpoints are unknown (ETL hygiene)."""
        removed = 0
        with self._lock:
            keep: list[Edge] = []
            for e in self._edges:
                if e.source in self._nodes and e.target in self._nodes:
                    keep.append(e)
                else:
                    removed += 1
            self._edges = keep
            self._rebuild_index(keep)
        return removed

    def _rebuild_index(self, edges: Iterable[Edge]) -> None:
        self._out = defaultdict(list)
        self._in = defaultdict(list)
        for e in edges:
            self._out[e.source].append(e)
            self._in[e.target].append(e)


STORE = InMemoryStore()
