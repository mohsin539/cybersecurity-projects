"""Neo4j-backed store (optional, same interface).

Enable with SG_NEO4J_ENABLED=true. Used for large lab domains and to mirror
real BloodHound collections imported via `bloodhound-python` / SharpHound ZIP
ETL (see app/collectors/importer.py).
"""
from __future__ import annotations

from typing import Any

from neo4j import GraphDatabase

from app.core.config import settings
from app.graph.model import Edge, Node
from app.graph.store import GraphStore


class Neo4jStore(GraphStore):
    def __init__(self) -> None:
        self._driver = GraphDatabase.driver(
            settings.neo4j_uri,
            auth=(settings.neo4j_user, settings.neo4j_password),
        )

    def close(self) -> None:
        self._driver.close()

    # -- mutations ---------------------------------------------------------
    def add_node(self, node: Node) -> None:
        q = (
            "MERGE (n:Base {id:$id}) "
            f"SET n:{node.kind} "
            "SET n.label=$label, n.domain=$domain, n.tier=$tier, n.props=$props"
        )
        with self._driver.session(database=settings.neo4j_database) as s:
            s.run(q, id=node.id, label=node.label, domain=node.domain,
                  tier=node.tier, props=node.props)

    def add_edge(self, edge: Edge) -> None:
        q = (
            "MATCH (a:Base {id:$src}), (b:Base {id:$dst}) "
            f"MERGE (a)-[r:{edge.kind}]->(b) SET r.props=$props"
        )
        with self._driver.session(database=settings.neo4j_database) as s:
            s.run(q, src=edge.source, dst=edge.target, props=edge.props)

    # -- queries -----------------------------------------------------------
    def node(self, node_id: str) -> Node | None:
        with self._driver.session(database=settings.neo4j_database) as s:
            rec = s.run(
                "MATCH (n:Base {id:$id}) RETURN n", id=node_id).single()
            if not rec:
                return None
            n = rec["n"]
            return Node(n["id"], _kind_of(n), n.get("label", ""),
                        n.get("domain", ""), n.get("props", {}),
                        n.get("tier"))

    def nodes(self) -> list[Node]:
        out: list[Node] = []
        with self._driver.session(database=settings.neo4j_database) as s:
            for rec in s.run("MATCH (n:Base) RETURN n"):
                n = rec["n"]
                out.append(Node(n["id"], _kind_of(n), n.get("label", ""),
                                n.get("domain", ""), n.get("props", {}),
                                n.get("tier")))
        return out

    def edges(self) -> list[Edge]:
        out: list[Edge] = []
        with self._driver.session(database=settings.neo4j_database) as s:
            for rec in s.run(
                "MATCH (a:Base)-[r]->(b:Base) "
                "RETURN a.id AS s, b.id AS t, type(r) AS k, r.props AS p"
            ):
                out.append(Edge(rec["s"], rec["t"], rec["k"], rec["p"] or {}))
        return out

    def out_edges(self, node_id: str) -> list[Edge]:
        with self._driver.session(database=settings.neo4j_database) as s:
            recs = s.run(
                "MATCH (a:Base {id:$id})-[r]->(b) "
                "RETURN b.id AS t, type(r) AS k, r.props AS p", id=node_id)
            return [Edge(node_id, r["t"], r["k"], r["p"] or {}) for r in recs]

    def in_edges(self, node_id: str) -> list[Edge]:
        with self._driver.session(database=settings.neo4j_database) as s:
            recs = s.run(
                "MATCH (a)-[r]->(b:Base {id:$id}) "
                "RETURN a.id AS s, type(r) AS k, r.props AS p", id=node_id)
            return [Edge(r["s"], node_id, r["k"], r["p"] or {}) for r in recs]

    def stats(self) -> dict[str, Any]:
        with self._driver.session(database=settings.neo4j_database) as s:
            nk = {r["k"]: r["c"] for r in s.run(
                "MATCH (n:Base) RETURN labels(n)[1] AS k, count(*) AS c")}
            ek = {r["k"]: r["c"] for r in s.run(
                "MATCH ()-[r]->() RETURN type(r) AS k, count(*) AS c")}
            return {"nodes_by_kind": nk, "edges_by_kind": ek,
                    "nodes_total": sum(nk.values()),
                    "edges_total": sum(ek.values())}


def _kind_of(n) -> str:
    for k in ("user", "group", "computer", "domain", "gpo", "ou",
              "container", "ca", "cert_template"):
        if k in n.labels:
            return k
    return "container"
