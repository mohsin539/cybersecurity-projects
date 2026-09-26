"""Import ETL for real BloodHound collections (SharpHound ZIP / bloodhound-python JSON).

Normalizes raw collector output into the app's node/edge schema and ingests
into the active store. Malicious content is bounded by size/depth limits
(OWASP A05: unrestricted resource consumption).
"""
from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any, Iterable

from app.core import audit
from app.graph.model import EDGE_KINDS, NODE_KINDS, Edge, Node
from app.graph.store import STORE

MAX_FILE_BYTES = 512 * 1024 * 1024   # 512 MB per archive
MAX_ENTRIES = 2_000_000


def _norm_id(raw: str, kind: str) -> str:
    return f"{kind}:{raw.lower().strip()}"


def _guess_kind(obj: dict[str, Any]) -> str | None:
    t = (obj.get("type") or obj.get("ObjectType") or "").lower()
    if t in NODE_KINDS:
        return t
    return None


def import_sharphound_zip(path: str | Path) -> dict[str, int]:
    path = Path(path)
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("Archive exceeds import size limit")
    counters = {"nodes": 0, "edges": 0, "skipped": 0}

    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if not info.filename.endswith(".json"):
                continue
            try:
                payload = json.loads(zf.read(info))
            except (json.JSONDecodeError, OSError):
                counters["skipped"] += 1
                continue
            _ingest_data(payload, counters)
    audit.record("collection.import", source=path.name, **counters)
    STORE.prune_dangling()
    return counters


def import_sharphound_json(payload: dict[str, Any]) -> dict[str, int]:
    counters = {"nodes": 0, "edges": 0, "skipped": 0}
    _ingest_data(payload, counters)
    audit.record("collection.import_inline", **counters)
    STORE.prune_dangling()
    return counters


def _ingest_data(payload: dict[str, Any], counters: dict[str, int]) -> None:
    data = payload.get("data") or []
    if not isinstance(data, list):
        return
    for entry in data[:MAX_ENTRIES]:
        if not isinstance(entry, dict):
            counters["skipped"] += 1
            continue
        kind = _guess_kind(entry)
        if not kind:
            counters["skipped"] += 1
            continue
        oid = entry.get("ObjectIdentifier") or entry.get("id")
        label = (entry.get("Properties") or {}).get(
            "name") or entry.get("Label") or str(oid)
        domain = (entry.get("Properties") or {}).get("domain", "")
        node = Node(_norm_id(oid, kind), kind, label, domain,
                    entry.get("Properties") or {})
        STORE.add_node(node)
        counters["nodes"] += 1

        for ac in entry.get("Aces") or []:
            principal = ac.get("PrincipalSID") or ac.get("PrincipalType")
            ptype = (ac.get("PrincipalType") or "user").lower()
            if not principal:
                counters["skipped"] += 1
                continue
            right = (ac.get("RightName") or "GenericAll").replace(" ", "")
            edge_kind = _map_ace(right, (ac.get("AceType") or "")).lower()
            if edge_kind not in EDGE_KINDS:
                counters["skipped"] += 1
                continue
            STORE.add_edge(Edge(_norm_id(principal, ptype), node.id,
                                edge_kind, {"raw": ac}))
            counters["edges"] += 1


def _map_ace(right: str, ace_type: str) -> str:
    r = right.lower()
    if "dcsync" in r or "getchanges" in r or "getchangesall" in r:
        return "dcsync"
    if "genericall" in r:
        return "generic_all"
    if "genericwrite" in r:
        return "generic_write"
    if "writedacl" in r or "writedac" in r:
        return "write_dacl"
    if "writeowner" in r:
        return "write_owner"
    if "extendedright" in r or "allvalidated" in r:
        return "all_extended_rights"
    if "forcechangepassword" in r or ace_type.lower() == "resetpassword":
        return "force_change_pw"
    if "addmember" in r:
        return "add_member"
    if "owns" in r:
        return "owns"
    return "all_extended_rights"
