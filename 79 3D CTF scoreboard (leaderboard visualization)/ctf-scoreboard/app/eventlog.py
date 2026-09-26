"""Append-only event log, audit chain and Merkle sealing.

This module is the only place allowed to write history. Everything else derives
state by replaying what these functions record, which is what makes a score
dispute settleable by evidence rather than by argument
(``state.md`` section 13, ``T-DER-03``/``T-DER-04``).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

GENESIS_HASH = "0" * 64

EVENT_TYPES = (
    "event.created",
    "event.started",
    "event.frozen",
    "event.ended",
    "team.registered",
    "challenge.created",
    "challenge.updated",
    "solve.recorded",
    "solve.disqualified",
    "score.adjusted",
    "webhook.received",
    "webhook.rejected",
    "webhook.replay.detected",
    "projection.rebuilt",
    "security.login",
    "security.logout",
    "security.denied",
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def canonical_json(payload: Any) -> str:
    """Deterministic JSON: sorted keys, no insignificant whitespace.

    Hash stability depends on this being the only serialiser used for hashing
    (T-DER-04).
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def chain_hash(prev_hash: str, canonical: str) -> str:
    return sha256_hex(prev_hash + canonical)


def merkle_root(leaves: Sequence[str]) -> str:
    """Binary Merkle root over hex leaf hashes (RFC 6962 style pairing)."""
    if not leaves:
        return sha256_hex("")
    level = list(leaves)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])  # duplicate the last node
        nxt: list[str] = []
        for i in range(0, len(level), 2):
            nxt.append(sha256_hex(level[i] + level[i + 1]))
        level = nxt
    return level[0]


@dataclass(frozen=True)
class AppendedEvent:
    seq: int
    event_id: str
    event_type: str
    occurred_at: str
    hash: str
    prev_hash: str


class EventLog:
    """Hash-chained event log bound to a single database."""

    def __init__(self, db, sealing_key: str) -> None:
        self.db = db
        self._sealing_key = sealing_key.encode("utf-8")

    # ----------------------------------------------------------------- append --
    def append(
        self,
        conn: sqlite3.Connection,
        *,
        event_type: str,
        payload: dict[str, Any],
        event_slug: str,
        actor_type: str = "system",
        actor_id: str = "system",
        occurred_at: datetime | None = None,
        event_id: str | None = None,
    ) -> AppendedEvent:
        """Append one event inside the caller's transaction.

        The caller owns the transaction boundary so that the event, its audit
        record and any projection write commit atomically (SEC-AUD-02).
        """
        if event_type not in EVENT_TYPES:
            raise ValueError(f"unknown event type: {event_type}")
        occurred = occurred_at or utcnow()
        occurred_iso = iso(occurred)
        new_id = event_id or f"evt_{uuid.uuid4().hex[:20]}"

        row = conn.execute("SELECT seq, hash FROM event_log ORDER BY seq DESC LIMIT 1").fetchone()
        prev_hash = row["hash"] if row else GENESIS_HASH
        next_seq = (row["seq"] + 1) if row else 1

        body = {
            "event_id": new_id,
            "event_type": event_type,
            "event_slug": event_slug,
            "schema_version": 1,
            "occurred_at": occurred_iso,
            "actor": {"type": actor_type, "id": actor_id},
            "payload": payload,
        }
        canonical = canonical_json(body)
        digest = chain_hash(prev_hash, canonical)

        conn.execute(
            """
            INSERT INTO event_log
                (event_id, event_slug, event_type, schema_version, occurred_at, recorded_at,
                 actor_type, actor_id, payload, prev_hash, hash)
            VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                new_id,
                event_slug,
                event_type,
                occurred_iso,
                iso(utcnow()),
                actor_type,
                actor_id,
                canonical_json(payload),
                prev_hash,
                digest,
            ),
        )
        return AppendedEvent(next_seq, new_id, event_type, occurred_iso, digest, prev_hash)

    # ------------------------------------------------------------- read side --
    def head(self, conn: sqlite3.Connection) -> tuple[int, str]:
        row = conn.execute("SELECT seq, hash FROM event_log ORDER BY seq DESC LIMIT 1").fetchone()
        return (row["seq"], row["hash"]) if row else (0, GENESIS_HASH)

    def iter_events(
        self,
        conn: sqlite3.Connection,
        *,
        event_slug: str | None = None,
        after_seq: int = 0,
        limit: int | None = None,
    ) -> Iterable[sqlite3.Row]:
        sql = "SELECT * FROM event_log WHERE seq > ?"
        params: list[Any] = [after_seq]
        if event_slug:
            sql += " AND event_slug = ?"
            params.append(event_slug)
        sql += " ORDER BY seq ASC"
        if limit:
            sql += " LIMIT ?"
            params.append(limit)
        return conn.execute(sql, params)

    # ----------------------------------------------------------- verification --
    def verify_chain(
        self, conn: sqlite3.Connection, *, event_slug: str | None = None
    ) -> dict[str, Any]:
        """Recompute the whole chain. Any mismatch is a P1 (INV-02, AL-S01).

        The chain is global, so when a single event is verified the walk starts
        from that event's genuine predecessor rather than from genesis - otherwise
        the second event in a multi-event deployment would always look broken.
        """
        sql = "SELECT * FROM event_log"
        params: list[Any] = []
        if event_slug:
            sql += " WHERE event_slug = ?"
            params.append(event_slug)
        sql += " ORDER BY seq ASC"

        prev = GENESIS_HASH
        checked = 0
        first = True
        for row in conn.execute(sql, params):
            if first and event_slug:
                predecessor = conn.execute(
                    "SELECT hash FROM event_log WHERE seq < ? ORDER BY seq DESC LIMIT 1", (row["seq"],)
                ).fetchone()
                prev = predecessor["hash"] if predecessor else GENESIS_HASH
                first = False
            body = {
                "event_id": row["event_id"],
                "event_type": row["event_type"],
                "event_slug": row["event_slug"],
                "schema_version": row["schema_version"],
                "occurred_at": row["occurred_at"],
                "actor": {"type": row["actor_type"], "id": row["actor_id"]},
                "payload": json.loads(row["payload"]),
            }
            expected = chain_hash(prev, canonical_json(body))
            if row["prev_hash"] != prev or row["hash"] != expected:
                return {
                    "ok": False,
                    "checked": checked,
                    "broken_at_seq": row["seq"],
                    "reason": "hash mismatch" if row["hash"] != expected else "prev_hash discontinuity",
                }
            prev = row["hash"]
            checked += 1
        return {"ok": True, "checked": checked, "head": prev}

    # ---------------------------------------------------------------- sealing --
    def unsealed_count(self, conn: sqlite3.Connection, event_slug: str) -> int:
        row = conn.execute(
            "SELECT COUNT(*) AS n FROM event_log WHERE event_slug = ? AND sealed_root IS NULL",
            (event_slug,),
        ).fetchone()
        return int(row["n"]) if row else 0

    def seal(
        self,
        conn: sqlite3.Connection,
        *,
        event_slug: str,
        anchoring_key: str | None = None,
        force: bool = False,
    ) -> dict[str, Any] | None:
        """Checkpoint a batch of events into a signed, anchored Merkle seal."""
        rows = conn.execute(
            "SELECT seq, hash FROM event_log WHERE event_slug = ? AND sealed_root IS NULL ORDER BY seq ASC",
            (event_slug,),
        ).fetchall()
        if not rows:
            return None
        if not force and len(rows) < 1:
            return None  # nothing to do even when forced

        leaves = [r["hash"] for r in rows]
        root = merkle_root(leaves)
        prev_row = conn.execute(
            "SELECT merkle_root FROM event_seal WHERE event_slug = ? ORDER BY id DESC LIMIT 1",
            (event_slug,),
        ).fetchone()
        prev_root = prev_row["merkle_root"] if prev_row else GENESIS_HASH

        signature = hmac.new(
            self._sealing_key, f"{event_slug}:{rows[0]['seq']}:{rows[-1]['seq']}:{root}".encode(),
            hashlib.sha256,
        ).hexdigest()
        anchored_at = iso(utcnow())

        conn.execute(
            """
            INSERT INTO event_seal
                (event_slug, from_seq, to_seq, event_count, merkle_root, prev_root,
                 signature, anchored_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_slug,
                rows[0]["seq"],
                rows[-1]["seq"],
                len(rows),
                root,
                prev_root,
                signature,
                anchored_at,
                anchored_at,
            ),
        )
        conn.executemany(
            "UPDATE event_log SET sealed_root = ? WHERE seq = ?", [(root, r["seq"]) for r in rows]
        )
        return {
            "from_seq": rows[0]["seq"],
            "to_seq": rows[-1]["seq"],
            "events": len(rows),
            "merkle_root": root,
            "prev_root": prev_root,
            "signature": signature,
            "anchored_at": anchored_at,
            "anchor": anchoring_key or "internal-hmac",
        }

    def seals(self, conn: sqlite3.Connection, event_slug: str) -> list[dict[str, Any]]:
        rows = conn.execute(
            "SELECT * FROM event_seal WHERE event_slug = ? ORDER BY id ASC", (event_slug,)
        ).fetchall()
        return [dict(r) for r in rows]


class AuditLog:
    """Separate hash chain for the security audit trail (SEC-AUD-01..09)."""

    def __init__(self, db) -> None:
        self.db = db

    def record(
        self,
        conn: sqlite3.Connection,
        *,
        action: str,
        actor_type: str,
        actor_id: str,
        resource_type: str,
        resource_id: str | None = None,
        outcome: str = "success",
        severity: str = "info",
        event_slug: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> int:
        if outcome not in {"success", "denied", "failure"}:
            raise ValueError(f"invalid outcome: {outcome}")
        if severity not in {"info", "notice", "warning", "critical"}:
            raise ValueError(f"invalid severity: {severity}")

        row = conn.execute("SELECT id, hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = row["hash"] if row else GENESIS_HASH

        body = {
            "occurred_at": iso(utcnow()),
            "actor": {"type": actor_type, "id": actor_id},
            "action": action,
            "resource": {"type": resource_type, "id": resource_id},
            "outcome": outcome,
            "severity": severity,
            "event_slug": event_slug,
            "context": context or {},
        }
        canonical = canonical_json(body)
        digest = chain_hash(prev_hash, canonical)

        cur = conn.execute(
            """
            INSERT INTO audit_log
                (occurred_at, actor_type, actor_id, action, resource_type, resource_id,
                 outcome, severity, event_slug, context, prev_hash, hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                body["occurred_at"],
                actor_type,
                actor_id,
                action,
                resource_type,
                resource_id,
                outcome,
                severity,
                event_slug,
                canonical_json(context or {}),
                prev_hash,
                digest,
            ),
        )
        return int(cur.lastrowid)

    def verify_chain(self, conn: sqlite3.Connection) -> dict[str, Any]:
        prev = GENESIS_HASH
        checked = 0
        for row in conn.execute("SELECT * FROM audit_log ORDER BY id ASC"):
            body = {
                "occurred_at": row["occurred_at"],
                "actor": {"type": row["actor_type"], "id": row["actor_id"]},
                "action": row["action"],
                "resource": {"type": row["resource_type"], "id": row["resource_id"]},
                "outcome": row["outcome"],
                "severity": row["severity"],
                "event_slug": row["event_slug"],
                "context": json.loads(row["context"]),
            }
            expected = chain_hash(prev, canonical_json(body))
            if row["hash"] != expected or row["prev_hash"] != prev:
                return {"ok": False, "checked": checked, "broken_at_id": row["id"]}
            prev = row["hash"]
            checked += 1
        return {"ok": True, "checked": checked, "head": prev}

    def search(
        self,
        conn: sqlite3.Connection,
        *,
        action: str | None = None,
        actor_id: str | None = None,
        outcome: str | None = None,
        event_slug: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        sql = "SELECT * FROM audit_log WHERE 1 = 1"
        params: list[Any] = []
        for column, value in (
            ("action", action),
            ("actor_id", actor_id),
            ("outcome", outcome),
            ("event_slug", event_slug),
        ):
            if value:
                sql += f" AND {column} = ?"
                params.append(value)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        out = []
        for row in conn.execute(sql, params):
            item = dict(row)
            item["context"] = json.loads(item["context"])
            out.append(item)
        return out
