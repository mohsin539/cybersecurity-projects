"""Hash chains, audit chain, Merkle sealing and storage-layer immutability."""

from __future__ import annotations

import json
import sqlite3

import pytest

from app.eventlog import GENESIS_HASH, AuditLog, EventLog, merkle_root
from app.service import SYSTEM, ServiceError


def test_first_event_links_to_genesis(service, event):
    with service.db.read() as conn:
        row = conn.execute(
            "SELECT prev_hash FROM event_log WHERE event_slug = 'main' ORDER BY seq LIMIT 1"
        ).fetchone()
    assert row["prev_hash"] == GENESIS_HASH


def test_chain_verifies_end_to_end(board, service):
    with service.db.read() as conn:
        result = EventLog(service.db, "k").verify_chain(conn, event_slug="main")
    assert result["ok"] is True
    assert result["checked"] > 0
    assert len(result["head"]) == 64


def test_audit_chain_is_continuous(service, board):
    with service.db.read() as conn:
        result = AuditLog(service.db).verify_chain(conn)
    assert result["ok"] is True
    assert result["checked"] > 0


# ------------------------------------------------------- storage guarantees --
def test_update_on_event_log_is_rejected(board, service):
    with service.db.write() as conn:
        with pytest.raises(sqlite3.IntegrityError) as excinfo:
            conn.execute("UPDATE event_log SET payload = '{}' WHERE seq = 1")
    assert "append-only" in str(excinfo.value)


def test_delete_from_event_log_is_rejected(board, service):
    with service.db.write() as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM event_log WHERE seq = 1")


def test_update_on_audit_log_is_rejected(service, board):
    with service.db.write() as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE audit_log SET action = 'tampered'")


def test_hash_cannot_be_rewritten(board, service):
    with service.db.write() as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE event_log SET hash = '" + "a" * 64 + "' WHERE seq = 1")


def test_seal_root_stamp_is_the_only_permitted_update(board, service):
    """The one carve-out in the append-only trigger: NULL -> a root, nothing else."""
    with service.db.write() as conn:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE event_log SET sealed_root = '" + "b" * 64 + "', payload = '{\"x\":1}' WHERE seq = 1")
        conn.execute("UPDATE event_log SET sealed_root = '" + "b" * 64 + "' WHERE seq = 1")
        row = conn.execute("SELECT payload FROM event_log WHERE seq = 1").fetchone()
    assert row["payload"] != '{"x":1}'


# ---------------------------------------------------------------- detection --
def test_tampering_with_a_payload_is_detected(board, service):
    with service.db.write() as conn:
        conn.execute("DROP TRIGGER trg_event_log_no_update")
        conn.execute("UPDATE event_log SET payload = '{\"tampered\":true}' WHERE seq = 2")
    with service.db.read() as conn:
        result = EventLog(service.db, "k").verify_chain(conn, event_slug="main")
    assert result["ok"] is False
    assert result["broken_at_seq"] == 2
    assert result["reason"] == "hash mismatch"


def test_tampering_with_an_audit_record_is_detected(service, board):
    with service.db.write() as conn:
        conn.execute("DROP TRIGGER trg_audit_log_no_update")
        conn.execute("UPDATE audit_log SET action = 'nothing.happened' WHERE id = 1")
    with service.db.read() as conn:
        result = AuditLog(service.db).verify_chain(conn)
    assert result["ok"] is False
    assert result["broken_at_id"] == 1


# -------------------------------------------------------------------- merkle --
def test_merkle_root_is_deterministic_and_order_sensitive():
    leaves = [f"{i:064x}" for i in range(7)]
    assert merkle_root(leaves) == merkle_root(list(leaves))
    assert merkle_root(leaves) != merkle_root(list(reversed(leaves)))
    assert len(merkle_root(leaves)) == 64


def test_seal_records_a_root_and_a_range(board, service):
    with service.db.write() as conn:
        seal = service.force_seal(conn, "main")
    assert seal is not None
    assert seal["to_seq"] >= seal["from_seq"]
    assert len(seal["merkle_root"]) == 64
    assert len(seal["signature"]) == 64
    with service.db.read() as conn:
        stored = conn.execute(
            "SELECT * FROM event_seal WHERE event_slug = 'main' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        unsealed = conn.execute(
            "SELECT COUNT(*) AS n FROM event_log WHERE sealed_root IS NULL"
        ).fetchone()["n"]
    assert stored["merkle_root"] == seal["merkle_root"]
    assert unsealed == 0


def test_sealing_twice_is_idempotent(board, service):
    with service.db.write() as conn:
        first = service.force_seal(conn, "main")
        second = service.force_seal(conn, "main")
    assert first is not None
    assert second is None  # nothing left unsealed


def test_a_second_seal_chains_to_the_first_root(board, service):
    with service.db.write() as conn:
        first = service.force_seal(conn, "main")
        EventLog(service.db, "k").append(
            conn,
            event_type="challenge.updated",
            event_slug="main",
            payload={"slug": "baby", "is_active": True},
            actor_type="system",
            actor_id="system",
        )
        second = service.force_seal(conn, "main")
    assert first["prev_root"] == GENESIS_HASH
    assert second["prev_root"] == first["merkle_root"]


def test_unsealed_count_tracks_the_log(service, event):
    with service.db.read() as conn:
        assert EventLog(service.db, "k").unsealed_count(conn, "main") == 1
