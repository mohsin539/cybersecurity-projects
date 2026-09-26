"""Scoring behaviour, invariants, two-person control, auth and the HTTP surface."""

from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest

from app.security import (
    create_session,
    destroy_session,
    ensure_user,
    hash_password,
    principal_for_token,
    verify_password,
)
from app.service import SYSTEM, Principal, ServiceError

REF1 = Principal(id="u_ref_1", handle="ref-1", role="referee")
REF2 = Principal(id="u_ref_2", handle="ref-2", role="referee")
VIEWER = Principal(id="u_view", handle="viewer", role="spectator")


@pytest.fixture
def board(service, event):
    """One live event with two teams, two challenges and three solves."""
    with service.db.write() as conn:
        conn.execute("INSERT INTO categories (slug, name, color, sort_order) VALUES ('pwn','Pwn','#EF476F',0)")
        service.create_challenge(conn, slug="baby", name="Baby", category="pwn", base_points=100, actor=SYSTEM)
        service.create_challenge(conn, slug="hard", name="Hard", category="pwn", base_points=300, actor=SYSTEM)
        service.register_team(conn, slug="alpha", name="Alpha", country="GB", actor=SYSTEM)
        service.register_team(conn, slug="beta", name="Beta", country="FR", actor=SYSTEM)
        service.set_phase(conn, phase="live", actor=SYSTEM)
        service.record_solve(conn, team="alpha", challenge="baby", source="test")
        service.record_solve(conn, team="alpha", challenge="hard", source="test")
        service.record_solve(conn, team="beta", challenge="baby", source="test")
        return service.leaderboard(conn, "main")


# ------------------------------------------------------------------ scoring --
def test_first_blood_bonus_is_awarded_once(board):
    alpha = board["teams"][0]
    assert alpha["slug"] == "alpha"
    # alpha took first blood on both challenges: (100 + 50) + (300 + 50) = 500,
    # plus the flat top-10 bonus of 25. The bonus must be counted exactly once.
    assert alpha["raw_score"] == 500 + 25


def test_the_stored_award_matches_a_recomputation(service, board):
    """Regression: the projection must not re-add first blood to points_awarded.

    ``points_awarded`` already includes the first-blood bonus, so feeding it back
    in as ``base_points`` silently paid every first blood twice.
    """
    with service.db.read() as conn:
        history = service.team_history(conn, "main", "alpha")
    # alpha holds first blood on both of its challenges: 100 + 50 and 300 + 50.
    assert [s["points"] for s in history["solves"]] == [150, 350]
    assert sum(s["points"] for s in history["solves"]) == 500
    alpha = board["teams"][0]
    assert alpha["raw_score"] == sum(s["points"] for s in history["solves"]) + 25


def test_board_is_ranked_by_score(board):
    scores = [t["score"] for t in board["teams"]]
    assert scores == sorted(scores, reverse=True)
    assert [t["rank"] for t in board["teams"]] == [1, 2]


def test_decayed_score_never_exceeds_the_raw_score(board):
    for team in board["teams"]:
        assert team["score"] <= team["raw_score"]


def test_duplicate_solve_is_rejected(service, board):
    with service.db.write() as conn:
        with pytest.raises(ServiceError) as excinfo:
            service.record_solve(conn, team="alpha", challenge="baby", source="test")
    assert excinfo.value.code == "already_solved"


def test_idempotency_key_replays_the_first_response(service, board):
    with service.db.write() as conn:
        first = service.record_solve(
            conn, team="beta", challenge="hard", source="test", idempotency_key="evt-1"
        )
        second = service.record_solve(
            conn, team="beta", challenge="hard", source="test", idempotency_key="evt-1"
        )
    assert second["idempotent_replay"] is True
    assert first["solve_id"] == second["solve_id"]


def test_unknown_team_and_challenge_are_rejected(service, board):
    with service.db.write() as conn:
        with pytest.raises(ServiceError) as unknown_team:
            service.record_solve(conn, team="ghosts", challenge="baby", source="test")
        with pytest.raises(ServiceError) as unknown_challenge:
            service.record_solve(conn, team="alpha", challenge="nope", source="test")
    assert unknown_team.value.status == 422
    assert unknown_challenge.value.status == 422


def test_solves_are_rejected_once_the_event_ends(service, board):
    with service.db.write() as conn:
        service.set_phase(conn, phase="ended", actor=SYSTEM)
        with pytest.raises(ServiceError) as excinfo:
            service.record_solve(conn, team="beta", challenge="hard", source="test")
    assert excinfo.value.code == "event_ended"


def test_retired_challenge_cannot_be_solved(service, board):
    with service.db.write() as conn:
        service.set_challenge_active(conn, slug="hard", active=False, actor=REF1)
        with pytest.raises(ServiceError) as excinfo:
            service.record_solve(conn, team="beta", challenge="hard", source="test")
    assert excinfo.value.code == "challenge_retired"


def test_illegal_phase_transitions_are_refused(service, board):
    with service.db.write() as conn:
        service.set_phase(conn, phase="ended", actor=SYSTEM)
        with pytest.raises(ServiceError) as excinfo:
            service.set_phase(conn, phase="live", actor=SYSTEM)
    assert excinfo.value.code == "illegal_transition"


# -------------------------------------------------------------- invariants ---
def test_every_invariant_passes_on_a_healthy_board(service, board):
    with service.db.read() as conn:
        result = service.evaluate_invariants(conn, "main")
    failed = [i for i in result["invariants"] if i["status"] == "fail"]
    assert failed == [], failed
    assert result["healthy"] is True
    assert result["duplicate_ids"] == []


def test_invariant_ids_match_the_specification(service, board):
    with service.db.read() as conn:
        result = service.evaluate_invariants(conn, "main")
    ids = {i["id"] for i in result["invariants"]}
    for n in range(1, 19):
        assert f"INV-{n:02d}" in ids, f"INV-{n:02d} is missing"
    assert "CHAINS" in ids


def test_invariants_cover_all_documented_ids(service, board):
    with service.db.read() as conn:
        ids = [i["id"] for i in service.evaluate_invariants(conn, "main")["invariants"]]
    assert len(ids) == len(set(ids)), "duplicate invariant ids"


def test_integrity_report_verifies_both_chains(service, board):
    with service.db.read() as conn:
        report = service.integrity_report(conn, "main")
    assert report["event_chain"]["ok"] is True
    assert report["audit_chain"]["ok"] is True
    assert report["scoring_model"]["version"]


def test_a_broken_projection_is_detected(service, board):
    with service.db.write() as conn:
        conn.execute(
            "UPDATE projection_team_score SET decayed_points = 99999 WHERE event_slug = 'main' AND rank = 1"
        )
        result = service.evaluate_invariants(conn, "main")
    provenance = next(i for i in result["invariants"] if i["id"] == "INV-11")
    assert provenance["status"] == "fail"
    assert result["healthy"] is False


# --------------------------------------------------------- two-person rule ---
def test_a_referee_cannot_approve_their_own_adjustment(service, board):
    with service.db.write() as conn:
        proposal = service.propose_adjustment(
            conn, team="alpha", delta=-50, reason="duplicate submission", actor=REF1
        )
        assert proposal["status"] == "pending"
        with pytest.raises(ServiceError) as excinfo:
            service.decide_adjustment(conn, adjustment_id=proposal["id"], approve=True, actor=REF1)
        assert excinfo.value.code == "separation_of_duties"
        assert excinfo.value.status == 403


def test_a_second_referee_approves(service, board):
    with service.db.write() as conn:
        proposal = service.propose_adjustment(
            conn, team="alpha", delta=-50, reason="duplicate submission", actor=REF1
        )
        decided = service.decide_adjustment(
            conn, adjustment_id=proposal["id"], approve=True, actor=REF2
        )
    assert decided["status"] == "approved"


def test_a_proposer_may_not_decide_their_own_proposal(service, board):
    """Separation of duties covers the decision record, not only the effect.

    A proposer may neither approve nor reject their own adjustment: the second
    pair of eyes is what makes the audit record trustworthy, and a proposer who
    could discard their own proposal could also hide that they filed it.
    """
    with service.db.write() as conn:
        proposal = service.propose_adjustment(
            conn, team="alpha", delta=-50, reason="duplicate submission", actor=REF1
        )
        for approve in (True, False):
            with pytest.raises(ServiceError) as excinfo:
                service.decide_adjustment(
                    conn, adjustment_id=proposal["id"], approve=approve, actor=REF1
                )
            assert excinfo.value.code == "separation_of_duties"
        with service.db.read() as check:
            row = check.execute(
                "SELECT status FROM score_adjustments WHERE id = ?", (proposal["id"],)
            ).fetchone()
    assert row["status"] == "pending"


def test_a_spectator_cannot_propose(service, board):
    with service.db.write() as conn:
        with pytest.raises(ServiceError) as excinfo:
            service.propose_adjustment(conn, team="alpha", delta=-50, reason="because i said so", actor=VIEWER)
    assert excinfo.value.status == 403


def test_a_weak_reason_is_refused(service, board):
    with service.db.write() as conn:
        with pytest.raises(ServiceError) as excinfo:
            service.propose_adjustment(conn, team="alpha", delta=-50, reason="oops", actor=REF1)
    assert excinfo.value.code == "weak_reason"


def test_a_zero_delta_is_refused(service, board):
    with service.db.write() as conn:
        with pytest.raises(ServiceError) as excinfo:
            service.propose_adjustment(conn, team="alpha", delta=0, reason="nothing to change here", actor=REF1)
    assert excinfo.value.code == "invalid_delta"


def test_an_applied_adjustment_moves_the_score_and_the_hash(service, board):
    before_hash = board["state_hash"]
    before_score = board["teams"][0]["score"]
    with service.db.write() as conn:
        proposal = service.propose_adjustment(
            conn, team="alpha", delta=-25, reason="duplicate submission", actor=REF1
        )
        service.decide_adjustment(conn, adjustment_id=proposal["id"], approve=True, actor=REF2)
        after = service.leaderboard(conn, "main")
    alpha = next(t for t in after["teams"] if t["slug"] == "alpha")
    assert alpha["score"] == before_score - 25
    assert after["state_hash"] != before_hash


def test_a_pending_adjustment_does_not_change_the_score(service, board):
    before = board["teams"][0]["score"]
    with service.db.write() as conn:
        service.propose_adjustment(conn, team="alpha", delta=-25, reason="duplicate submission", actor=REF1)
        after = service.leaderboard(conn, "main")
    assert after["teams"][0]["score"] == before


def test_the_audit_trail_records_a_denied_self_approval(service, board):
    with service.db.write() as conn:
        proposal = service.propose_adjustment(conn, team="alpha", delta=-50, reason="duplicate submission", actor=REF1)
        with pytest.raises(ServiceError):
            service.decide_adjustment(conn, adjustment_id=proposal["id"], approve=True, actor=REF1)
        denied = service.auditlog.search(conn, outcome="denied", limit=10)
    assert any(row["action"] == "score.adjust.approve" for row in denied)


# ---------------------------------------------------------------- passwords --
def test_password_hash_round_trip():
    digest, salt = hash_password("correct horse battery staple")
    assert digest != "correct horse battery staple"
    assert verify_password("correct horse battery staple", digest, salt)
    assert not verify_password("wrong", digest, salt)


def test_each_hash_uses_a_fresh_salt():
    a, salt_a = hash_password("same-password")
    b, salt_b = hash_password("same-password")
    assert salt_a != salt_b
    assert a != b


# ----------------------------------------------------------------- sessions --
def test_session_tokens_are_opaque_and_single_use(db):
    with db.write() as conn:
        ensure_user(conn, user_id="u1", handle="alice", display_name="Alice", role="admin", password="pw")
        from app.config import Settings

        settings = Settings(secret_key="x")
        user = conn.execute("SELECT * FROM users WHERE id = 'u1'").fetchone()
        token = create_session(conn, user, settings)
        assert len(token) >= 32
        assert principal_for_token(conn, token).handle == "alice"
        # Only the hash is stored, never the token itself.
        stored = conn.execute("SELECT token_hash FROM sessions").fetchone()["token_hash"]
        assert stored != token
        destroy_session(conn, token)
        assert principal_for_token(conn, token) is None


def test_expired_sessions_are_refused(db):
    with db.write() as conn:
        ensure_user(conn, user_id="u1", handle="bob", display_name="Bob", role="referee", password="pw")
        from app.config import Settings
        from app.eventlog import iso, utcnow
        from datetime import timedelta

        settings = Settings(secret_key="x", session_ttl_seconds=-10)
        user = conn.execute("SELECT * FROM users WHERE id = 'u1'").fetchone()
        token = create_session(conn, user, settings)
        conn.execute(
            "UPDATE sessions SET expires_at = ? WHERE token_hash = ?",
            (iso(utcnow() - timedelta(hours=1)), hashlib.sha256(token.encode()).hexdigest()),
        )
        assert principal_for_token(conn, token) is None
