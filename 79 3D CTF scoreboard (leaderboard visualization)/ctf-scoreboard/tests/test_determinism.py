"""T-DER-01..T-DER-05: determinism of the projection (security.md 17.13)."""

from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone

from app.scoring import Solve, TeamInput, compute_rank_order, decay_factor, project
from app.scoring import ScoringModel

MODEL = ScoringModel(
    version="test-v1",
    base_points=100,
    first_blood_bonus=50,
    top_n_bonus=25,
    top_n=3,
    decay_per_hour=0.02,
    purifier_window_seconds=1800,
)
AS_OF = datetime(2026, 9, 26, 12, 0, tzinfo=timezone.utc)


def _inputs():
    teams = [
        TeamInput(id=1, name="Alpha", slug="alpha", accent="#111111", country="ZZ"),
        TeamInput(id=2, name="Beta", slug="beta", accent="#222222", country="ZZ"),
    ]
    challenges = [
        {"slug": "baby", "base_points": 100, "is_active": 1},
        {"slug": "hard", "base_points": 300, "is_active": 1},
    ]
    solves = [
        Solve(team_id=1, challenge_id=1, solved_at=AS_OF - timedelta(hours=2), base_points=150,
              first_blood=True, seq=1, challenge_slug="baby"),
        Solve(team_id=1, challenge_id=2, solved_at=AS_OF - timedelta(hours=1), base_points=300,
              first_blood=False, seq=2, challenge_slug="hard"),
    ]
    return teams, solves, challenges


# ------------------------------------------------------------- T-DER-01/02 ----
def test_projection_is_a_pure_function_of_its_inputs():
    teams, solves, challenges = _inputs()
    first = project(event_slug="e", teams=teams, solves=solves, challenges=challenges,
                    model=MODEL, as_of=AS_OF)
    second = project(event_slug="e", teams=teams, solves=solves, challenges=challenges,
                     model=MODEL, as_of=AS_OF)
    assert first.state_hash == second.state_hash
    assert first.to_dict() == second.to_dict()


def test_projection_does_not_mutate_its_inputs():
    teams, solves, challenges = _inputs()
    teams_snapshot = copy.deepcopy(teams)
    solves_snapshot = copy.deepcopy(solves)
    project(event_slug="e", teams=teams, solves=solves, challenges=challenges, model=MODEL, as_of=AS_OF)
    assert teams == teams_snapshot
    assert solves == solves_snapshot


def test_input_order_does_not_change_the_result():
    teams, solves, challenges = _inputs()
    forward = project(event_slug="e", teams=teams, solves=solves, challenges=challenges,
                      model=MODEL, as_of=AS_OF)
    backward = project(event_slug="e", teams=list(reversed(teams)), solves=list(reversed(solves)),
                       challenges=list(reversed(challenges)), model=MODEL, as_of=AS_OF)
    assert forward.state_hash == backward.state_hash
    assert [t.team.slug for t in forward.teams] == [t.team.slug for t in backward.teams]


# ----------------------------------------------------------------- T-DER-03 --
def test_a_rebuild_reproduces_the_stored_hash(board, service):
    with service.db.read() as conn:
        before = service.leaderboard(conn, "main")
    with service.db.write() as conn:
        service.rebuild(conn, "main")
        after = service.leaderboard(conn, "main")
    assert before["state_hash"] == after["state_hash"]


def test_two_recomputations_in_one_request_agree(service, board):
    with service.db.read() as conn:
        first = service.build_state(conn, "main")
        second = service.build_state(conn, "main")
    assert first.state_hash == second.state_hash


# ----------------------------------------------------------------- T-DER-04 --
def test_as_of_is_honoured_exactly(board, service):
    with service.db.read() as conn:
        pinned = service.leaderboard(conn, "main", as_of=datetime(2026, 1, 1, tzinfo=timezone.utc))
        again = service.leaderboard(conn, "main", as_of=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert pinned["state_hash"] == again["state_hash"]


def test_decay_is_monotone_and_floored():
    fresh = decay_factor(MODEL, AS_OF - timedelta(minutes=1), AS_OF)
    old = decay_factor(MODEL, AS_OF - timedelta(hours=10), AS_OF)
    ancient = decay_factor(MODEL, AS_OF - timedelta(days=30), AS_OF)
    assert fresh > old >= ancient
    assert ancient >= MODEL.decay_floor
    assert decay_factor(MODEL, AS_OF, AS_OF) == 1.0


# ----------------------------------------------------------------- T-DER-05 --
def test_every_solve_carries_its_derivation(service, board):
    """Every stored award must be explainable without re-running the code."""
    with service.db.read() as conn:
        rows = conn.execute(
            "SELECT s.derivation, s.points_awarded, s.first_blood, s.base_points, s.derivation AS d "
            "FROM solves s"
        ).fetchall()
    assert rows
    for row in rows:
        body = json.loads(row["derivation"])
        assert body["parts"], row["derivation"]
        assert body["model_version"]
        # The parts must add up to the stored award exactly: no silent bonus,
        # no lost bonus.
        assert sum(p["points"] for p in body["parts"]) == body["total"]
        assert body["total"] == row["points_awarded"]
        assert body["base_points"] == row["base_points"]
        labels = [p["label"] for p in body["parts"]]
        assert ("first_blood" in labels) == bool(row["first_blood"])


def test_live_board_is_deterministic(board, service):
    with service.db.read() as conn:
        one = service.leaderboard(conn, "main")
        two = service.leaderboard(conn, "main")
    assert one["state_hash"] == two["state_hash"]
    assert one["teams"] == two["teams"]


# ---------------------------------------------------------------- rank order --
def test_rank_order_is_stable_for_tied_scores():
    scores = {1: 100.0, 2: 100.0, 3: 100.0}
    raw = {1: 100, 2: 100, 3: 100}
    last = {1: None, 2: None, 3: None}
    names = {1: "c", 2: "a", 3: "b"}
    order = compute_rank_order(scores, raw, last, names)
    assert order == [2, 3, 1]  # name is the final tie-break
    assert compute_rank_order(scores, raw, last, names) == order


def test_rank_order_prefers_the_earlier_solve_when_scores_tie():
    scores = {1: 100.0, 2: 100.0}
    raw = {1: 100, 2: 100}
    last = {1: datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc), 2: datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)}
    order = compute_rank_order(scores, raw, last, {1: "late", 2: "early"})
    assert order == [2, 1]


def test_rank_order_prefers_the_higher_raw_score_when_decayed_scores_tie():
    scores = {1: 50.0, 2: 50.0}
    raw = {1: 100, 2: 250}
    order = compute_rank_order(scores, raw, {1: None, 2: None}, {1: "a", 2: "b"})
    assert order == [2, 1]
