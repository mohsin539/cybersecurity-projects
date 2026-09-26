"""The HTTP surface: public reads, the referee console and signed ingest."""

from __future__ import annotations

import hashlib
import hmac
import json
import time

import pytest

from app.seed import DEMO_PASSWORD

# Far enough in the future that decay has saturated at its floor, so a snapshot
# taken twice is comparable. The live board decays continuously by design, so an
# unpinned state hash legitimately differs between two requests seconds apart.
FROZEN_AS_OF = "2099-01-01T00:00:00+00:00"


def board_at(client, as_of: str = FROZEN_AS_OF) -> dict:
    return client.get("/api/leaderboard", params={"as_of": as_of}).json()


def solve_total(board: dict) -> int:
    return sum(team["solves"] for team in board["teams"])


def _secret(client) -> str:
    with client.app.state.service.db.read() as conn:
        return conn.execute(
            "SELECT key_secret FROM webhook_clients WHERE client_id = 'platform-demo'"
        ).fetchone()["key_secret"]


def _signed(client, payload: dict, *, secret=None, client_id="platform-demo", timestamp=None, raw=None):
    body = raw if raw is not None else json.dumps(payload).encode("utf-8")
    secret = secret if secret is not None else _secret(client)
    ts = str(timestamp if timestamp is not None else int(time.time()))
    signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return client.post(
        "/api/webhooks/ctf",
        content=body,
        headers={
            "content-type": "application/json",
            "x-client-id": client_id,
            "x-timestamp": ts,
            "x-signature": f"sha256={signature}",
        },
    )


# ------------------------------------------------------------ public reads ---
def test_health_endpoint(seeded_client):
    response = seeded_client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["chain_ok"] is True
    assert body["audit_chain_ok"] is True
    assert "stream" in body


def test_leaderboard_shape(seeded_client):
    body = seeded_client.get("/api/leaderboard").json()
    assert {"event", "teams", "last_seq", "chain_head", "state_hash", "scoring_model", "challenges"} <= set(body)
    assert body["event"]["slug"] == "main"
    assert [t["rank"] for t in body["teams"]] == list(range(1, len(body["teams"]) + 1))
    assert body["teams"][0]["score"] >= body["teams"][-1]["score"]


def test_leaderboard_is_deterministic_across_requests(seeded_client):
    a = seeded_client.get("/api/leaderboard").json()
    b = seeded_client.get("/api/leaderboard").json()
    assert a["teams"] == b["teams"]


def test_leaderboard_csv_has_a_header_and_a_row_per_team(seeded_client):
    response = seeded_client.get("/api/leaderboard.csv")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "attachment" in response.headers["content-disposition"]
    lines = response.text.strip().splitlines()
    assert lines[0].startswith("rank,team,slug,country,score,raw_score")
    assert len(lines) == len(seeded_client.get("/api/leaderboard").json()["teams"]) + 1


def test_report_json_is_self_describing_and_hash_stamped(seeded_client):
    response = seeded_client.get("/api/report.json")
    assert response.status_code == 200
    assert response.headers["x-content-sha256"]
    body = json.loads(response.text)
    assert body["generated_at"]
    assert body["state_hash"]
    assert body["teams"]


def test_team_detail_and_404(seeded_client):
    assert seeded_client.get("/api/teams/null-pointer").json()["team"]["slug"] == "null-pointer"
    assert seeded_client.get("/api/teams/does-not-exist").status_code == 404


def test_invariants_endpoint(seeded_client):
    body = seeded_client.get("/api/invariants").json()
    assert body["healthy"] is True
    assert body["failed"] == 0
    assert body["duplicate_ids"] == []
    assert body["delegated"] >= 4  # INV-05, INV-12, INV-13, INV-16


def test_integrity_endpoint(seeded_client):
    body = seeded_client.get("/api/integrity").json()
    assert body["event_chain"]["ok"] is True
    assert body["audit_chain"]["ok"] is True


def test_audit_endpoint_is_paged_and_filterable(seeded_client):
    body = seeded_client.get("/api/audit?limit=5").json()
    assert len(body["records"]) <= 5
    filtered = seeded_client.get("/api/audit?action=solve.record").json()
    assert all(r["action"] == "solve.record" for r in filtered["records"])


def test_config_endpoint_hides_secrets(seeded_client):
    body = seeded_client.get("/api/config").json()
    assert "secret" not in json.dumps(body).lower()
    assert body["scoring_model"]["version"]


def test_unknown_event_is_a_clean_404(seeded_client):
    assert seeded_client.get("/api/leaderboard?event=nope").status_code == 404


# ------------------------------------------------------------------- auth ----
def test_admin_requires_authentication(seeded_client):
    assert seeded_client.get("/api/admin/state").status_code == 401
    assert seeded_client.post("/api/admin/phase", json={"phase": "ended"}).status_code == 401
    assert seeded_client.post("/api/admin/solves", json={"team": "a", "challenge": "b"}).status_code == 401


def test_login_me_logout_cycle(seeded_client):
    assert seeded_client.post("/api/auth/login", json={"handle": "admin", "password": "wrong"}).status_code == 401
    ok = seeded_client.post("/api/auth/login", json={"handle": "admin", "password": DEMO_PASSWORD})
    assert ok.status_code == 200
    assert ok.json()["role"] == "admin"

    me = seeded_client.get("/api/auth/me").json()
    assert me["authenticated"] is True
    assert me["role"] == "admin"
    assert me["is_admin"] is True

    assert seeded_client.post("/api/auth/logout").status_code == 200
    assert seeded_client.get("/api/auth/me").json()["authenticated"] is False


def test_a_bad_login_is_audited(seeded_client):
    seeded_client.post("/api/auth/login", json={"handle": "admin", "password": "wrong"})
    records = seeded_client.get("/api/audit?action=security.login").json()["records"]
    denied = [r for r in records if r["outcome"] == "denied"]
    assert denied
    # The attempted handle is evidence, not an identity: it belongs in the
    # context, and the record must not claim a resolvable human principal.
    assert denied[0]["context"]["attempted_handle"] == "admin"
    assert denied[0]["actor_id"] == "unauthenticated"


def test_a_failed_login_does_not_break_the_invariants(seeded_client):
    """INV-15 must not flip red just because someone typed the wrong password."""
    seeded_client.post("/api/auth/login", json={"handle": "admin", "password": "wrong"})
    seeded_client.post("/api/auth/login", json={"handle": "no-such-person", "password": "wrong"})
    report = seeded_client.get("/api/invariants").json()
    assert report["healthy"] is True, [i for i in report["invariants"] if i["status"] == "fail"]


def test_spectator_cannot_record_a_solve(seeded_client):
    seeded_client.post("/api/auth/login", json={"handle": "spectator", "password": DEMO_PASSWORD})
    response = seeded_client.post("/api/admin/solves", json={"team": "null-pointer", "challenge": "baby-rsa"})
    assert response.status_code == 403


def test_referee_can_record_a_solve(seeded_client, unsolved_pair):
    team, challenge = unsolved_pair
    seeded_client.post("/api/auth/login", json={"handle": "referee-1", "password": DEMO_PASSWORD})
    before = seeded_client.get("/api/leaderboard").json()
    response = seeded_client.post("/api/admin/solves", json={"team": team, "challenge": challenge})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["team"] == team
    assert body["challenge"] == challenge
    assert body["points"] > 0
    after = seeded_client.get("/api/leaderboard").json()
    assert after["last_seq"] > before["last_seq"]
    assert after["state_hash"] != before["state_hash"]


def test_a_solve_ignores_a_client_supplied_score(seeded_client, unsolved_pair):
    team, challenge = unsolved_pair
    seeded_client.post("/api/auth/login", json={"handle": "referee-1", "password": DEMO_PASSWORD})
    response = seeded_client.post(
        "/api/admin/solves",
        json={"team": team, "challenge": challenge, "points": 999999, "score": 999999},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["points"] < 1000
    board = seeded_client.get("/api/leaderboard").json()
    scored = next(t for t in board["teams"] if t["slug"] == team)
    assert scored["raw_score"] < 100000


def test_solve_requires_team_and_challenge(seeded_client):
    seeded_client.post("/api/auth/login", json={"handle": "referee-1", "password": DEMO_PASSWORD})
    assert seeded_client.post("/api/admin/solves", json={"team": ""}).status_code == 422


def test_two_person_rule_over_http(seeded_client):
    """Referee 1 proposes, referee 2 approves; referee 1 cannot approve."""
    seeded_client.post("/api/auth/login", json={"handle": "referee-1", "password": DEMO_PASSWORD})
    proposed = seeded_client.post(
        "/api/admin/adjustments",
        json={"team": "null-pointer", "delta": -50, "reason": "duplicate submission"},
    )
    assert proposed.status_code == 200
    adjustment_id = proposed.json()["id"]

    state = seeded_client.get("/api/admin/state").json()
    assert any(a["id"] == adjustment_id for a in state["pending_adjustments"])

    denied = seeded_client.post(
        f"/api/admin/adjustments/{adjustment_id}/decision", json={"approve": True}
    )
    assert denied.status_code == 403
    assert denied.json()["error"] == "separation_of_duties"

    seeded_client.post("/api/auth/logout")
    seeded_client.post("/api/auth/login", json={"handle": "referee-2", "password": DEMO_PASSWORD})
    approved = seeded_client.post(
        f"/api/admin/adjustments/{adjustment_id}/decision", json={"approve": True}
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "approved"


def test_a_short_reason_is_a_422(seeded_client):
    seeded_client.post("/api/auth/login", json={"handle": "referee-1", "password": DEMO_PASSWORD})
    response = seeded_client.post(
        "/api/admin/adjustments", json={"team": "null-pointer", "delta": -50, "reason": "no"}
    )
    assert response.status_code == 422


def test_step_up_gates_the_audit_export(seeded_client):
    seeded_client.post("/api/auth/login", json={"handle": "referee-1", "password": DEMO_PASSWORD})
    assert seeded_client.get("/api/admin/audit/export.csv").status_code == 403
    step = seeded_client.post("/api/auth/step-up", json={"password": DEMO_PASSWORD})
    assert step.status_code == 200
    export = seeded_client.get("/api/admin/audit/export.csv")
    assert export.status_code == 200
    assert export.text.splitlines()[0].startswith("id,occurred_at,actor_id,action")


def test_step_up_requires_the_right_password(seeded_client):
    seeded_client.post("/api/auth/login", json={"handle": "referee-1", "password": DEMO_PASSWORD})
    assert seeded_client.post("/api/auth/step-up", json={"password": "nope"}).status_code == 401


def test_only_an_admin_may_change_the_phase(seeded_client):
    seeded_client.post("/api/auth/login", json={"handle": "referee-1", "password": DEMO_PASSWORD})
    response = seeded_client.post("/api/admin/phase", json={"phase": "frozen"})
    assert response.status_code == 200  # a referee may freeze a live event
    assert response.json()["phase"] == "frozen"


def test_a_second_login_replaces_the_session(seeded_client):
    seeded_client.post("/api/auth/login", json={"handle": "referee-1", "password": DEMO_PASSWORD})
    seeded_client.post("/api/auth/login", json={"handle": "admin", "password": DEMO_PASSWORD})
    assert seeded_client.get("/api/auth/me").json()["role"] == "admin"


# ---------------------------------------------------------------- ingest -----
def test_a_valid_webhook_is_accepted(seeded_client, unsolved_pair):
    team, challenge = unsolved_pair
    response = _signed(
        seeded_client,
        {"type": "solve.recorded", "id": "evt-1", "team": team, "challenge": challenge},
    )
    assert response.status_code == 202
    assert response.json()["status"] == "accepted"
    assert response.json()["points"] > 0


def test_a_ping_is_answered(seeded_client):
    assert _signed(seeded_client, {"type": "ping"}).json()["status"] == "pong"


def test_a_bad_signature_is_rejected_and_audited(seeded_client):
    response = _signed(
        seeded_client,
        {"type": "solve.recorded", "team": "null-pointer", "challenge": "baby-rsa"},
        secret="whsec_wrong",
    )
    assert response.status_code == 401
    assert response.json()["status"] == "rejected"
    assert any(
        r["outcome"] == "denied"
        for r in seeded_client.get("/api/audit?outcome=denied").json()["records"]
    )


def test_an_unknown_client_is_rejected(seeded_client):
    response = _signed(
        seeded_client,
        {"type": "ping"},
        client_id="nobody",
    )
    assert response.status_code == 401


def test_a_stale_timestamp_is_a_replay_attempt(seeded_client):
    response = _signed(
        seeded_client,
        {"type": "ping"},
        timestamp=int(time.time()) - 4000,
    )
    assert response.status_code == 401
    assert any(
        r["action"] == "webhook.replay.detected"
        for r in seeded_client.get("/api/audit?action=webhook.replay.detected").json()["records"]
    )


def test_the_body_is_verified_before_it_is_parsed(seeded_client):
    """A malformed body with a valid signature is quarantined, not crashed on."""
    response = _signed(seeded_client, None, raw=b"{not json at all")
    assert response.status_code == 422
    assert response.json()["status"] == "quarantined"


def test_poison_payloads_are_quarantined_with_an_owner(seeded_client):
    _signed(seeded_client, {"type": "solve.recorded", "team": "null-pointer", "challenge": "baby-rsa", "points": 10})
    with seeded_client.app.state.service.db.read() as conn:
        rows = conn.execute("SELECT reason, owner, resolved_at FROM dead_letters").fetchall()
    assert rows
    for row in rows:
        assert row["owner"]
        assert row["reason"]


def test_unknown_properties_are_quarantined(seeded_client):
    response = _signed(seeded_client, {"type": "ping", "surprise": 1})
    assert response.status_code == 422
    assert "surprise" in response.json()["reason"]


def test_a_duplicate_delivery_changes_nothing(seeded_client, unsolved_pair):
    team, challenge = unsolved_pair
    payload = {"type": "solve.recorded", "id": "evt-dup", "team": team, "challenge": challenge}
    first = _signed(seeded_client, payload)
    before = board_at(seeded_client)
    second = _signed(seeded_client, payload)
    after = board_at(seeded_client)
    assert first.status_code == 202
    assert second.status_code == 202
    assert second.json()["idempotent_replay"] is True
    assert before["state_hash"] == after["state_hash"]
    assert before["last_seq"] == after["last_seq"]


def test_a_repeated_solve_without_an_id_is_a_no_op(seeded_client, unsolved_pair):
    team, challenge = unsolved_pair
    payload = {"type": "solve.recorded", "team": team, "challenge": challenge}
    _signed(seeded_client, payload)
    before = board_at(seeded_client)
    response = _signed(seeded_client, payload)
    after = board_at(seeded_client)
    assert response.status_code == 200
    assert response.json()["error"] == "already_solved"
    assert before["state_hash"] == after["state_hash"]
    assert before["last_seq"] == after["last_seq"]
    assert solve_total(before) == solve_total(after)


def test_the_webhook_never_sets_the_score(seeded_client, unsolved_pair):
    team, challenge = unsolved_pair
    response = _signed(
        seeded_client,
        {
            "type": "solve.recorded",
            "id": "evt-points",
            "team": team,
            "challenge": challenge,
            "value": 999999,
        },
    )
    assert response.status_code == 202
    assert response.json()["points"] < 1000
