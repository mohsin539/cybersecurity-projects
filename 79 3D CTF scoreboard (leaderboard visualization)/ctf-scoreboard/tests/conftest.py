"""Shared fixtures. Every test runs against a throwaway SQLite file."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.config import Settings  # noqa: E402
from app.database import init_db  # noqa: E402
from app.eventlog import utcnow  # noqa: E402
from app.service import SYSTEM, init_service  # noqa: E402


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        environment="test",
        database_path=tmp_path / "scoreboard.db",
        secret_key="test-secret-key-for-hmac-and-sessions",
        seed_on_startup=False,
        simulator_enabled=False,
    )


@pytest.fixture
def db(settings):
    database = init_db(settings.database_path)
    yield database
    database.close()


@pytest.fixture
def service(db, settings):
    return init_service(db, settings)


@pytest.fixture
def event(service):
    with service.db.write() as conn:
        return service.create_event(
            conn, slug="main", name="Test Event", starts_at=utcnow(), actor=SYSTEM
        )


@pytest.fixture
def board(service, event):
    """One event, one category, three challenges, four teams, five solves."""
    with service.db.write() as conn:
        conn.execute(
            "INSERT INTO categories (slug, name, color, sort_order) VALUES ('pwn','Pwn','#EF476F',0)"
        )
        service.create_challenge(
            conn, slug="baby", name="Baby", category="pwn", base_points=100, actor=SYSTEM
        )
        service.create_challenge(
            conn, slug="mid", name="Mid", category="pwn", base_points=200, actor=SYSTEM
        )
        service.create_challenge(
            conn, slug="hard", name="Hard", category="pwn", base_points=300, actor=SYSTEM
        )
        for slug, name in (("alpha", "Alpha"), ("beta", "Beta"), ("gamma", "Gamma"), ("delta", "Delta")):
            service.register_team(conn, slug=slug, name=name, country="ZZ", actor=SYSTEM)
        service.set_phase(conn, phase="live", actor=SYSTEM)
        for team, challenge in (
            ("alpha", "baby"),
            ("alpha", "mid"),
            ("beta", "hard"),
            ("gamma", "baby"),
            ("delta", "mid"),
        ):
            service.record_solve(conn, team=team, challenge=challenge, event_slug="main", source="test")
        return service.leaderboard(conn, "main")


@pytest.fixture
def seeded_client(settings):
    """A fully seeded board behind a real ASGI app, ready for HTTP assertions."""
    from fastapi.testclient import TestClient

    from app.main import create_app
    from app.seed import DEMO_PASSWORD, seed_all

    database = init_db(settings.database_path)
    svc = init_service(database, settings)
    seed_all(svc, teams=24, challenges=12, password=DEMO_PASSWORD)
    app = create_app(settings, database_path=settings.database_path, seed=False)
    with TestClient(app) as client:
        client.demo_password = DEMO_PASSWORD
        yield client
    database.close()


@pytest.fixture
def unsolved_pair(seeded_client):
    """A (team, challenge) pair that nobody has solved yet.

    Tests must not hard-code pairs: the seeded history is random within a fixed
    seed, so any named pair may already be solved.
    """
    board = seeded_client.get("/api/leaderboard").json()
    done = {slug for team in board["teams"] for slug in team["solved_slugs"]}
    for team in board["teams"]:
        for challenge in board["challenges"]:
            if challenge["slug"] not in done:
                return team["slug"], challenge["slug"]
    raise AssertionError("the seeded board has no unsolved pair left")


@pytest.fixture
def login(seeded_client):
    def _login(handle: str) -> str:
        response = seeded_client.post(
            "/api/auth/login",
            json={"handle": handle, "password": seeded_client.demo_password},
        )
        assert response.status_code == 200, response.text
        return response.json()["role"]

    return _login
