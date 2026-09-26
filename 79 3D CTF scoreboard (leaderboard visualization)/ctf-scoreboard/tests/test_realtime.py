"""Realtime: SSE framing, replay, resync and the simulator."""

from __future__ import annotations

import json

import anyio
import pytest

from app.eventlog import utcnow
from app.realtime import StreamHub, sse_encode
from app.service import SYSTEM


@pytest.fixture
def anyio_backend():
    return "asyncio"


# ------------------------------------------------------------------ framing --
def test_sse_frame_format():
    frame = {"type": "board", "id": 42, "board": {"teams": []}}
    text = sse_encode(frame)
    assert text.endswith("\n\n")
    lines = text.strip().splitlines()
    assert lines[0] == "id: 42"
    assert lines[1] == "event: board"
    data = json.loads(lines[2][len("data: "):])
    assert data["type"] == "board"
    assert data["id"] == 42


def test_frames_without_an_id_omit_the_field():
    assert "id:" not in sse_encode({"type": "heartbeat"})


def test_retry_is_passed_through():
    text = sse_encode({"type": "board", "retry": 3000, "id": 1})
    assert "retry: 3000" in text
    assert "retry" not in json.loads(text.split("data: ")[1].strip())


def test_a_board_frame_id_matches_the_log_head(service, board):
    """INV-13: every published board frame is traceable to a log position."""
    with service.db.read() as conn:
        leaderboard = service.leaderboard(conn, "main")
    hub = StreamHub(service)
    hub.publish({"type": "board", "id": leaderboard["last_seq"], "board": leaderboard})
    frame = hub.replay[-1]
    assert frame["id"] == leaderboard["last_seq"]
    assert frame["board"]["state_hash"] == leaderboard["state_hash"]


# ------------------------------------------------------------------- replay --
def test_replay_buffer_is_bounded():
    hub = StreamHub(service=None, replay_size=3)
    for i in range(10):
        hub.publish({"type": "board", "id": i})
    assert len(hub.replay) == 3
    assert [f["id"] for f in hub.replay] == [7, 8, 9]


def test_status_reports_the_oldest_and_newest_ids():
    hub = StreamHub(service=None, replay_size=5)
    for i in range(3):
        hub.publish({"type": "board", "id": i})
    status = hub.status()
    assert status["frames_published"] == 3
    assert status["oldest_replay_id"] == 0
    assert status["newest_replay_id"] == 2


@pytest.mark.anyio
async def test_subscribe_replays_from_a_last_event_id():
    hub = StreamHub(service=None, replay_size=10)
    for i in range(1, 4):
        hub.publish({"type": "board", "id": i})

    seen = []

    async def consume():
        async for frame in hub.subscribe(last_event_id=1):
            seen.append(frame["id"])
            if len(seen) == 2:
                break

    with anyio.fail_after(2):
        await consume()
    assert seen == [2, 3]


# ---------------------------------------------------------------- simulator --
def test_simulator_start_and_stop():
    import asyncio

    from app.simulator import Simulator

    async def scenario():
        sim = Simulator(service=None, rate_per_second=1000)
        assert sim.active is False
        sim.start()
        assert sim.active is True
        await sim.stop()
        assert sim.active is False

    asyncio.run(scenario())


def test_simulator_emits_a_real_solve(service, board):
    """The simulator must use the same service path a webhook uses."""
    from app.simulator import Simulator

    with service.db.read() as conn:
        before = service.leaderboard(conn, "main")

    sim = Simulator(service, rate_per_second=1, seed=1)
    for _ in range(30):
        if sim.solves:
            break
        sim._tick()

    with service.db.read() as conn:
        after = service.leaderboard(conn, "main")
    assert sim.solves >= 1
    assert after["last_seq"] > before["last_seq"]
    assert sum(t["solves"] for t in after["teams"]) == sum(
        t["solves"] for t in before["teams"]
    ) + sim.solves
    # Every simulator solve must be attributable in the event log.
    with service.db.read() as conn:
        sources = {
            json.loads(r["payload"])["source"]
            for r in conn.execute(
                "SELECT payload FROM event_log WHERE event_type = 'solve.recorded'"
            ).fetchall()
        }
    assert "simulator" in sources


def test_simulator_does_nothing_when_the_event_is_not_live(service, board):
    from app.simulator import Simulator

    with service.db.write() as conn:
        service.set_phase(conn, phase="frozen", actor=SYSTEM)
    sim = Simulator(service, rate_per_second=1)
    for _ in range(10):
        sim._tick()
    assert sim.solves == 0
