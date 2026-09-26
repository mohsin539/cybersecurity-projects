"""Live competition simulator.

A CTF board is only interesting while it moves. When the event is live this task
records plausible solves at a configurable rate so the 3D scene, the SSE stream
and the invariants all have real traffic to work on. It is disabled with
``SCOREBOARD_SIMULATE=0``.

The simulator goes through exactly the same service path as a real webhook, so
it cannot create a state the ingest path could not.
"""

from __future__ import annotations

import asyncio
import random
from typing import Any

from .eventlog import iso, utcnow
from .service import SYSTEM, ScoreboardService, ServiceError


class Simulator:
    def __init__(self, service: ScoreboardService, rate_per_second: float = 0.9, seed: int = 7) -> None:
        self.service = service
        self.rate = max(0.0, rate_per_second)
        self.rng = random.Random(seed)
        self._task: asyncio.Task | None = None
        self._running = False
        self.solves = 0
        self.skips = 0

    @property
    def active(self) -> bool:
        return self._running

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._running = True
            self._task = asyncio.create_task(self._run(), name="scoreboard-simulator")

    async def stop(self) -> None:
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None

    async def _run(self) -> None:
        hub = getattr(self.service, "_hub", None)
        while self._running:
            try:
                await asyncio.sleep(max(0.05, self.rng.expovariate(max(self.rate, 0.01))))
                self._tick()
            except asyncio.CancelledError:
                raise
            except Exception:
                self.skips += 1
                await asyncio.sleep(1.0)

    def _tick(self) -> None:
        service = self.service
        with service.db.read() as conn:
            try:
                slug = service.event_slug(conn)
                meta = service.event_meta(conn, slug)
            except ServiceError:
                return
            if meta["phase"] != "live":
                return
            candidates = [
                r["slug"]
                for r in conn.execute(
                    "SELECT slug FROM teams WHERE event_slug = ?", (slug,)
                ).fetchall()
            ]
            active_challenges = [
                r["slug"]
                for r in conn.execute(
                    "SELECT slug FROM challenges WHERE event_slug = ? AND is_active = 1 ORDER BY base_points ASC",
                    (slug,),
                ).fetchall()
            ]
            unsolved = [
                r["slug"]
                for r in conn.execute(
                    """
                    SELECT c.slug FROM challenges c
                    WHERE c.event_slug = ? AND c.is_active = 1
                      AND NOT EXISTS (SELECT 1 FROM solves s WHERE s.challenge_id = c.id)
                    """,
                    (slug,),
                ).fetchall()
            ]

        if not candidates or not active_challenges:
            return

        # Prefer an unsolved challenge when one exists, so the board keeps moving
        # through the whole challenge set instead of stalling at the end.
        if unsolved and self.rng.random() < 0.65:
            challenge = self.rng.choice(unsolved)
        else:
            challenge = self.rng.choice(active_challenges)
        team = self.rng.choice(candidates)

        with service.db.write() as conn:
            try:
                result = service.record_solve(
                    conn, team=team, challenge=challenge, actor=SYSTEM, source="simulator"
                )
                board = service.leaderboard(conn, slug)
            except ServiceError:
                self.skips += 1
                return
            self.solves += 1

        hub = getattr(service, "_hub", None)
        if hub is not None:
            hub.publish({"type": "board", "id": board["last_seq"], "board": board, "reason": "solve"})
            hub.publish(
                {
                    "type": "solve",
                    "id": result["seq"],
                    "team": result["team"],
                    "challenge": result["challenge"],
                    "points": result["points"],
                    "first_blood": result["first_blood"],
                    "by": "simulator",
                }
            )

    def status(self) -> dict[str, Any]:
        return {
            "running": self._running,
            "rate_per_second": self.rate,
            "solves_emitted": self.solves,
            "rejections": self.skips,
        }
