"""Deterministic demonstration data.

The seed is a pure function of ``SCOREBOARD_SEED``: the same seed always
produces the same teams, challenges and solve history, so a screenshot, a test
failure and a bug report all refer to the same board. No wall-clock reads beyond
the timestamps that are generated relative to ``now``.
"""

from __future__ import annotations

import random
import sqlite3
from datetime import timedelta
from typing import Any

from .eventlog import iso, utcnow
from .security import ensure_user
from .service import SYSTEM, ScoreboardService, ServiceError

CATEGORIES: list[tuple[str, str, str]] = [
    ("pwn", "Pwn", "#EF476F"),
    ("web", "Web", "#FFD166"),
    ("crypto", "Crypto", "#06D6A0"),
    ("forensics", "Forensics", "#00D2FF"),
    ("osint", "OSINT", "#C77DFF"),
    ("misc", "Misc", "#8B95B8"),
]

CHALLENGE_SEED: list[tuple[str, str, str, int]] = [
    ("baby-rsa", "Baby RSA", "crypto", 100),
    ("cookie-jar", "Cookie Jar", "web", 100),
    ("stack-smash", "Stack Smash", "pwn", 150),
    ("packet-whisperer", "Packet Whisperer", "forensics", 150),
    ("hash-crack", "Hash Crack", "crypto", 200),
    ("ssrf-delivery", "SSRF Delivery", "web", 200),
    ("ghost-in-the-machine", "Ghost In The Machine", "forensics", 250),
    ("rop-chainsaw", "Rop Chainsaw", "pwn", 250),
    ("identity-theft", "Identity Theft", "osint", 300),
    ("nonce-collision", "Nonce Collision", "crypto", 300),
    ("admin-panel", "Admin Panel", "web", 350),
    ("kernel-panic", "Kernel Panic", "pwn", 400),
]

TEAM_SEED: list[tuple[str, str, str]] = [
    ("null-pointer", "Null Pointers", "SE"),
    ("segfault-squad", "Segfault Squad", "DE"),
    ("bit-bangers", "Bit Bangers", "US"),
    ("heap-of-trouble", "Heap of Trouble", "NL"),
    ("stack-smashers", "Stack Smashers", "PL"),
    ("root-cause", "Root Cause", "IL"),
    ("the-off-by-ones", "The Off By Ones", "GB"),
    ("cache-miss", "Cache Miss", "FR"),
    ("race-condition", "Race Condition", "JP"),
    ("fork-bomb", "Fork Bomb", "AU"),
    ("undefined-behaviour", "Undefined Behaviour", "CA"),
    ("kernel-panic", "Kernel Panic Squad", "BR"),
    ("gdb-haters", "GDB Haters", "ES"),
    ("printf-gods", "Printf Gods", "IN"),
    ("sanitizer-wizards", "Sanitizer Wizards", "KR"),
    ("shellcode-samurai", "Shellcode Samurai", "JP"),
    ("crypto-kraken", "Crypto Kraken", "SG"),
    ("packet-poetry", "Packet Poetry", "NZ"),
    ("reverse-me", "Reverse Me", "FI"),
    ("lambda-lords", "Lambda Lords", "IE"),
    ("null-session", "Null Session", "CZ"),
    ("chaos-monkeys", "Chaos Monkeys", "SE"),
    ("entropy-wizards", "Entropy Wizards", "CH"),
    ("bit-rot", "Bit Rot", "NO"),
]

DEMO_USERS: list[tuple[str, str, str, str]] = [
    ("admin", "admin", "Ada Admin", "admin"),
    ("referee-1", "referee-one", "Rex Referee", "referee"),
    ("referee-2", "referee-two", "Robin Referee", "referee"),
    ("spectator", "spectator", "Sam Spectator", "spectator"),
]

DEMO_PASSWORD = "scoreboard-demo"


def seed_all(
    service: ScoreboardService,
    *,
    teams: int = 24,
    challenges: int = 12,
    password: str = DEMO_PASSWORD,
    seed: int = 20260926,
) -> dict[str, Any]:
    rng = random.Random(seed)
    with service.db.write() as conn:
        if not conn.execute("SELECT 1 FROM events LIMIT 1").fetchone():
            now = utcnow()
            service.create_event(
                conn,
                slug="main",
                name="Neural Nexus CTF 2026",
                starts_at=now - timedelta(hours=6),
                ends_at=now + timedelta(hours=6),
                actor=SYSTEM,
            )

        for order, (slug, name, color) in enumerate(CATEGORIES):
            conn.execute(
                "INSERT OR IGNORE INTO categories (slug, name, color, sort_order) VALUES (?,?,?,?)",
                (slug, name, color, order),
            )

        for slug, name, category, points in CHALLENGE_SEED[:challenges]:
            try:
                service.create_challenge(
                    conn, slug=slug, name=name, category=category, base_points=points, actor=SYSTEM
                )
            except ServiceError:
                pass  # idempotent seeding

        for index, (slug, name, country) in enumerate(TEAM_SEED[:teams]):
            try:
                service.register_team(
                    conn,
                    slug=slug,
                    name=name,
                    country=country,
                    accent=_accent(index),
                    seed=rng.randint(0, 10_000),
                    actor=SYSTEM,
                )
            except ServiceError:
                pass

        for handle, display, name, role in DEMO_USERS:
            ensure_user(
                conn,
                user_id=f"usr_{handle.replace('-', '_')}",
                handle=handle,
                display_name=name,
                role=role,
                password=password,
            )

        conn.execute(
            "INSERT OR IGNORE INTO webhook_clients (client_id, label, key_id, key_secret, active, created_at)"
            " VALUES (?,?,?,?,1,?)",
            (
                "platform-demo",
                "CTF platform (demo)",
                "kid_demo",
                "whsec_" + _stable_secret(seed),
                iso(utcnow()),
            ),
        )

        summary = _seed_history(service, conn, rng, teams=teams, challenges=challenges)
        service.set_phase(conn, phase="live", actor=SYSTEM)
        service.rebuild(conn, "main")
        return summary


def _seed_history(
    service: ScoreboardService, conn: sqlite3.Connection, rng: random.Random, *, teams: int, challenges: int
) -> dict[str, Any]:
    """Replay a plausible six hours of competition."""
    team_rows = conn.execute("SELECT id, slug, name FROM teams WHERE event_slug = 'main'").fetchall()
    challenge_rows = conn.execute(
        "SELECT id, slug, base_points FROM challenges WHERE event_slug = 'main' ORDER BY base_points ASC"
    ).fetchall()
    if not team_rows or not challenge_rows:
        return {"solves": 0}

    # Skill weights so the board has a stable hierarchy instead of noise.
    weights = [rng.random() ** 1.6 for _ in team_rows]
    total_weight = sum(weights) or 1.0

    now = utcnow()
    start = now - timedelta(hours=6)
    window_seconds = int((now - start).total_seconds())

    solved: set[tuple[int, int]] = set()
    recorded = 0
    # Difficulty curve: easy challenges fall early, hard ones late.
    ordered = sorted(challenge_rows, key=lambda r: r["base_points"])
    for step, challenge in enumerate(ordered):
        difficulty = (step + 1) / len(ordered)
        solve_window = window_seconds * (0.25 + 0.7 * difficulty)
        for team, weight in zip(team_rows, weights):
            probability = (weight / total_weight) * (1.15 - difficulty) * 1.5
            if rng.random() > probability:
                continue
            if (team["id"], challenge["id"]) in solved:
                continue
            offset = rng.uniform(60, max(120.0, solve_window))
            solved_at = start + timedelta(seconds=min(offset, window_seconds - 30))
            try:
                service.record_solve(
                    conn,
                    team=team["slug"],
                    challenge=challenge["slug"],
                    event_slug="main",
                    solved_at=solved_at,
                    source="seed",
                )
                recorded += 1
            except ServiceError:
                continue
    return {"solves": recorded, "teams": len(team_rows), "challenges": len(challenge_rows)}


def _accent(index: int) -> str:
    palette = [
        "#6C5CE7", "#00D2FF", "#06D6A0", "#FFD166", "#EF476F", "#C77DFF",
        "#4ECDC4", "#FF9F1C", "#A29BFE", "#55EFC4", "#FD79A8", "#74B9FF",
    ]
    return palette[index % len(palette)]


def _stable_secret(seed: int) -> str:
    import hashlib

    return hashlib.sha256(f"scoreboard-webhook-{seed}".encode()).hexdigest()[:40]
