"""Application service.

This is the only module allowed to mutate state. Its responsibilities:

* translate a request into an event plus an audit record, committed together;
* rebuild the read model by replaying the log through the pure projector;
* enforce the two-person rule, idempotency and phase legality;
* answer the questions the API, the SSE stream and the reports need.

Request handlers never touch a projection table directly (``state.md`` INV-01).
"""

from __future__ import annotations

import csv
import io
import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from . import invariants as inv
from .config import Settings, get_settings
from .database import Database, get_db
from .eventlog import AuditLog, EventLog, canonical_json, iso, sha256_hex, utcnow
from .scoring import LeaderboardState, ScoringModel, Solve, TeamInput, project

DEFAULT_EVENT_SLUG = "main"


class ServiceError(Exception):
    """A rejection with a stable code the API can map to a status."""

    def __init__(self, code: str, message: str, status: int = 400, **extra: Any) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.extra = extra

    def to_dict(self) -> dict[str, Any]:
        return {"error": self.code, "detail": self.message, **self.extra}


@dataclass
class Principal:
    id: str
    handle: str
    role: str

    @property
    def is_staff(self) -> bool:
        return self.role in {"referee", "admin"}

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


SYSTEM = Principal(id="system", handle="system", role="admin")


def actor_identity(actor: Principal) -> tuple[str, str]:
    """Return ``(actor_type, actor_id)`` for an event or audit record.

    The seeding and simulator paths act as ``SYSTEM``; recording those writes as
    ``human`` would forge an identity that resolves to no principal and would
    break INV-15. Centralised so the two never drift apart.
    """
    return ("system" if actor.id == "system" else "human", actor.id)


def _actor_type(actor: Principal) -> str:
    return actor_identity(actor)[0]


class ScoreboardService:
    def __init__(self, db: Database, settings: Settings) -> None:
        self.db = db
        self.settings = settings
        self.eventlog = EventLog(db, sealing_key=settings.resolved_secret())
        self.auditlog = AuditLog(db)
        self.model = ScoringModel(
            version=settings.scoring_model_version,
            base_points=settings.challenge_base_points,
            first_blood_bonus=settings.first_blood_bonus,
            top_n_bonus=settings.top10_bonus,
            top_n=10,
            decay_per_hour=settings.score_decay_per_hour,
            purifier_window_seconds=settings.purifier_window_seconds,
        )
        self._listeners: list[Any] = []
        # Recovers base points for databases created before the snapshot column.
        self.db.backfill_solve_base_points(settings.first_blood_bonus)

    # ------------------------------------------------------------ subscribers --
    def subscribe(self, listener) -> None:
        self._listeners.append(listener)

    def unsubscribe(self, listener) -> None:
        if listener in self._listeners:
            self._listeners.remove(listener)

    def publish(self, frame: dict[str, Any]) -> None:
        for listener in list(self._listeners):
            try:
                listener(frame)
            except Exception:  # a broken subscriber must not break ingestion
                pass

    # ------------------------------------------------------------- event meta --
    def event_slug(self, conn: sqlite3.Connection) -> str:
        row = conn.execute("SELECT slug FROM events ORDER BY created_at ASC LIMIT 1").fetchone()
        if row:
            return row["slug"]
        raise ServiceError("no_event", "No competition event exists", status=404)

    def event_meta(self, conn: sqlite3.Connection, slug: str) -> dict[str, Any]:
        row = conn.execute("SELECT * FROM events WHERE slug = ?", (slug,)).fetchone()
        if not row:
            raise ServiceError("unknown_event", f"Unknown event '{slug}'", status=404)
        return dict(row)

    def challenges(self, conn: sqlite3.Connection, slug: str) -> list[dict[str, Any]]:
        rows = conn.execute(
            """
            SELECT c.*, cat.slug AS category_slug, cat.name AS category_name, cat.color AS category_color
            FROM challenges c JOIN categories cat ON cat.id = c.category_id
            WHERE c.event_slug = ? ORDER BY c.base_points DESC, c.slug ASC
            """,
            (slug,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ---------------------------------------------------------------- loading --
    def _load_inputs(self, conn: sqlite3.Connection, slug: str) -> tuple[list[TeamInput], list[dict], list[Solve], dict[int, int]]:
        teams = [
            TeamInput(id=r["id"], name=r["name"], slug=r["slug"], accent=r["accent"], country=r["country"])
            for r in conn.execute("SELECT * FROM teams WHERE event_slug = ? ORDER BY name ASC", (slug,))
        ]
        challenges = self.challenges(conn, slug)
        cat_by_id = {c["id"]: c for c in challenges}
        solves: list[Solve] = []
        for r in conn.execute(
            """
            SELECT s.*, ch.slug AS ch_slug, ch.name AS ch_name, cat.slug AS cat_slug
            FROM solves s
            JOIN challenges ch ON ch.id = s.challenge_id
            JOIN categories cat ON cat.id = ch.category_id
            WHERE s.event_slug = ? ORDER BY s.seq ASC
            """,
            (slug,),
        ):
            challenge = cat_by_id.get(r["challenge_id"], {})
            solves.append(
                Solve(
                    team_id=r["team_id"],
                    challenge_id=r["challenge_id"],
                    solved_at=datetime.fromisoformat(r["solved_at"].replace("Z", "+00:00")),
                    base_points=r["base_points"],
                    first_blood=bool(r["first_blood"]),
                    seq=r["seq"],
                    challenge_slug=r["ch_slug"],
                    challenge_name=r["ch_name"],
                    category=r["cat_slug"],
                )
            )
        adjustments: dict[int, int] = {}
        for r in conn.execute(
            "SELECT team_id, SUM(delta) AS total FROM score_adjustments WHERE event_slug = ? AND status = 'applied' GROUP BY team_id",
            (slug,),
        ):
            adjustments[r["team_id"]] = int(r["total"] or 0)
        return teams, challenges, solves, adjustments

    def build_state(
        self, conn: sqlite3.Connection, slug: str, as_of: datetime | None = None
    ) -> LeaderboardState:
        meta = self.event_meta(conn, slug)
        teams, challenges, solves, adjustments = self._load_inputs(conn, slug)
        head_seq, _ = self.eventlog.head(conn)
        return project(
            event_slug=slug,
            teams=teams,
            solves=solves,
            challenges=challenges,
            model=self.model,
            as_of=as_of or utcnow(),
            phase=meta["phase"],
            last_seq=head_seq,
            adjustments=adjustments,
        )

    # ------------------------------------------------------------ persistence --
    def persist_state(self, conn: sqlite3.Connection, state: LeaderboardState) -> None:
        conn.execute("DELETE FROM projection_team_score WHERE event_slug = ?", (state.event_slug,))
        conn.executemany(
            """
            INSERT INTO projection_team_score
                (event_slug, team_id, raw_points, decayed_points, solves_count, rank,
                 last_solve_at, last_event_seq, trend)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    state.event_slug,
                    t.team.id,
                    t.raw_points,
                    round(t.decayed_points, 4),
                    t.solves,
                    t.rank,
                    iso(t.last_solve_at) if t.last_solve_at else None,
                    state.last_seq,
                    t.trend,
                )
                for t in state.teams
            ],
        )
        conn.execute(
            """
            INSERT INTO projection_state
                (event_slug, last_seq, projected_at, scoring_model_version, state_hash, healthy)
            VALUES (?, ?, ?, ?, ?, 1)
            ON CONFLICT(event_slug) DO UPDATE SET
                last_seq = excluded.last_seq,
                projected_at = excluded.projected_at,
                scoring_model_version = excluded.scoring_model_version,
                state_hash = excluded.state_hash
            """,
            (
                state.event_slug,
                state.last_seq,
                iso(state.as_of),
                state.scoring_model_version,
                state.state_hash,
            ),
        )

    def rebuild(self, conn: sqlite3.Connection, slug: str, as_of: datetime | None = None) -> LeaderboardState:
        state = self.build_state(conn, slug, as_of=as_of)
        self.persist_state(conn, state)
        return state

    def stored_as_of(self, conn: sqlite3.Connection, slug: str) -> datetime | None:
        row = conn.execute("SELECT projected_at FROM projection_state WHERE event_slug = ?", (slug,)).fetchone()
        if not row:
            return None
        return datetime.fromisoformat(row["projected_at"].replace("Z", "+00:00"))

    # ------------------------------------------------------------- mutations --
    def create_event(
        self,
        conn: sqlite3.Connection,
        *,
        slug: str,
        name: str,
        starts_at: datetime,
        ends_at: datetime | None = None,
        actor: Principal = SYSTEM,
    ) -> dict[str, Any]:
        if conn.execute("SELECT 1 FROM events WHERE slug = ?", (slug,)).fetchone():
            raise ServiceError("event_exists", f"Event '{slug}' already exists", status=409)
        now = iso(utcnow())
        conn.execute(
            "INSERT INTO events (slug, name, starts_at, ends_at, phase, scoring_model_version, created_at)"
            " VALUES (?, ?, ?, ?, 'setup', ?, ?)",
            (slug, name, iso(starts_at), iso(ends_at) if ends_at else None, self.model.version, now),
        )
        self.eventlog.append(
            conn,
            event_type="event.created",
            event_slug=slug,
            payload={"slug": slug, "name": name, "phase": "setup", "scoring_model_version": self.model.version},
            actor_type=_actor_type(actor),
            actor_id=actor.id,
        )
        self.auditlog.record(
            conn,
            action="event.create",
            actor_type=_actor_type(actor),
            actor_id=actor.id,
            resource_type="event",
            resource_id=slug,
            event_slug=slug,
            context={"name": name},
        )
        return {"slug": slug, "name": name, "phase": "setup"}

    def register_team(
        self,
        conn: sqlite3.Connection,
        *,
        slug: str,
        name: str,
        country: str | None = None,
        accent: str = "#6C5CE7",
        seed: int = 0,
        event_slug: str | None = None,
        actor: Principal = SYSTEM,
    ) -> dict[str, Any]:
        event_slug = event_slug or self.event_slug(conn)
        self.event_meta(conn, event_slug)
        if conn.execute("SELECT 1 FROM teams WHERE event_slug = ? AND slug = ?", (event_slug, slug)).fetchone():
            raise ServiceError("team_exists", f"Team '{slug}' already registered", status=409)
        cur = conn.execute(
            "INSERT INTO teams (event_slug, slug, name, country, accent, seed, created_at) VALUES (?,?,?,?,?,?,?)",
            (event_slug, slug, name, country, accent, seed, iso(utcnow())),
        )
        team_id = int(cur.lastrowid)
        self.eventlog.append(
            conn,
            event_type="team.registered",
            event_slug=event_slug,
            payload={"team_id": team_id, "slug": slug, "name": name, "country": country, "accent": accent},
            actor_type=_actor_type(actor),
            actor_id=actor.id,
        )
        self.auditlog.record(
            conn,
            action="team.register",
            actor_type=_actor_type(actor),
            actor_id=actor.id,
            resource_type="team",
            resource_id=slug,
            event_slug=event_slug,
            context={"team_id": team_id},
        )
        self.rebuild(conn, event_slug)
        return {"id": team_id, "slug": slug, "name": name}

    def create_challenge(
        self,
        conn: sqlite3.Connection,
        *,
        slug: str,
        name: str,
        category: str,
        base_points: int | None = None,
        author: str | None = None,
        event_slug: str | None = None,
        actor: Principal = SYSTEM,
    ) -> dict[str, Any]:
        event_slug = event_slug or self.event_slug(conn)
        self.event_meta(conn, event_slug)
        cat = conn.execute("SELECT * FROM categories WHERE slug = ?", (category,)).fetchone()
        if not cat:
            raise ServiceError("unknown_category", f"Unknown category '{category}'", status=422)
        if conn.execute("SELECT 1 FROM challenges WHERE event_slug = ? AND slug = ?", (event_slug, slug)).fetchone():
            raise ServiceError("challenge_exists", f"Challenge '{slug}' already exists", status=409)
        points = int(base_points if base_points is not None else self.settings.challenge_base_points)
        if points <= 0:
            raise ServiceError("invalid_points", "base_points must be positive", status=422)
        cur = conn.execute(
            "INSERT INTO challenges (event_slug, slug, name, category_id, base_points, author, created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (event_slug, slug, name, cat["id"], points, author, iso(utcnow())),
        )
        challenge_id = int(cur.lastrowid)
        self.eventlog.append(
            conn,
            event_type="challenge.created",
            event_slug=event_slug,
            payload={
                "challenge_id": challenge_id,
                "slug": slug,
                "name": name,
                "category": category,
                "base_points": points,
            },
            actor_type=_actor_type(actor),
            actor_id=actor.id,
        )
        self.auditlog.record(
            conn,
            action="challenge.create",
            actor_type=_actor_type(actor),
            actor_id=actor.id,
            resource_type="challenge",
            resource_id=slug,
            event_slug=event_slug,
            context={"base_points": points, "category": category},
        )
        self.rebuild(conn, event_slug)
        return {"id": challenge_id, "slug": slug, "base_points": points}

    def set_challenge_active(
        self, conn: sqlite3.Connection, *, slug: str, active: bool, actor: Principal, event_slug: str | None = None
    ) -> dict[str, Any]:
        event_slug = event_slug or self.event_slug(conn)
        row = conn.execute(
            "SELECT * FROM challenges WHERE event_slug = ? AND slug = ?", (event_slug, slug)
        ).fetchone()
        if not row:
            raise ServiceError("unknown_challenge", f"Unknown challenge '{slug}'", status=404)
        if bool(row["is_active"]) == bool(active):
            raise ServiceError("no_change", f"Challenge '{slug}' is already {'active' if active else 'retired'}")
        conn.execute("UPDATE challenges SET is_active = ? WHERE id = ?", (1 if active else 0, row["id"]))
        self.eventlog.append(
            conn,
            event_type="challenge.updated",
            event_slug=event_slug,
            payload={"challenge_id": row["id"], "slug": slug, "is_active": bool(active)},
            actor_type=_actor_type(actor),
            actor_id=actor.id,
        )
        self.auditlog.record(
            conn,
            action="challenge.update",
            actor_type=_actor_type(actor),
            actor_id=actor.id,
            resource_type="challenge",
            resource_id=slug,
            event_slug=event_slug,
            context={"is_active": bool(active)},
            severity="notice",
        )
        self.rebuild(conn, event_slug)
        return {"slug": slug, "is_active": bool(active)}

    def record_solve(
        self,
        conn: sqlite3.Connection,
        *,
        team: str,
        challenge: str,
        event_slug: str | None = None,
        solved_at: datetime | None = None,
        actor: Principal = SYSTEM,
        source: str = "platform",
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        """Record one solve: validate, score, log, audit, reproject â€” atomically."""
        event_slug = event_slug or self.event_slug(conn)
        meta = self.event_meta(conn, event_slug)
        if meta["phase"] == "ended":
            raise ServiceError("event_ended", "The event has ended; solves are rejected", status=409)

        if idempotency_key:
            existing = conn.execute(
                "SELECT response FROM idempotency_keys WHERE key = ?", (idempotency_key,)
            ).fetchone()
            if existing:
                return {**json.loads(existing["response"]), "idempotent_replay": True}

        team_row = conn.execute(
            "SELECT * FROM teams WHERE event_slug = ? AND (slug = ? OR name = ?)", (event_slug, team, team)
        ).fetchone()
        if not team_row:
            raise ServiceError("unknown_team", f"Unknown team '{team}'", status=422)
        challenge_row = conn.execute(
            "SELECT * FROM challenges WHERE event_slug = ? AND (slug = ? OR name = ?)",
            (event_slug, challenge, challenge),
        ).fetchone()
        if not challenge_row:
            raise ServiceError("unknown_challenge", f"Unknown challenge '{challenge}'", status=422)
        if not challenge_row["is_active"]:
            raise ServiceError("challenge_retired", f"Challenge '{challenge}' is retired", status=409)
        if conn.execute(
            "SELECT 1 FROM solves WHERE event_slug = ? AND team_id = ? AND challenge_id = ?",
            (event_slug, team_row["id"], challenge_row["id"]),
        ).fetchone():
            raise ServiceError(
                "already_solved", f"{team_row['name']} already solved {challenge_row['name']}", status=409
            )

        solved = solved_at or utcnow()
        if meta["phase"] == "frozen" and solved > (datetime.fromisoformat(meta["frozen_at"].replace("Z", "+00:00")) if meta["frozen_at"] else utcnow()):
            raise ServiceError("after_freeze", "The leaderboard is frozen; this solve is post-freeze", status=409)

        first_blood = not conn.execute(
            "SELECT 1 FROM solves WHERE event_slug = ? AND challenge_id = ?", (event_slug, challenge_row["id"])
        ).fetchone()

        head_seq, _ = self.eventlog.head(conn)
        seq = head_seq + 1

        from .scoring import solve_award  # local import keeps the module graph acyclic

        provisional = Solve(
            team_id=team_row["id"],
            challenge_id=challenge_row["id"],
            solved_at=solved,
            base_points=challenge_row["base_points"],
            first_blood=first_blood,
            seq=seq,
            challenge_slug=challenge_row["slug"],
            challenge_name=challenge_row["name"],
        )
        points, derivation = solve_award(self.model, provisional)

        conn.execute(
            """
            INSERT INTO solves
                (event_slug, seq, team_id, challenge_id, solved_at, base_points,
                 points_awarded, first_blood, derivation, scoring_model_version)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            """,
            (
                event_slug,
                seq,
                team_row["id"],
                challenge_row["id"],
                iso(solved),
                challenge_row["base_points"],
                points,
                1 if first_blood else 0,
                canonical_json(derivation),
                self.model.version,
            ),
        )
        appended = self.eventlog.append(
            conn,
            event_type="solve.recorded",
            event_slug=event_slug,
            payload={
                "team_id": team_row["id"],
                "team_slug": team_row["slug"],
                "challenge_id": challenge_row["id"],
                "challenge_slug": challenge_row["slug"],
                "points": points,
                "first_blood": first_blood,
                "source": source,
                "derivation": derivation,
            },
            actor_type=_actor_type(actor),
            actor_id=actor.id,
            occurred_at=solved,
        )
        self.auditlog.record(
            conn,
            action="solve.record",
            actor_type=_actor_type(actor),
            actor_id=actor.id,
            resource_type="solve",
            resource_id=appended.event_id,
            event_slug=event_slug,
            severity="notice",
            context={"team": team_row["slug"], "challenge": challenge_row["slug"], "points": points},
        )

        state = self.rebuild(conn, event_slug)
        me = next((t for t in state.teams if t.team.id == team_row["id"]), None)
        response = {
            "solve_id": appended.event_id,
            "seq": appended.seq,
            "team": team_row["slug"],
            "challenge": challenge_row["slug"],
            "points": points,
            "first_blood": first_blood,
            "rank": me.rank if me else None,
            "score": round(me.decayed_points, 2) if me else None,
            "state_hash": state.state_hash,
        }
        if idempotency_key:
            conn.execute(
                "INSERT INTO idempotency_keys (key, event_slug, first_seen_at, response) VALUES (?,?,?,?)",
                (idempotency_key, event_slug, iso(utcnow()), canonical_json(response)),
            )
        return response

    def set_phase(
        self, conn: sqlite3.Connection, *, phase: str, actor: Principal, event_slug: str | None = None
    ) -> dict[str, Any]:
        event_slug = event_slug or self.event_slug(conn)
        meta = self.event_meta(conn, event_slug)
        legal = {
            "setup": {"live", "ended"},
            "live": {"frozen", "ended"},
            "frozen": {"live", "ended"},
            "ended": set(),
        }
        if phase not in {"live", "frozen", "ended", "setup"}:
            raise ServiceError("unknown_phase", f"Unknown phase '{phase}'", status=422)
        if phase not in legal.get(meta["phase"], set()):
            raise ServiceError(
                "illegal_transition",
                f"Cannot move from '{meta['phase']}' to '{phase}'",
                status=409,
            )
        now = iso(utcnow())
        conn.execute(
            "UPDATE events SET phase = ?, frozen_at = COALESCE(frozen_at, ?), ended_at = COALESCE(ended_at, ?) WHERE slug = ?",
            (phase, now if phase == "frozen" else None, now if phase == "ended" else None, event_slug),
        )
        event_type = {"live": "event.started", "frozen": "event.frozen", "ended": "event.ended"}.get(
            phase, "event.created"
        )
        self.eventlog.append(
            conn,
            event_type=event_type,
            event_slug=event_slug,
            payload={"phase": phase, "previous_phase": meta["phase"]},
            actor_type=_actor_type(actor),
            actor_id=actor.id,
        )
        self.auditlog.record(
            conn,
            action=f"event.{phase}",
            actor_type=_actor_type(actor),
            actor_id=actor.id,
            resource_type="event",
            resource_id=event_slug,
            event_slug=event_slug,
            severity="notice" if phase != "live" else "info",
            context={"from": meta["phase"], "to": phase},
        )
        state = self.rebuild(conn, event_slug)
        self.maybe_seal(conn, event_slug)
        return {"phase": phase, "state_hash": state.state_hash, "as_of": iso(state.as_of)}

    # ------------------------------------------------- two-person adjustments --
    def propose_adjustment(
        self,
        conn: sqlite3.Connection,
        *,
        team: str,
        delta: int,
        reason: str,
        actor: Principal,
        event_slug: str | None = None,
    ) -> dict[str, Any]:
        if not actor.is_staff:
            raise ServiceError("forbidden", "Only referees or admins may propose adjustments", status=403)
        if delta == 0:
            raise ServiceError("invalid_delta", "delta must be non-zero", status=422)
        if len(reason.strip()) < 10:
            raise ServiceError("weak_reason", "A reason of at least 10 characters is required", status=422)
        event_slug = event_slug or self.event_slug(conn)
        team_row = conn.execute(
            "SELECT * FROM teams WHERE event_slug = ? AND (slug = ? OR name = ?)", (event_slug, team, team)
        ).fetchone()
        if not team_row:
            raise ServiceError("unknown_team", f"Unknown team '{team}'", status=422)

        cur = conn.execute(
            "INSERT INTO score_adjustments (event_slug, team_id, delta, reason, status, proposed_by, proposed_at)"
            " VALUES (?,?,?,?,'pending',?,?)",
            (event_slug, team_row["id"], int(delta), reason.strip(), actor.id, iso(utcnow())),
        )
        adjustment_id = int(cur.lastrowid)
        self.eventlog.append(
            conn,
            event_type="score.adjusted",
            event_slug=event_slug,
            payload={
                "adjustment_id": adjustment_id,
                "team_id": team_row["id"],
                "team_slug": team_row["slug"],
                "delta": int(delta),
                "reason": reason.strip(),
                "status": "pending",
                "proposed_by": actor.id,
            },
            actor_type=_actor_type(actor),
            actor_id=actor.id,
        )
        self.auditlog.record(
            conn,
            action="score.adjust.propose",
            actor_type=_actor_type(actor),
            actor_id=actor.id,
            resource_type="score_adjustment",
            resource_id=str(adjustment_id),
            event_slug=event_slug,
            severity="warning",
            context={"team": team_row["slug"], "delta": int(delta), "reason": reason.strip()},
        )
        return {"id": adjustment_id, "status": "pending", "requires_approval_from": "another staff member"}

    def decide_adjustment(
        self, conn: sqlite3.Connection, *, adjustment_id: int, approve: bool, actor: Principal
    ) -> dict[str, Any]:
        if not actor.is_staff:
            raise ServiceError("forbidden", "Only referees or admins may decide adjustments", status=403)
        row = conn.execute("SELECT * FROM score_adjustments WHERE id = ?", (adjustment_id,)).fetchone()
        if not row:
            raise ServiceError("unknown_adjustment", f"No adjustment #{adjustment_id}", status=404)
        if row["status"] != "pending":
            raise ServiceError("already_decided", f"Adjustment is already {row['status']}", status=409)
        if row["proposed_by"] == actor.id:
            # The core of the control: a proposer can never approve their own change.
            self.auditlog.record(
                conn,
                action="score.adjust.approve",
                actor_type=_actor_type(actor),
                actor_id=actor.id,
                resource_type="score_adjustment",
                resource_id=str(adjustment_id),
                event_slug=row["event_slug"],
                outcome="denied",
                severity="warning",
                context={"reason": "separation of duties: proposer cannot approve"},
            )
            raise ServiceError(
                "separation_of_duties",
                "A second person must approve this adjustment (SEC-AUTH-07)",
                status=403,
            )

        now = iso(utcnow())
        if approve:
            conn.execute(
                "UPDATE score_adjustments SET status = 'approved', approved_by = ?, approved_at = ? WHERE id = ?",
                (actor.id, now, adjustment_id),
            )
            head_seq, _ = self.eventlog.head(conn)
            conn.execute(
                "UPDATE score_adjustments SET status = 'applied', applied_seq = ? WHERE id = ?",
                (head_seq + 1, adjustment_id),
            )
            audit_id = self.auditlog.record(
                conn,
                action="score.adjust.apply",
                actor_type=_actor_type(actor),
                actor_id=actor.id,
                resource_type="score_adjustment",
                resource_id=str(adjustment_id),
                event_slug=row["event_slug"],
                severity="critical",
                context={"delta": row["delta"], "proposed_by": row["proposed_by"]},
            )
            conn.execute("UPDATE score_adjustments SET audit_id = ? WHERE id = ?", (audit_id, adjustment_id))
            self.eventlog.append(
                conn,
                event_type="score.adjusted",
                event_slug=row["event_slug"],
                payload={
                    "adjustment_id": adjustment_id,
                    "team_id": row["team_id"],
                    "delta": row["delta"],
                    "status": "applied",
                    "proposed_by": row["proposed_by"],
                    "approved_by": actor.id,
                    "reason": row["reason"],
                },
                actor_type=_actor_type(actor),
                actor_id=actor.id,
            )
            self.rebuild(conn, row["event_slug"])
        else:
            conn.execute(
                "UPDATE score_adjustments SET status = 'rejected', approved_by = ?, approved_at = ? WHERE id = ?",
                (actor.id, now, adjustment_id),
            )
            self.auditlog.record(
                conn,
                action="score.adjust.reject",
                actor_type=_actor_type(actor),
                actor_id=actor.id,
                resource_type="score_adjustment",
                resource_id=str(adjustment_id),
                event_slug=row["event_slug"],
                severity="notice",
                context={"reason": row["reason"]},
            )
        return {"id": adjustment_id, "status": "approved" if approve else "rejected"}

    def pending_adjustments(self, conn: sqlite3.Connection, event_slug: str) -> list[dict[str, Any]]:
        rows = conn.execute(
            """
            SELECT a.*, t.slug AS team_slug, t.name AS team_name
            FROM score_adjustments a JOIN teams t ON t.id = a.team_id
            WHERE a.event_slug = ? AND a.status = 'pending' ORDER BY a.id ASC
            """,
            (event_slug,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ---------------------------------------------------------------- sealing --
    def maybe_seal(self, conn: sqlite3.Connection, event_slug: str) -> dict[str, Any] | None:
        unsealed = self.eventlog.unsealed_count(conn, event_slug)
        if unsealed < self.settings.seal_batch_size:
            return None
        return self.eventlog.seal(conn, event_slug=event_slug, anchoring_key="local-hsm")

    def force_seal(self, conn: sqlite3.Connection, event_slug: str) -> dict[str, Any] | None:
        return self.eventlog.seal(conn, event_slug=event_slug, anchoring_key="local-hsm", force=True)

    # -------------------------------------------------------------- integrity --
    def integrity_report(self, conn: sqlite3.Connection, event_slug: str) -> dict[str, Any]:
        event_chain = self.eventlog.verify_chain(conn, event_slug=event_slug)
        audit_chain = self.auditlog.verify_chain(conn)
        seals = self.eventlog.seals(conn, event_slug)
        return {
            "event_chain": event_chain,
            "audit_chain": audit_chain,
            "seals": seals[-5:],
            "seal_count": len(seals),
            "unsealed_events": self.eventlog.unsealed_count(conn, event_slug),
            "scoring_model": self.model.describe(),
        }

    def evaluate_invariants(self, conn: sqlite3.Connection, event_slug: str) -> dict[str, Any]:
        stored_as_of = self.stored_as_of(conn, event_slug)
        recomputed = self.build_state(conn, event_slug, as_of=stored_as_of or utcnow())
        # Second, independent recomputation: identical input must give an identical hash.
        replayed = self.build_state(conn, event_slug, as_of=stored_as_of or utcnow())
        rows = conn.execute(
            "SELECT p.*, t.slug FROM projection_team_score p JOIN teams t ON t.id = p.team_id WHERE p.event_slug = ?",
            (event_slug,),
        ).fetchall()
        stored = [
            {"team_id": r["team_id"], "score": r["decayed_points"], "rank": r["rank"]} for r in rows
        ]
        head_seq, chain_head = self.eventlog.head(conn)
        ctx = inv.Context(
            conn=conn,
            event_slug=event_slug,
            recomputed_state=replayed,
            stored_teams=stored,
            eventlog_verify=self.eventlog.verify_chain(conn, event_slug=event_slug),
            audit_verify=self.auditlog.verify_chain(conn),
            head_seq=head_seq,
            chain_head=chain_head,
            recomputed_hash=recomputed.state_hash,
            replayed_hash=replayed.state_hash,
        )
        result = inv.evaluate(ctx)
        result["recomputed_state_hash"] = recomputed.state_hash
        result["deterministic"] = recomputed.state_hash == replayed.state_hash
        return result

    # ------------------------------------------------------------- API views --
    def leaderboard(self, conn: sqlite3.Connection, event_slug: str, as_of: datetime | None = None) -> dict[str, Any]:
        meta = self.event_meta(conn, event_slug)
        state = self.build_state(conn, event_slug, as_of=as_of)
        challenges = self.challenges(conn, event_slug)
        team_by_id = {t.team.id: t for t in state.teams}
        board = []
        for entry in state.to_dict()["teams"]:
            team_id = entry["team_id"]
            score = team_by_id[team_id]
            entry = dict(entry)
            entry["solved_slugs"] = [c["challenge_slug"] for c in score.contributions]
            entry["recent"] = [
                {"challenge_slug": c["challenge_slug"], "contribution": c["contribution"], "solved_at": c["solved_at"]}
                for c in score.contributions[-5:]
            ][::-1]
            board.append(entry)
        head_seq, chain_head = self.eventlog.head(conn)
        return {
            "event": {
                "slug": meta["slug"],
                "name": meta["name"],
                "phase": meta["phase"],
                "frozen": meta["phase"] in {"frozen", "ended"},
                "starts_at": meta["starts_at"],
                "ends_at": meta["ends_at"],
                "frozen_at": meta["frozen_at"],
            },
            "as_of": iso(state.as_of),
            "last_seq": head_seq,
            "chain_head": chain_head,
            "state_hash": state.state_hash,
            "scoring_model": state.scoring_model_version,
            "totals": state.totals,
            "teams": board,
            "challenges": [
                {
                    "slug": c["slug"],
                    "name": c["name"],
                    "category": c["category_slug"],
                    "category_name": c["category_name"],
                    "color": c["category_color"],
                    "base_points": c["base_points"],
                    "is_active": bool(c["is_active"]),
                    "solves": sum(1 for t in state.teams for s in t.contributions if s["challenge_slug"] == c["slug"]),
                    "first_blood": next(
                        (t.team.slug for t in state.teams for s in t.contributions if s["challenge_slug"] == c["slug"] and s["first_blood"]),
                        None,
                    ),
                }
                for c in challenges
            ],
        }

    def team_history(self, conn: sqlite3.Connection, event_slug: str, team_slug: str) -> dict[str, Any]:
        row = conn.execute(
            "SELECT * FROM teams WHERE event_slug = ? AND slug = ?", (event_slug, team_slug)
        ).fetchone()
        if not row:
            raise ServiceError("unknown_team", f"Unknown team '{team_slug}'", status=404)
        solves = conn.execute(
            """
            SELECT s.solved_at, s.points_awarded, s.first_blood, ch.slug AS challenge_slug,
                   ch.name AS challenge_name, cat.name AS category_name, cat.color
            FROM solves s
            JOIN challenges ch ON ch.id = s.challenge_id
            JOIN categories cat ON cat.id = ch.category_id
            WHERE s.team_id = ? ORDER BY s.solved_at ASC
            """,
            (row["id"],),
        ).fetchall()
        state = self.build_state(conn, event_slug)
        me = next((t for t in state.teams if t.team.id == row["id"]), None)
        return {
            "team": {"slug": row["slug"], "name": row["name"], "country": row["country"], "accent": row["accent"]},
            "rank": me.rank if me else None,
            "score": round(me.decayed_points, 2) if me else 0,
            "solves": [
                {
                    "challenge_slug": s["challenge_slug"],
                    "challenge_name": s["challenge_name"],
                    "category": s["category_name"],
                    "color": s["color"],
                    "solved_at": s["solved_at"],
                    "points": s["points_awarded"],
                    "first_blood": bool(s["first_blood"]),
                }
                for s in solves
            ],
        }

    # ---------------------------------------------------------------- reports --
    def leaderboard_csv(self, conn: sqlite3.Connection, event_slug: str) -> str:
        data = self.leaderboard(conn, event_slug)
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(
            ["rank", "team", "slug", "country", "score", "raw_score", "solves", "challenges_solved", "trend", "last_solve_at"]
        )
        for t in data["teams"]:
            writer.writerow(
                [
                    t["rank"], t["name"], t["slug"], t["country"] or "", t["score"], t["raw_score"],
                    t["solves"], t["challenges_solved"], t["trend"], t["last_solve_at"] or "",
                ]
            )
        return buffer.getvalue()

    def audit_csv(self, conn: sqlite3.Connection, event_slug: str) -> str:
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(["id", "occurred_at", "actor_id", "action", "resource_type", "resource_id", "outcome", "severity"])
        for row in self.auditlog.search(conn, event_slug=event_slug, limit=5000):
            writer.writerow(
                [row["id"], row["occurred_at"], row["actor_id"], row["action"], row["resource_type"],
                 row["resource_id"] or "", row["outcome"], row["severity"]]
            )
        return buffer.getvalue()

    def report_manifest(self, conn: sqlite3.Connection, event_slug: str) -> dict[str, Any]:
        data = self.leaderboard(conn, event_slug)
        payload = {
            "generated_at": iso(utcnow()),
            "event": data["event"],
            "state_hash": data["state_hash"],
            "chain_head": data["chain_head"],
            "scoring_model": data["scoring_model"],
            "teams": data["teams"],
        }
        body = canonical_json(payload)
        return {
            "filename": f"{event_slug}-leaderboard-{utcnow().strftime('%Y%m%dT%H%M%SZ')}.json",
            "content_type": "application/json",
            "body": json.dumps(payload, indent=2),
            "sha256": sha256_hex(body),
            "bytes": len(body),
        }


_service: ScoreboardService | None = None


def get_service() -> ScoreboardService:
    if _service is None:  # pragma: no cover - configured during startup
        raise RuntimeError("Service not initialised")
    return _service


def init_service(db: Database | None = None, settings: Settings | None = None) -> ScoreboardService:
    global _service
    _service = ScoreboardService(db or get_db(), settings or get_settings())
    return _service


def reset_service() -> None:  # pragma: no cover - tests
    global _service
    _service = None
