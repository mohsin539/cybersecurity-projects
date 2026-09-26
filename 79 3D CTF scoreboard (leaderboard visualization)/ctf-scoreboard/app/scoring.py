"""Deterministic scoring.

The rules in this module are a *pure function* of their inputs: no clock reads, no
randomness, no I/O, no database access. Callers supply ``as_of`` explicitly.
That is what makes a rebuild bit-for-bit comparable to live state
(``state.md`` section 6, invariants INV-01/INV-02, tests T-DER-01..T-DER-04).

Scoring model
-------------
* A solve awards the challenge's base points.
* First blood on a challenge adds a flat bonus.
* Points decay exponentially so an early lead is not a permanent lead.
* Decay is suspended for the *purifier window* after a team's last solve, which
  removes the one source of replay non-determinism (wall-clock drift).
* A team's displayed score is the sum of decayed contributions, floored so a
  dormant team cannot collapse to zero and vanish from the board.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping, Sequence

from .eventlog import canonical_json, sha256_hex

DECAY_FLOOR = 0.40


@dataclass(frozen=True)
class ScoringModel:
    """Immutable, versioned scoring rules. Changing any field means a new version."""

    version: str
    base_points: int
    first_blood_bonus: int
    top_n_bonus: int
    top_n: int
    decay_per_hour: float
    purifier_window_seconds: int
    decay_floor: float = DECAY_FLOOR

    def describe(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "base_points": self.base_points,
            "first_blood_bonus": self.first_blood_bonus,
            "top_n_bonus": self.top_n_bonus,
            "top_n": self.top_n,
            "decay_per_hour": self.decay_per_hour,
            "purifier_window_seconds": self.purifier_window_seconds,
            "decay_floor": self.decay_floor,
        }

    def fingerprint(self) -> str:
        return sha256_hex(canonical_json(self.describe()))[:16]


@dataclass(frozen=True)
class Solve:
    team_id: int
    challenge_id: int
    solved_at: datetime
    base_points: int
    first_blood: bool
    seq: int
    challenge_slug: str = ""
    challenge_name: str = ""
    category: str = ""
    disqualified: bool = False


@dataclass(frozen=True)
class TeamInput:
    id: int
    name: str
    slug: str
    accent: str
    country: str | None = None


@dataclass
class TeamScore:
    team: TeamInput
    rank: int
    previous_rank: int | None
    raw_points: int
    decayed_points: float
    solves: int
    challenges_solved: int
    total_possible: int
    last_solve_at: datetime | None
    trend: str
    contributions: list[dict[str, Any]] = field(default_factory=list)
    delta: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "team_id": self.team.id,
            "name": self.team.name,
            "slug": self.team.slug,
            "accent": self.team.accent,
            "country": self.team.country,
            "rank": self.rank,
            "previous_rank": self.previous_rank,
            "trend": self.trend,
            "score": round(self.decayed_points, 2),
            "raw_score": self.raw_points,
            "solves": self.solves,
            "challenges_solved": self.challenges_solved,
            "total_possible": self.total_possible,
            "completion": round(
                (self.challenges_solved / self.total_possible) if self.total_possible else 0.0, 4
            ),
            "last_solve_at": self.last_solve_at.isoformat() if self.last_solve_at else None,
            "delta": round(self.delta, 2),
        }


@dataclass(frozen=True)
class LeaderboardState:
    event_slug: str
    phase: str
    as_of: datetime
    scoring_model_version: str
    last_seq: int
    teams: list[TeamScore]
    totals: dict[str, Any]
    state_hash: str
    frozen: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_slug": self.event_slug,
            "phase": self.phase,
            "frozen": self.frozen,
            "as_of": self.as_of.isoformat(),
            "scoring_model_version": self.scoring_model_version,
            "last_seq": self.last_seq,
            "state_hash": self.state_hash,
            "teams": [t.to_dict() for t in self.teams],
            "totals": self.totals,
        }


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def decay_reference(last_solve_at: datetime | None, as_of: datetime, window_seconds: int) -> datetime:
    """The instant decay is measured from.

    Inside the purifier window this is the last solve, so decay is effectively
    frozen; afterwards it is simply ``as_of``.
    """
    if last_solve_at is None:
        return as_of
    return min(as_of, _aware(last_solve_at) + timedelta(seconds=window_seconds))


def decay_factor(model: ScoringModel, solved_at: datetime, reference: datetime) -> float:
    hours = max(0.0, (_aware(reference) - _aware(solved_at)).total_seconds() / 3600.0)
    if hours <= 0:
        return 1.0
    return max(model.decay_floor, math.exp(-model.decay_per_hour * hours))


def solve_award(
    model: ScoringModel, solve: Solve, is_top_n: bool = False
) -> tuple[int, dict[str, Any]]:
    """Points for one solve, plus the derivation that explains them.

    The derivation is stored with the solve. "Why is this team on 400?" must be
    answerable without re-running the code (T-DER-05).
    """
    base = int(solve.base_points)
    parts: list[dict[str, Any]] = [{"label": "base", "points": base}]
    total = base
    if solve.first_blood:
        total += model.first_blood_bonus
        parts.append({"label": "first_blood", "points": model.first_blood_bonus})
    if is_top_n:
        total += model.top_n_bonus
        parts.append({"label": f"top_{model.top_n}_bonus", "points": model.top_n_bonus})
    return total, {
        "challenge": solve.challenge_slug,
        "base_points": base,
        "parts": parts,
        "total": total,
        "model_version": model.version,
    }


def _team_score_at(model: ScoringModel, solves: Sequence[Solve], as_of: datetime) -> float:
    if not solves:
        return 0.0
    last = max(_aware(s.solved_at) for s in solves)
    reference = decay_reference(last, as_of, model.purifier_window_seconds)
    total = 0.0
    for s in solves:
        total += s.base_points * decay_factor(model, s.solved_at, reference)
    return total


def compute_rank_order(
    scores: Mapping[int, float], raw: Mapping[int, int], last_solve: Mapping[int, datetime | None], names: Mapping[int, str]
) -> list[int]:
    """Total order with documented tie-breaks.

    Higher decayed score wins; then raw score; then the earlier last solve; then
    team name. The final key guarantees a stable order so equal teams never
    flicker between positions (INV-09).
    """
    def key(team_id: int) -> tuple[float, int, float, str]:
        last = last_solve.get(team_id)
        # Ascending sort: an earlier last solve must come first, so the timestamp
        # is used as-is. Teams that never solved sort last among ties.
        last_key = _aware(last).timestamp() if last else float("inf")
        return (-round(scores.get(team_id, 0.0), 6), -raw.get(team_id, 0), last_key, names.get(team_id, ""))

    return sorted(scores.keys(), key=key)


def project(
    *,
    event_slug: str,
    teams: Iterable[TeamInput],
    solves: Iterable[Solve],
    challenges: Iterable[Mapping[str, Any]],
    model: ScoringModel,
    as_of: datetime,
    phase: str = "live",
    last_seq: int = 0,
    adjustments: Mapping[int, int] | None = None,
) -> LeaderboardState:
    """Project the leaderboard. Pure: same inputs, same output, always."""
    as_of = _aware(as_of)
    team_list = list(teams)
    challenge_list = list(challenges)
    total_possible = sum(int(c["base_points"]) for c in challenge_list if c.get("is_active", 1))

    per_team: dict[int, list[Solve]] = {t.id: [] for t in team_list}
    for s in solves:
        if s.disqualified:
            continue
        if s.team_id in per_team:
            per_team[s.team_id].append(s)
    for values in per_team.values():
        values.sort(key=lambda s: (_aware(s.solved_at), s.seq))

    adjustments = adjustments or {}
    first_blood_challenges = {s.challenge_id for values in per_team.values() for s in values if s.first_blood}

    raw_points: dict[int, int] = {}
    decayed: dict[int, float] = {}
    last_solve: dict[int, datetime | None] = {}
    solve_counts: dict[int, int] = {}
    unique_counts: dict[int, int] = {}
    contributions: dict[int, list[dict[str, Any]]] = {}

    for team in team_list:
        team_solves = per_team[team.id]
        solve_counts[team.id] = len(team_solves)
        unique_counts[team.id] = len({s.challenge_id for s in team_solves})
        if team_solves:
            last = max(_aware(s.solved_at) for s in team_solves)
            last_solve[team.id] = last
            reference = decay_reference(last, as_of, model.purifier_window_seconds)
            raw = 0
            total = 0.0
            contrib: list[dict[str, Any]] = []
            for s in team_solves:
                award, derivation = solve_award(model, s, is_top_n=False)
                raw += award
                factor = decay_factor(model, s.solved_at, reference)
                total += award * factor
                contrib.append(
                    {
                        "challenge_slug": s.challenge_slug,
                        "challenge_name": s.challenge_name,
                        "category": s.category,
                        "solved_at": _aware(s.solved_at).isoformat(),
                        "points": award,
                        "decay_factor": round(factor, 4),
                        "contribution": round(award * factor, 2),
                        "first_blood": s.first_blood,
                    }
                )
            raw += int(adjustments.get(team.id, 0))
            raw_points[team.id] = raw
            decayed[team.id] = total + int(adjustments.get(team.id, 0))
            contributions[team.id] = contrib
        else:
            last_solve[team.id] = None
            raw_points[team.id] = int(adjustments.get(team.id, 0))
            decayed[team.id] = float(adjustments.get(team.id, 0))
            contributions[team.id] = []

    names = {t.id: t.name for t in team_list}
    order = compute_rank_order(decayed, raw_points, last_solve, names)

    # Top-N bonus is applied after ordering so it cannot change the ordering.
    top_ids = set(order[: model.top_n])
    for team_id in top_ids:
        if solve_counts.get(team_id):
            decayed[team_id] += model.top_n_bonus
            raw_points[team_id] += model.top_n_bonus
    if top_ids:
        order = compute_rank_order(decayed, raw_points, last_solve, names)

    earlier = as_of - timedelta(minutes=5)
    ranked: list[TeamScore] = []
    for position, team_id in enumerate(order, start=1):
        team = next(t for t in team_list if t.id == team_id)
        now_score = decayed[team_id]
        past_score = _team_score_at(model, per_team[team_id], earlier) + int(adjustments.get(team_id, 0))
        if team_id in top_ids and solve_counts.get(team_id):
            past_score += model.top_n_bonus
        delta = now_score - past_score
        if delta > 0.5:
            trend = "rising"
        elif delta < -0.5:
            trend = "falling"
        else:
            trend = "steady"
        ranked.append(
            TeamScore(
                team=team,
                rank=position,
                previous_rank=None,
                raw_points=raw_points[team_id],
                decayed_points=now_score,
                solves=solve_counts[team_id],
                challenges_solved=unique_counts[team_id],
                total_possible=total_possible,
                last_solve_at=last_solve[team_id],
                trend=trend,
                contributions=contributions[team_id],
                delta=delta,
            )
        )

    totals = {
        "teams": len(team_list),
        "solves": sum(solve_counts.values()),
        "challenges": len(challenge_list),
        "active_challenges": sum(1 for c in challenge_list if c.get("is_active", 1)),
        "total_possible": total_possible,
        "points_awarded": sum(raw_points.values()),
        "first_bloods": len(first_blood_challenges),
        "model_fingerprint": model.fingerprint(),
    }

    state_hash = sha256_hex(
        canonical_json(
            {
                "event_slug": event_slug,
                "as_of_bucket": int(as_of.timestamp() // 5),
                "model": model.version,
                "teams": [
                    [t.team.id, round(t.decayed_points, 4), t.rank, t.solves] for t in ranked
                ],
            }
        )
    )

    return LeaderboardState(
        event_slug=event_slug,
        phase=phase,
        as_of=as_of,
        scoring_model_version=model.version,
        last_seq=last_seq,
        teams=ranked,
        totals=totals,
        state_hash=state_hash,
        frozen=phase in {"frozen", "ended"},
    )
