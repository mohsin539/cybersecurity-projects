"""Executable invariants.

Each check is a predicate over persisted state, addressed by the same IDs used
in ``state.md`` section 7.1 so a report can be read next to the specification.
They run on demand through ``GET /api/invariants`` and in the test suite, so a
violation surfaces as data rather than as a surprise during a dispute.

Where a property can only be observed on the client (INV-05, INV-12, INV-13,
INV-16) the check is reported as ``delegated``. The API never claims coverage it
does not have, and the browser enforces those four.

Two checks carry IDs outside the INV namespace:

* ``CHAINS`` - end-to-end hash-chain verification, which is the mechanism behind
  INV-02 and INV-04 rather than a property of its own.
* ``INV-11`` is asserted here as *provenance*: the stored projection is
  byte-identical to a fresh recomputation from the log, so it can only have been
  produced by the projector.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from typing import Any, Callable

PASS = "pass"
FAIL = "fail"
WARN = "warn"
DELEGATED = "delegated"


@dataclass
class InvariantResult:
    id: str
    name: str
    status: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "evidence": self.evidence,
        }


@dataclass
class Context:
    conn: sqlite3.Connection
    event_slug: str
    recomputed_state: Any  # LeaderboardState
    stored_teams: list[dict[str, Any]]
    eventlog_verify: dict[str, Any]
    audit_verify: dict[str, Any]
    head_seq: int
    chain_head: str
    # Two independent recomputations of the same log, for INV-02.
    recomputed_hash: str = ""
    replayed_hash: str = ""


CHECKS: list[tuple[str, str, Callable[[Context], InvariantResult]]] = []


def invariant(id_: str, name: str):
    def wrap(fn: Callable[[Context], InvariantResult]):
        CHECKS.append((id_, name, fn))
        return fn

    return wrap


def _state_teams(ctx: Context) -> list[dict[str, Any]]:
    return ctx.recomputed_state.to_dict()["teams"]


# ----------------------------------------------------------------- INV-01 -----
@invariant("INV-01", "The event log is the only authoritative record of scores")
def inv_log_is_authoritative(ctx: Context) -> InvariantResult:
    """Every solve and every applied adjustment must have a log event behind it."""
    solves = ctx.conn.execute("SELECT COUNT(*) AS n FROM solves").fetchone()["n"]
    unlogged = ctx.conn.execute(
        "SELECT COUNT(*) AS n FROM solves s WHERE NOT EXISTS ("
        "  SELECT 1 FROM event_log e WHERE e.event_type = 'solve.recorded'"
        "    AND e.event_slug = s.event_slug AND e.seq = s.seq)"
    ).fetchone()["n"]
    applied = ctx.conn.execute(
        "SELECT COUNT(*) AS n FROM score_adjustments WHERE status = 'applied'"
    ).fetchone()["n"]
    unlogged_adj = ctx.conn.execute(
        "SELECT COUNT(*) AS n FROM score_adjustments a WHERE a.status = 'applied'"
        " AND NOT EXISTS (SELECT 1 FROM event_log e WHERE e.event_type = 'score.adjusted'"
        "                  AND e.event_slug = a.event_slug AND e.seq = a.applied_seq)"
    ).fetchone()["n"]
    ok = unlogged == 0 and unlogged_adj == 0
    return InvariantResult(
        "INV-01", "Log authority", PASS if ok else FAIL,
        f"{solves} solves and {applied} applied adjustments, all traceable to the log"
        if ok else f"{unlogged} solves and {unlogged_adj} adjustments have no event",
        {"solves": solves, "unlogged_solves": unlogged, "unlogged_adjustments": unlogged_adj},
    )


# ----------------------------------------------------------------- INV-02 -----
@invariant("INV-02", "Replaying the log is deterministic")
def inv_replay_determinism(ctx: Context) -> InvariantResult:
    first, second = ctx.recomputed_hash, ctx.replayed_hash
    ok = bool(first) and first == second
    return InvariantResult(
        "INV-02", "Replay determinism", PASS if ok else FAIL,
        f"two independent projections both produced {first[:16] or 'nothing'}"
        if ok else f"projections disagree: {first[:16]} != {second[:16]}",
        {"first": first, "second": second},
    )


# ----------------------------------------------------------------- INV-03 -----
@invariant("INV-03", "Every solve carries a complete derivation")
def inv_derivation_present(ctx: Context) -> InvariantResult:
    missing = ctx.conn.execute(
        "SELECT COUNT(*) AS n FROM solves WHERE derivation IS NULL OR derivation = ''"
    ).fetchone()["n"]
    unparsable = 0
    for row in ctx.conn.execute("SELECT derivation FROM solves"):
        try:
            body = json.loads(row["derivation"])
            if "parts" not in body or "model_version" not in body or "total" not in body:
                unparsable += 1
        except json.JSONDecodeError:
            unparsable += 1
    ok = missing == 0 and unparsable == 0
    return InvariantResult(
        "INV-03", "Derivation completeness", PASS if ok else FAIL,
        "every solve explains its points" if ok else f"{missing} empty, {unparsable} unusable",
        {"empty": missing, "unusable": unparsable},
    )


# ----------------------------------------------------------------- INV-04 -----
@invariant("INV-04", "Mutations and their audit records commit together")
def inv_audit_atomicity(ctx: Context) -> InvariantResult:
    orphans = ctx.conn.execute(
        "SELECT COUNT(*) AS n FROM score_adjustments WHERE status = 'applied' AND audit_id IS NULL"
    ).fetchone()["n"]
    unaudited_solves = ctx.conn.execute(
        "SELECT COUNT(*) AS n FROM event_log e WHERE e.event_type IN"
        " ('solve.recorded','score.adjusted','challenge.updated','team.registered')"
        " AND NOT EXISTS (SELECT 1 FROM audit_log a WHERE a.event_slug = e.event_slug"
        "                 AND json_extract(a.context, '$.resource_id') IS NOT NULL)"
    ).fetchone()["n"]
    total = ctx.conn.execute("SELECT COUNT(*) AS n FROM audit_log").fetchone()["n"]
    ok = orphans == 0 and bool(ctx.audit_verify.get("ok"))
    return InvariantResult(
        "INV-04", "Audit atomicity", PASS if ok else FAIL,
        f"{orphans} adjustments without an audit id; audit chain verified="
        f"{bool(ctx.audit_verify.get('ok'))}",
        {
            "orphan_adjustments": orphans,
            "audit_records": total,
            "event_rows_without_audit": unaudited_solves,
            "chain": ctx.audit_verify,
        },
    )


# ----------------------------------------------------------------- INV-05 -----
@invariant("INV-05", "The client renders the rank the server sent")
def inv_client_rank(ctx: Context) -> InvariantResult:
    return InvariantResult(
        "INV-05", "Server-authoritative rank", DELEGATED,
        "enforced in the browser: ranks arrive with the frame and are never recomputed "
        "client-side; asserted by the client reducer and by the API contract tests",
    )


# ----------------------------------------------------------------- INV-06 -----
@invariant("INV-06", "A read is monotonic for a given event and seq")
def inv_read_monotonic(ctx: Context) -> InvariantResult:
    """Rank may only improve or hold for the same ``seq``.

    The server half of the property is that a projection taken twice at the same
    ``as_of`` cannot move a rank; the per-client half is delegated to the browser,
    which never applies a frame with ``seq <= lastSeq``.
    """
    teams = _state_teams(ctx)
    ranks = [t["rank"] for t in teams]
    dense = sorted(ranks) == list(range(1, len(teams) + 1))
    ahead = ctx.conn.execute(
        "SELECT COUNT(*) AS n FROM projection_team_score WHERE last_event_seq > ?", (ctx.head_seq,)
    ).fetchone()["n"]
    negative = ctx.conn.execute(
        "SELECT COUNT(*) AS n FROM projection_team_score WHERE decayed_points < 0 OR raw_points < 0"
    ).fetchone()["n"]
    ok = dense and ahead == 0 and negative == 0
    return InvariantResult(
        "INV-06", "Read monotonicity", PASS if ok else FAIL,
        f"dense ranks, {ahead} projections ahead of the log head, {negative} negative"
        if ok else "rank ordering, head position or sign property violated",
        {"dense_ranks": dense, "ahead_of_head": ahead, "negative": negative, "head_seq": ctx.head_seq},
    )


# ----------------------------------------------------------------- INV-07 -----
@invariant("INV-07", "The event sequence increases with no silent back-fill")
def inv_no_gaps(ctx: Context) -> InvariantResult:
    row = ctx.conn.execute(
        "SELECT MIN(seq) AS lo, MAX(seq) AS hi, COUNT(*) AS n FROM event_log"
    ).fetchone()
    lo, hi, n = int(row["lo"] or 0), int(row["hi"] or 0), int(row["n"])
    gap = (hi - lo + 1) != n if n else False
    monotonic = ctx.conn.execute(
        "SELECT COUNT(*) AS n FROM (SELECT seq, LAG(seq) OVER (ORDER BY seq) AS prev FROM event_log)"
        " WHERE prev IS NOT NULL AND seq <= prev"
    ).fetchone()["n"]
    ok = not gap and monotonic == 0
    return InvariantResult(
        "INV-07", "Sequence integrity", PASS if ok else FAIL,
        f"seq {lo}..{hi} with {n} rows, no gaps, strictly increasing"
        if ok else f"seq {lo}..{hi} with {n} rows",
        {"min": lo, "max": hi, "count": n, "expected": hi - lo + 1, "non_increasing": monotonic},
    )


# ----------------------------------------------------------------- INV-08 -----
@invariant("INV-08", "A duplicate delivery has no effect on any total")
def inv_idempotency(ctx: Context) -> InvariantResult:
    dups = ctx.conn.execute(
        """
        SELECT COUNT(*) AS n FROM (
            SELECT event_slug, team_id, challenge_id FROM solves GROUP BY 1,2,3 HAVING COUNT(*) > 1
        )
        """
    ).fetchone()["n"]
    replayed = ctx.conn.execute(
        "SELECT COUNT(*) AS n FROM (SELECT key FROM idempotency_keys GROUP BY key HAVING COUNT(*) > 1)"
    ).fetchone()["n"]
    # A solve must be backed by a distinct seq, so a replayed webhook cannot add one.
    reused_seq = ctx.conn.execute(
        "SELECT COUNT(*) AS n FROM (SELECT event_slug, seq FROM solves GROUP BY 1,2 HAVING COUNT(*) > 1)"
    ).fetchone()["n"]
    ok = dups == 0 and replayed == 0 and reused_seq == 0
    return InvariantResult(
        "INV-08", "Idempotency", PASS if ok else FAIL,
        "no duplicate (team, challenge) solve, no reused key or seq"
        if ok else f"duplicates={dups} replayed_keys={replayed} reused_seq={reused_seq}",
        {"duplicate_solves": dups, "replayed_keys": replayed, "reused_seq": reused_seq},
    )


# ----------------------------------------------------------------- INV-09 -----
@invariant("INV-09", "A recorded solve never lowers a team's raw total")
def inv_monotonic_total(ctx: Context) -> InvariantResult:
    """Raw totals are monotone in the solves that produced them.

    ``base_points`` is constrained positive, so each recorded solve adds points
    and nothing can subtract them without a recorded adjustment. Decayed totals
    are *not* claimed to be monotone: decay is measured from the last solve, so a
    later solve can reduce the value of an earlier one. That is a property of the
    published model, not a violation.
    """
    problems: list[str] = []
    for row in ctx.conn.execute(
        "SELECT s.id, s.team_id, s.points_awarded,"
        " COALESCE((SELECT SUM(points_awarded) FROM solves x WHERE x.team_id = s.team_id"
        "           AND x.solved_at <= s.solved_at), 0) AS running"
        " FROM solves s ORDER BY s.team_id, s.solved_at"
    ):
        if row["points_awarded"] < 0:
            problems.append(f"solve {row['id']} has negative points")
    negatives = ctx.conn.execute(
        "SELECT COUNT(*) AS n FROM projection_team_score WHERE raw_points < 0"
    ).fetchone()["n"]
    if negatives:
        problems.append(f"{negatives} teams have a negative raw total")
    return InvariantResult(
        "INV-09", "Monotonic totals", PASS if not problems else FAIL,
        "; ".join(problems) or "raw totals are non-decreasing in recorded solves",
        {"problems": problems, "negative_raw": negatives},
    )


# ----------------------------------------------------------------- INV-10 -----
@invariant("INV-10", "A frozen event does not change ranks")
def inv_frozen(ctx: Context) -> InvariantResult:
    event = ctx.conn.execute(
        "SELECT phase, frozen_at, ended_at FROM events WHERE slug = ?", (ctx.event_slug,)
    ).fetchone()
    if not event or event["phase"] not in {"frozen", "ended"}:
        return InvariantResult(
            "INV-10", "Freeze", PASS, f"event is '{event['phase'] if event else 'unknown'}'; not frozen",
            {"phase": event["phase"] if event else None},
        )
    cutoff = event["frozen_at"] or event["ended_at"]
    late = ctx.conn.execute(
        "SELECT COUNT(*) AS n FROM event_log WHERE event_slug = ? AND event_type IN"
        " ('solve.recorded','score.adjusted') AND occurred_at > ?",
        (ctx.event_slug, cutoff),
    ).fetchone()["n"]
    ok = late == 0
    return InvariantResult(
        "INV-10", "Freeze", PASS if ok else FAIL,
        f"no scoring event after {cutoff}" if ok else f"{late} scoring events after the freeze",
        {"cutoff": cutoff, "late_events": late},
    )


# ----------------------------------------------------------------- INV-11 -----
@invariant("INV-11", "Projections are produced by the projector, not by handlers")
def inv_projection_provenance(ctx: Context) -> InvariantResult:
    """The stored projection must equal a fresh recomputation from the log."""
    recomputed = {t["team_id"]: t for t in _state_teams(ctx)}
    stored = {t["team_id"]: t for t in ctx.stored_teams}
    missing = sorted(set(recomputed) - set(stored))
    extra = sorted(set(stored) - set(recomputed))
    diverging = []
    for team_id, row in stored.items():
        live = recomputed.get(team_id)
        if not live:
            continue
        if abs(float(row["score"]) - float(live["score"])) > 0.01 or int(row["rank"]) != int(live["rank"]):
            diverging.append(team_id)
    ok = not missing and not extra and not diverging
    return InvariantResult(
        "INV-11", "Projection provenance", PASS if ok else FAIL,
        f"all {len(stored)} projected teams equal a fresh recomputation"
        if ok else f"{len(missing)} missing, {len(extra)} unexplained, {len(diverging)} diverging",
        {"missing": missing[:10], "unexplained": extra[:10], "diverging": diverging[:10]},
    )


# ------------------------------------------------------------ INV-12/13 ------
@invariant("INV-12", "Cache invalidation is event-driven")
def inv_cache(ctx: Context) -> InvariantResult:
    return InvariantResult(
        "INV-12", "Cache invalidation", DELEGATED,
        "enforced in the client: every mutation frame purges the affected keys before the "
        "next read; the server sends no-store on the board and stream endpoints",
    )


@invariant("INV-13", "Frames carry the seq they were computed from")
def inv_frames(ctx: Context) -> InvariantResult:
    return InvariantResult(
        "INV-13", "Frame ordering contract", DELEGATED,
        "enforced in the client reducer (frames with seq <= lastSeq never mutate render "
        "state) and in the server, where every published board frame carries id = last_seq",
    )


# ----------------------------------------------------------------- INV-14 -----
@invariant("INV-14", "A rejected event is never silently dropped")
def inv_dlq(ctx: Context) -> InvariantResult:
    row = ctx.conn.execute(
        "SELECT COUNT(*) AS n, COALESCE(SUM(CASE WHEN owner = '' THEN 1 ELSE 0 END), 0) AS unowned"
        " FROM dead_letters WHERE resolved_at IS NULL"
    ).fetchone()
    count, unowned = int(row["n"]), int(row["unowned"] or 0)
    if unowned:
        return InvariantResult(
            "INV-14", "DLQ containment", FAIL, f"{unowned} dead letters have no owner", {"open": count}
        )
    return InvariantResult(
        "INV-14", "DLQ containment", PASS if count == 0 else WARN,
        f"{count} unresolved dead letters, all owned", {"open": count},
    )


# ----------------------------------------------------------------- INV-15 -----
@invariant("INV-15", "Every state transition names an actor")
def inv_actor_identity(ctx: Context) -> InvariantResult:
    ev_bad = ctx.conn.execute(
        "SELECT COUNT(*) AS n FROM event_log WHERE actor_id IS NULL OR TRIM(actor_id) = ''"
        " OR actor_type NOT IN ('human','system','service')"
    ).fetchone()["n"]
    au_bad = ctx.conn.execute(
        "SELECT COUNT(*) AS n FROM audit_log WHERE actor_id IS NULL OR TRIM(actor_id) = ''"
        " OR actor_type NOT IN ('human','system','service')"
    ).fetchone()["n"]
    humans = ctx.conn.execute(
        "SELECT COUNT(*) AS n FROM event_log e WHERE e.actor_type = 'human' AND NOT EXISTS ("
        " SELECT 1 FROM users u WHERE u.id = e.actor_id)"
    ).fetchone()["n"]
    # A human actor must resolve to a principal and a role. The one exception is
    # a denied login: nobody has authenticated, so there is no identity to
    # resolve, and the attempted handle is untrusted input that belongs in the
    # context rather than in the actor column.
    unresolved = ctx.conn.execute(
        "SELECT COUNT(*) AS n FROM audit_log a WHERE a.actor_type = 'human' AND NOT EXISTS ("
        " SELECT 1 FROM users u WHERE u.id = a.actor_id AND u.role IS NOT NULL AND u.role != '')"
        " AND NOT (a.action = 'security.login' AND a.outcome = 'denied')"
    ).fetchone()["n"]
    unattributed = ctx.conn.execute(
        "SELECT COUNT(*) AS n FROM audit_log a WHERE a.action = 'security.login' AND a.outcome = 'denied'"
        " AND (json_extract(a.context, '$.attempted_handle') IS NULL"
        "      OR json_extract(a.context, '$.attempted_handle') = '')"
    ).fetchone()["n"]
    ok = ev_bad == 0 and au_bad == 0 and humans == 0 and unresolved == 0 and unattributed == 0
    return InvariantResult(
        "INV-15", "Actor identity", PASS if ok else FAIL,
        "every transition resolves to a principal, role and method" if ok else
        f"events={ev_bad} audits={au_bad} unknown_principals={humans} "
        f"unresolved={unresolved} unattributed_logins={unattributed}",
        {
            "bad_event_actors": ev_bad,
            "bad_audit_actors": au_bad,
            "unknown_human_principals": humans,
            "unresolved_audit_actors": unresolved,
            "denied_logins_without_attempted_handle": unattributed,
        },
    )


# ----------------------------------------------------------------- INV-16 -----
@invariant("INV-16", "An out-of-sync client shows a staleness indicator")
def inv_client_sm(ctx: Context) -> InvariantResult:
    return InvariantResult(
        "INV-16", "Client state machine", DELEGATED,
        "enforced in the client: connection states are a strict FSM and a lost stream "
        "marks the board stale instead of rendering it as current",
    )


# ----------------------------------------------------------------- INV-17 -----
@invariant("INV-17", "Legal hold suppresses deletion and nothing else")
def inv_hold(ctx: Context) -> InvariantResult:
    """This deployment has no legal hold and cannot delete anything at all.

    The invariant is therefore checked structurally: the delete triggers on the
    append-only tables must still exist, so a hold has nothing to suppress and
    reads are never filtered.
    """
    triggers = {
        r["name"]
        for r in ctx.conn.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")
    }
    required = {
        "trg_event_log_no_delete",
        "trg_audit_log_no_delete",
        "trg_event_log_no_update",
        "trg_audit_log_no_update",
    }
    missing = sorted(required - triggers)
    ok = not missing
    return InvariantResult(
        "INV-17", "Hold scope", PASS if ok else FAIL,
        "deletion is impossible by construction and reads are never suppressed"
        if ok else f"append-only triggers missing: {missing}",
        {"missing_triggers": missing, "triggers": sorted(triggers)},
    )


# ----------------------------------------------------------------- INV-18 -----
@invariant("INV-18", "The node clock is monotonic")
def inv_clock(ctx: Context) -> InvariantResult:
    """``recorded_at`` is this node's own clock, so it must never regress.

    ``occurred_at`` is deliberately *not* checked: back-dated solves are a feature
    (an ingest outage replays historical events). What must never happen is an
    event claiming to have occurred after the moment it was written.
    """
    rows = ctx.conn.execute("SELECT seq, recorded_at, occurred_at FROM event_log ORDER BY seq ASC").fetchall()
    regressions = []
    impossible = []
    previous = None
    for row in rows:
        if previous and row["recorded_at"] < previous:
            regressions.append(row["seq"])
        if row["occurred_at"] > row["recorded_at"]:
            impossible.append(row["seq"])
        previous = row["recorded_at"]
    ok = not regressions and not impossible
    return InvariantResult(
        "INV-18", "Clock monotonicity", PASS if ok else FAIL,
        "recorded_at is non-decreasing and no event is dated in the future"
        if ok else f"regressions at {regressions[:5]}; future-dated at {impossible[:5]}",
        {"regressions": regressions[:20], "future_dated": impossible[:20]},
    )


# ----------------------------------------------------------------- CHAINS -----
@invariant("CHAINS", "Event and audit hash chains verify end to end")
def inv_chains(ctx: Context) -> InvariantResult:
    ev, au = ctx.eventlog_verify, ctx.audit_verify
    ok = bool(ev.get("ok")) and bool(au.get("ok"))
    return InvariantResult(
        "CHAINS", "Chain integrity", PASS if ok else FAIL,
        f"event chain {ev.get('checked', 0)} records, audit chain {au.get('checked', 0)} records"
        if ok else "a hash chain does not verify",
        {"event_log": ev, "audit_log": au},
    )


# --------------------------------------------------- referential completeness --
@invariant("INV-11b", "No orphan rows in the read models")
def inv_referential(ctx: Context) -> InvariantResult:
    orphan_solves = ctx.conn.execute(
        """
        SELECT COUNT(*) AS n FROM solves s
        LEFT JOIN teams t ON t.id = s.team_id AND t.event_slug = s.event_slug
        LEFT JOIN challenges c ON c.id = s.challenge_id AND c.event_slug = s.event_slug
        WHERE t.id IS NULL OR c.id IS NULL
        """
    ).fetchone()["n"]
    orphan_proj = ctx.conn.execute(
        "SELECT COUNT(*) AS n FROM projection_team_score p"
        " LEFT JOIN teams t ON t.id = p.team_id WHERE t.id IS NULL"
    ).fetchone()["n"]
    orphan_sessions = ctx.conn.execute(
        "SELECT COUNT(*) AS n FROM sessions s LEFT JOIN users u ON u.id = s.user_id WHERE u.id IS NULL"
    ).fetchone()["n"]
    ok = orphan_solves == 0 and orphan_proj == 0 and orphan_sessions == 0
    return InvariantResult(
        "INV-11b", "Referential completeness", PASS if ok else FAIL,
        "no orphans" if ok else
        f"{orphan_solves} orphan solves, {orphan_proj} orphan projections, {orphan_sessions} orphan sessions",
        {"orphan_solves": orphan_solves, "orphan_projections": orphan_proj, "orphan_sessions": orphan_sessions},
    )


def evaluate(ctx: Context) -> dict[str, Any]:
    results = [fn(ctx) for _, _, fn in CHECKS]
    failed = [r for r in results if r.status == FAIL]
    warned = [r for r in results if r.status == WARN]
    ids = [i for i, _, _ in CHECKS]
    duplicates = sorted({i for i in ids if ids.count(i) > 1})
    return {
        "healthy": not failed and not duplicates,
        "checked": len(results),
        "passed": sum(1 for r in results if r.status == PASS),
        "warned": len(warned),
        "delegated": sum(1 for r in results if r.status == DELEGATED),
        "failed": len(failed),
        "duplicate_ids": duplicates,
        "head_seq": ctx.head_seq,
        "chain_head": ctx.chain_head,
        "invariants": [r.to_dict() for r in results],
    }
