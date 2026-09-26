"""SQLite storage layer.

The production target in ``architecture.md`` is PostgreSQL 16. This deployment
uses SQLite so the scoreboard runs with a single command and no external
services, while preserving the properties the rest of the system depends on:

* ``WAL`` journaling and ``synchronous=FULL`` so an acknowledged write is durable
  (memory.md DL-01).
* Foreign keys enforced, so referential completeness is a database guarantee
  rather than an application convention (INV-01).
* ``audit_log`` and ``event_log`` are append-only *at the storage layer*: triggers
  reject ``UPDATE`` and ``DELETE`` from every role, including ours
  (SEC-AUD-03, INV-04). The only exception is stamping a Merkle seal root.
* Check constraints encode the scoring invariants that must never be violated
  even by a direct SQL client.
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

SCHEMA_VERSION = 3

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- ---------------------------------------------------------------- event log --
-- Append-only, hash chained (SEC-AUD-04). This is the only authoritative record.
CREATE TABLE IF NOT EXISTS event_log (
    seq              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id         TEXT    NOT NULL UNIQUE,
    event_slug       TEXT    NOT NULL,
    event_type       TEXT    NOT NULL,
    schema_version   INTEGER NOT NULL DEFAULT 1,
    occurred_at      TEXT    NOT NULL,
    recorded_at      TEXT    NOT NULL,
    actor_type       TEXT    NOT NULL,
    actor_id         TEXT    NOT NULL,
    payload          TEXT    NOT NULL,
    prev_hash        TEXT    NOT NULL,
    hash             TEXT    NOT NULL,
    sealed_root      TEXT,
    CHECK (length(hash) = 64),
    CHECK (length(prev_hash) = 64)
);
CREATE INDEX IF NOT EXISTS idx_event_log_slug_seq ON event_log (event_slug, seq);
CREATE INDEX IF NOT EXISTS idx_event_log_type ON event_log (event_type, seq);
CREATE INDEX IF NOT EXISTS idx_event_log_unsealed ON event_log (seq) WHERE sealed_root IS NULL;

-- Merkle checkpoints sealed to "immutable" storage (SEC-AUD-05).
CREATE TABLE IF NOT EXISTS event_seal (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    event_slug    TEXT    NOT NULL,
    from_seq      INTEGER NOT NULL,
    to_seq        INTEGER NOT NULL,
    event_count   INTEGER NOT NULL,
    merkle_root   TEXT    NOT NULL,
    prev_root     TEXT    NOT NULL,
    signature     TEXT,
    anchored_at   TEXT,
    created_at    TEXT    NOT NULL,
    CHECK (from_seq = to_seq - event_count + 1)
);

-- ------------------------------------------------------------------- audit --
CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at   TEXT    NOT NULL,
    actor_type    TEXT    NOT NULL,
    actor_id      TEXT    NOT NULL,
    action        TEXT    NOT NULL,
    resource_type TEXT    NOT NULL,
    resource_id   TEXT,
    outcome       TEXT    NOT NULL CHECK (outcome IN ('success', 'denied', 'failure')),
    severity      TEXT    NOT NULL CHECK (severity IN ('info', 'notice', 'warning', 'critical')),
    event_slug    TEXT,
    context       TEXT    NOT NULL DEFAULT '{}',
    prev_hash     TEXT    NOT NULL,
    hash          TEXT    NOT NULL,
    CHECK (length(hash) = 64),
    CHECK (length(prev_hash) = 64)
);
CREATE INDEX IF NOT EXISTS idx_audit_slug ON audit_log (event_slug, id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log (action, id);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log (actor_id, id);

-- ------------------------------------------------------------- competition --
CREATE TABLE IF NOT EXISTS events (
    slug        TEXT PRIMARY KEY,
    name        TEXT    NOT NULL,
    starts_at   TEXT    NOT NULL,
    ends_at     TEXT,
    phase       TEXT    NOT NULL CHECK (phase IN ('setup', 'live', 'frozen', 'ended')),
    scoring_model_version TEXT NOT NULL,
    frozen_at   TEXT,
    ended_at    TEXT,
    created_at  TEXT    NOT NULL,
    CHECK (phase IN ('setup', 'live', 'frozen', 'ended'))
);

CREATE TABLE IF NOT EXISTS categories (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    slug  TEXT NOT NULL UNIQUE,
    name  TEXT NOT NULL,
    color TEXT NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS challenges (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    event_slug    TEXT    NOT NULL REFERENCES events(slug) ON DELETE RESTRICT,
    slug          TEXT    NOT NULL,
    name          TEXT    NOT NULL,
    category_id   INTEGER NOT NULL REFERENCES categories(id) ON DELETE RESTRICT,
    base_points   INTEGER NOT NULL CHECK (base_points > 0),
    author        TEXT,
    is_active     INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
    created_at    TEXT    NOT NULL,
    UNIQUE (event_slug, slug)
);
CREATE INDEX IF NOT EXISTS idx_challenges_event ON challenges (event_slug, is_active);

CREATE TABLE IF NOT EXISTS teams (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_slug  TEXT    NOT NULL REFERENCES events(slug) ON DELETE RESTRICT,
    slug        TEXT    NOT NULL,
    name        TEXT    NOT NULL,
    country     TEXT,
    accent      TEXT    NOT NULL DEFAULT '#6C5CE7',
    seed        INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL,
    UNIQUE (event_slug, slug)
);
CREATE INDEX IF NOT EXISTS idx_teams_event ON teams (event_slug);

CREATE TABLE IF NOT EXISTS team_members (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id   INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    handle    TEXT    NOT NULL,
    role      TEXT    NOT NULL CHECK (role IN ('captain', 'member')),
    UNIQUE (team_id, handle)
);

-- ------------------------------------------------------------------ solves --
CREATE TABLE IF NOT EXISTS solves (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  event_slug     TEXT    NOT NULL,
  seq            INTEGER NOT NULL,
  team_id        INTEGER NOT NULL REFERENCES teams(id) ON DELETE RESTRICT,
  challenge_id   INTEGER NOT NULL REFERENCES challenges(id) ON DELETE RESTRICT,
  solved_at      TEXT    NOT NULL,
  base_points    INTEGER NOT NULL DEFAULT 0 CHECK (base_points >= 0),
  points_awarded INTEGER NOT NULL CHECK (points_awarded >= 0),
  first_blood    INTEGER NOT NULL DEFAULT 0 CHECK (first_blood IN (0, 1)),
  derivation     TEXT    NOT NULL,
  scoring_model_version TEXT NOT NULL,
  UNIQUE (event_slug, team_id, challenge_id),
  UNIQUE (event_slug, seq)
);
CREATE INDEX IF NOT EXISTS idx_solves_team ON solves (event_slug, team_id);
CREATE INDEX IF NOT EXISTS idx_solves_challenge ON solves (event_slug, challenge_id);

-- Two-person rule: a manual adjustment is proposed by one human and approved by
-- another. The database refuses to close an adjustment without an approver
-- (SEC-AUTH-07, INV-11).
CREATE TABLE IF NOT EXISTS score_adjustments (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    event_slug     TEXT    NOT NULL REFERENCES events(slug) ON DELETE RESTRICT,
    team_id        INTEGER NOT NULL REFERENCES teams(id) ON DELETE RESTRICT,
    delta          INTEGER NOT NULL CHECK (delta != 0),
    reason         TEXT    NOT NULL CHECK (length(reason) >= 10),
    status         TEXT    NOT NULL CHECK (status IN ('pending', 'approved', 'applied', 'rejected')),
    proposed_by    TEXT    NOT NULL,
    proposed_at    TEXT    NOT NULL,
    approved_by    TEXT,
    approved_at    TEXT,
    applied_seq    INTEGER,
    audit_id       INTEGER,
    CHECK (status <> 'applied' OR (approved_by IS NOT NULL AND applied_seq IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_adjustments_event ON score_adjustments (event_slug, status);

-- ------------------------------------------------------------- projections --
-- Rebuildable read models. Never written by a request handler (state.md INV-01);
-- only the projector touches these tables, from the event log alone.
CREATE TABLE IF NOT EXISTS projection_team_score (
    event_slug   TEXT    NOT NULL,
    team_id      INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    raw_points   INTEGER NOT NULL DEFAULT 0,
    decayed_points REAL   NOT NULL DEFAULT 0,
    solves_count INTEGER NOT NULL DEFAULT 0,
    rank         INTEGER NOT NULL DEFAULT 0,
    last_solve_at TEXT,
    last_event_seq INTEGER NOT NULL DEFAULT 0,
    trend        TEXT    NOT NULL DEFAULT 'steady' CHECK (trend IN ('rising', 'steady', 'falling')),
    PRIMARY KEY (event_slug, team_id),
    CHECK (raw_points >= 0),
    CHECK (rank >= 0)
);
CREATE INDEX IF NOT EXISTS idx_pts_rank ON projection_team_score (event_slug, rank);

CREATE TABLE IF NOT EXISTS projection_rank_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_slug  TEXT    NOT NULL,
    team_id     INTEGER NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    rank        INTEGER NOT NULL,
    score       REAL    NOT NULL,
    recorded_at TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rankhist ON projection_rank_history (event_slug, team_id, id);

CREATE TABLE IF NOT EXISTS projection_state (
    event_slug     TEXT PRIMARY KEY,
    last_seq       INTEGER NOT NULL DEFAULT 0,
    projected_at   TEXT    NOT NULL,
    scoring_model_version TEXT NOT NULL,
    state_hash     TEXT    NOT NULL,
    healthy        INTEGER NOT NULL DEFAULT 1 CHECK (healthy IN (0, 1))
);

-- ------------------------------------------------------------- idempotency --
CREATE TABLE IF NOT EXISTS idempotency_keys (
    key           TEXT PRIMARY KEY,
    event_slug    TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    response      TEXT NOT NULL
);

-- ---------------------------------------------------------------- security --
CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    handle        TEXT    NOT NULL UNIQUE,
    display_name  TEXT    NOT NULL,
    role          TEXT    NOT NULL CHECK (role IN ('spectator', 'participant', 'referee', 'admin')),
    password_hash TEXT    NOT NULL,
    password_salt TEXT    NOT NULL,
    created_at    TEXT    NOT NULL,
    disabled      INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1))
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    step_up_at  TEXT,
    mfa_verified INTEGER NOT NULL DEFAULT 0 CHECK (mfa_verified IN (0, 1)),
    user_agent  TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions (user_id);

CREATE TABLE IF NOT EXISTS webhook_clients (
    client_id   TEXT PRIMARY KEY,
    label       TEXT NOT NULL,
    key_id      TEXT NOT NULL,
    key_secret  TEXT NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_at  TEXT NOT NULL
);

-- Dead letter queue for poison events (T-DER-12).
CREATE TABLE IF NOT EXISTS dead_letters (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at TEXT NOT NULL,
    source      TEXT NOT NULL,
    reason      TEXT NOT NULL,
    payload     TEXT NOT NULL,
    owner       TEXT NOT NULL,
    resolved_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_dead_letters_open ON dead_letters (resolved_at) WHERE resolved_at IS NULL;

-- --------------------------------------------------------------- integrity --
-- Storage-layer immutability. These triggers are the reason a compromised
-- application role still cannot rewrite history (SEC-AUD-03).
-- The *content* of an event is immutable. The single permitted mutation is
-- stamping `sealed_root` onto unsealed rows when a Merkle checkpoint is written
-- (NULL -> a value, every other column byte-identical). Without that carve-out
-- sealing could never happen, and without the carve-out an attacker with the
-- application role could rewrite history: both properties are asserted by
-- tests/test_eventlog.py.
CREATE TRIGGER IF NOT EXISTS trg_event_log_no_update
BEFORE UPDATE ON event_log
WHEN NOT (
       OLD.sealed_root IS NULL
   AND NEW.sealed_root IS NOT NULL
   AND NEW.seq            IS OLD.seq
   AND NEW.event_id       IS OLD.event_id
   AND NEW.event_slug     IS OLD.event_slug
   AND NEW.event_type     IS OLD.event_type
   AND NEW.schema_version IS OLD.schema_version
   AND NEW.occurred_at    IS OLD.occurred_at
   AND NEW.recorded_at    IS OLD.recorded_at
   AND NEW.actor_type     IS OLD.actor_type
   AND NEW.actor_id       IS OLD.actor_id
   AND NEW.payload        IS OLD.payload
   AND NEW.prev_hash      IS OLD.prev_hash
   AND NEW.hash           IS OLD.hash
)
BEGIN
    SELECT RAISE(ABORT, 'event_log is append-only: UPDATE is prohibited (SEC-AUD-03)');
END;

CREATE TRIGGER IF NOT EXISTS trg_event_log_no_delete
BEFORE DELETE ON event_log
BEGIN
    SELECT RAISE(ABORT, 'event_log is append-only: DELETE is prohibited (SEC-AUD-03)');
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE is prohibited (SEC-AUD-03)');
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log is append-only: DELETE is prohibited (SEC-AUD-03)');
END;

CREATE TRIGGER IF NOT EXISTS trg_event_seal_no_update
BEFORE UPDATE ON event_seal
WHEN OLD.anchored_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'anchored seals are immutable (SEC-AUD-06)');
END;

-- A solve must reference a challenge in the same event as its team, and its
-- derivation must be present. Enforced here so even a buggy projector cannot
-- create a score that the log cannot explain.
CREATE TRIGGER IF NOT EXISTS trg_solves_consistency
BEFORE INSERT ON solves
WHEN NEW.derivation IS NULL OR NEW.derivation = ''
     OR (SELECT event_slug FROM teams WHERE id = NEW.team_id) <> NEW.event_slug
     OR (SELECT event_slug FROM challenges WHERE id = NEW.challenge_id) <> NEW.event_slug
BEGIN
    SELECT RAISE(ABORT, 'solve violates referential/event consistency (SEC-AUD-02)');
END;
"""


class Database:
    """Thread-safe connection factory.

    SQLite connections are not shareable across threads, so each unit of work
    takes its own connection from a small pool guarded by a lock. Writes are
    serialised, which is also what makes the hash chain deterministic.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self._local = threading.local()
        self._write_lock = threading.RLock()
        self._all: list[sqlite3.Connection] = []
        self._all_lock = threading.Lock()
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------- lifecycle --
    def connect(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(
                str(self.path),
                timeout=15.0,
                isolation_level=None,  # explicit transaction control
                check_same_thread=False,
            )
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = FULL")
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA busy_timeout = 15000")
            self._local.conn = conn
            with self._all_lock:
                self._all.append(conn)
        return conn

    def close_thread_connection(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None
            with self._all_lock:
                if conn in self._all:
                    self._all.remove(conn)

    def close(self) -> None:
        with self._all_lock:
            for conn in self._all:
                try:
                    conn.close()
                except sqlite3.Error:
                    pass
            self._all.clear()
        self._local = threading.local()

    # ----------------------------------------------------------- transactions --
    @contextmanager
    def read(self) -> Iterator[sqlite3.Connection]:
        yield self.connect()

    @contextmanager
    def write(self) -> Iterator[sqlite3.Connection]:
        """Serialised IMMEDIATE transaction.

        The event append, the audit insert and the idempotency record all commit
        together or not at all (SEC-AUD-02, INV-04).
        """
        conn = self.connect()
        with self._write_lock:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            else:
                conn.execute("COMMIT")

    # ------------------------------------------------------------------ setup --
    def columns(self, table: str) -> set[str]:
        return {r[1] for r in self.connect().execute(f"PRAGMA table_info({table})")}

    def initialise(self) -> None:
        conn = self.connect()
        conn.executescript(SCHEMA)
        # Idempotent migration: a solve must snapshot the base points it was
        # scored against, otherwise a later challenge re-pricing would rewrite
        # history and the projection could not reproduce the award.
        if "base_points" not in self.columns("solves"):
            conn.execute("ALTER TABLE solves ADD COLUMN base_points INTEGER NOT NULL DEFAULT 0")
        conn.execute(
            "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (str(SCHEMA_VERSION),),
        )

    def backfill_solve_base_points(self, first_blood_bonus: int) -> int:
        """Recover base points for rows written before the column existed.

        ``points_awarded == base + (first_blood * bonus)`` holds for every row
        the service has ever written, so the reconstruction is exact.
        """
        conn = self.connect()
        done = conn.execute(
            "SELECT value FROM schema_meta WHERE key = 'solves_base_points_backfilled'"
        ).fetchone()
        if done and done["value"] == str(first_blood_bonus):
            return 0
        cur = conn.execute(
            "UPDATE solves SET base_points = MAX(points_awarded - (first_blood * ?), 0) "
            "WHERE base_points <> MAX(points_awarded - (first_blood * ?), 0)",
            (first_blood_bonus, first_blood_bonus),
        )
        conn.execute(
            "INSERT INTO schema_meta (key, value) VALUES ('solves_base_points_backfilled', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (str(first_blood_bonus),),
        )
        return cur.rowcount

    def is_empty(self) -> bool:
        row = self.connect().execute("SELECT COUNT(*) AS n FROM events").fetchone()
        return bool(row and row["n"] == 0)


_db: Database | None = None


def get_db() -> Database:
    if _db is None:  # pragma: no cover - configured during startup
        raise RuntimeError("Database has not been initialised; call init_db() during startup.")
    return _db


def init_db(path: Path | str) -> Database:
    global _db
    _db = Database(path)
    _db.initialise()
    return _db


def reset_db() -> None:  # pragma: no cover - used by tests
    global _db
    if _db is not None:
        _db.close()
    _db = None
