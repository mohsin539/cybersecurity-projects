"""SQLite data layer.

Single portable SQLite database with parameterised queries only
(OWASP A03 mitigation). Schema is created idempotently on first run.
"""

import sqlite3

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name  TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'examiner'
                  CHECK (role IN ('admin','examiner','auditor')),
    active        INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    last_login    TEXT
);

CREATE TABLE IF NOT EXISTS cases (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    case_ref     TEXT UNIQUE NOT NULL,
    title        TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'open'
                 CHECK (status IN ('open','active','closed','shelved')),
    severity     TEXT NOT NULL DEFAULT 'medium'
                 CHECK (severity IN ('low','medium','high','critical')),
    lead_examiner TEXT NOT NULL DEFAULT '',
    created_by   INTEGER REFERENCES users(id),
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
    closed_at    TEXT
);

CREATE TABLE IF NOT EXISTS evidence (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id          INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    device_serial    TEXT NOT NULL DEFAULT '',
    device_model     TEXT NOT NULL,
    manufacturer     TEXT NOT NULL DEFAULT '',
    os_type          TEXT NOT NULL DEFAULT '',
    imei             TEXT NOT NULL DEFAULT '',
    phone_number     TEXT NOT NULL DEFAULT '',
    carrier          TEXT NOT NULL DEFAULT '',
    acquisition_method TEXT NOT NULL DEFAULT 'logical'
                      CHECK (acquisition_method IN ('logical','physical','chip-off','cloud','manual')),
    acquired_by      TEXT NOT NULL DEFAULT '',
    acquired_at      TEXT NOT NULL DEFAULT (datetime('now')),
    location         TEXT NOT NULL DEFAULT '',
    storage_hash     TEXT NOT NULL DEFAULT '',
    sha1             TEXT NOT NULL DEFAULT '',
    sha256           TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL DEFAULT 'intake'
                     CHECK (status IN ('intake','acquired','analyzed','sealed','disposed')),
    custodian        TEXT NOT NULL DEFAULT '',
    notes            TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS custody_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id  INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    event_type   TEXT NOT NULL
                 CHECK (event_type IN ('INTAKE','CHECKOUT','TRANSFER','CHECKIN','SEAL','DESTRUCTION')),
    from_user    TEXT NOT NULL DEFAULT '',
    to_user      TEXT NOT NULL DEFAULT '',
    from_location TEXT NOT NULL DEFAULT '',
    to_location  TEXT NOT NULL DEFAULT '',
    notes        TEXT NOT NULL DEFAULT '',
    occurred_at  TEXT NOT NULL DEFAULT (datetime('now')),
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS artifacts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id    INTEGER NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    category       TEXT NOT NULL
                   CHECK (category IN ('call_log','sms','contact','geo','app','media','browser','account','crypto','other')),
    name           TEXT NOT NULL,
    detail         TEXT NOT NULL DEFAULT '',
    value          TEXT NOT NULL DEFAULT '',
    timestamp      TEXT,
    severity       TEXT NOT NULL DEFAULT 'info'
                   CHECK (severity IN ('blocker','critical','high','medium','low','info')),
    source_path    TEXT NOT NULL DEFAULT '',
    artifact_hash  TEXT NOT NULL DEFAULT '',
    created_by     INTEGER REFERENCES users(id),
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT NOT NULL,
    actor_id     TEXT NOT NULL,
    actor_role   TEXT NOT NULL,
    action       TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_id   TEXT,
    context      TEXT NOT NULL DEFAULT '{}',
    severity     TEXT NOT NULL DEFAULT 'info',
    prev_hash    TEXT NOT NULL,
    hash         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_custody_evidence ON custody_events(evidence_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_evidence ON artifacts(evidence_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app):
    app.teardown_appcontext(close_db)
    with app.app_context():
        db = get_db()
        db.executescript(SCHEMA)
        db.commit()

def query(sql, args=()):
    db = get_db()
    return db.execute(sql, args).fetchall()

def query_one(sql, args=()):
    db = get_db()
    return db.execute(sql, args).fetchone()

def execute(sql, args=()):
    db = get_db()
    cur = db.execute(sql, args)
    db.commit()
    return cur.lastrowid