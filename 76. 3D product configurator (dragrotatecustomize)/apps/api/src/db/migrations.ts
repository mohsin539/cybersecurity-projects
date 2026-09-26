/**
 * Schema migrations - append-only, forward only.
 *
 * Every migration is idempotent at the bookkeeping layer (`schema_migrations`)
 * and every table is created with the constraints that make the audit story
 * defensible:
 *   - `audit_log` is append-only (enforced by triggers that reject UPDATE/DELETE)
 *   - a monotonic `seq` gives a total order for the hash chain
 *   - `prev_hash` / `entry_hash` bind each record to the one before it
 */

import { getDb, run } from './driver.js';
import { logger } from '../config/logger.js';

export interface Migration {
  version: number;
  name: string;
  sql: string;
}

const V1_CORE = `
-- ---------------------------------------------------------------------------
-- Identity & access  (ISO/IEC 27001 A.5.16, A.5.17, A.5.18, A.8.2, A.8.5)
-- ---------------------------------------------------------------------------
CREATE TABLE users (
  id                 TEXT PRIMARY KEY,
  email              TEXT NOT NULL UNIQUE,
  email_hash         TEXT NOT NULL,              -- HMAC of lower(email) for case-insensitive lookup w/o storing plaintext
  display_name       TEXT NOT NULL DEFAULT '',
  role               TEXT NOT NULL CHECK (role IN ('viewer','configurator','auditor','security_officer','admin')),
  password_hash      TEXT NOT NULL,
  password_updated_at TEXT,
  must_change_password INTEGER NOT NULL DEFAULT 0,
  is_active          INTEGER NOT NULL DEFAULT 1,
  failed_attempts    INTEGER NOT NULL DEFAULT 0,
  locked_until       TEXT,
  last_login_at      TEXT,
  last_login_ip_fp   TEXT,
  mfa_secret_enc     TEXT,                       -- sealed with AES-256-GCM
  mfa_label          TEXT,
  mfa_enrolled_at    TEXT,
  created_at         TEXT NOT NULL,
  updated_at         TEXT NOT NULL,
  created_by         TEXT,
  CHECK (length(email) BETWEEN 3 AND 254),
  CHECK (length(password_hash) >= 40)
);
CREATE INDEX idx_users_email_hash ON users(email_hash);
CREATE INDEX idx_users_role ON users(role, is_active);

-- Refresh-token families. Enables rotation + reuse detection (OWASP A07:2021).
CREATE TABLE sessions (
  id                TEXT PRIMARY KEY,
  user_id           TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  family_id         TEXT NOT NULL,
  token_hash        TEXT NOT NULL UNIQUE,       -- SHA-256 of the token; the token itself is never stored
  device_label      TEXT,
  device_fp         TEXT,
  ip_fp             TEXT,
  user_agent        TEXT,
  issued_at         TEXT NOT NULL,
  expires_at        TEXT NOT NULL,
  absolute_expires_at TEXT NOT NULL,
  rotated_at        TEXT,
  revoked_at        TEXT,
  revoked_reason    TEXT,
  created_at        TEXT NOT NULL
);
CREATE INDEX idx_sessions_user ON sessions(user_id, revoked_at);
CREATE INDEX idx_sessions_family ON sessions(family_id);
CREATE INDEX idx_sessions_expiry ON sessions(expires_at);

-- Authentication attempts (feeds A.5.17 lockout + brute-force analytics).
CREATE TABLE login_attempts (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  email_hash    TEXT NOT NULL,
  user_id       TEXT,
  outcome       TEXT NOT NULL CHECK (outcome IN ('SUCCESS','FAILURE','DENIED')),
  reason        TEXT,
  ip_fp         TEXT,
  user_agent    TEXT,
  occurred_at   TEXT NOT NULL
);
CREATE INDEX idx_attempts_email_time ON login_attempts(email_hash, occurred_at DESC);
CREATE INDEX idx_attempts_time ON login_attempts(occurred_at DESC);

-- ---------------------------------------------------------------------------
-- Domain data
-- ---------------------------------------------------------------------------
CREATE TABLE configurations (
  id             TEXT PRIMARY KEY,
  public_id      TEXT NOT NULL UNIQUE,
  version        INTEGER NOT NULL DEFAULT 1,
  name           TEXT NOT NULL,
  product_id     TEXT NOT NULL,
  owner_id       TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  spec_enc       TEXT NOT NULL,                 -- AES-256-GCM sealed ConfigurationSpec
  price_enc      TEXT NOT NULL,                 -- sealed PriceBreakdown (authoritative)
  fingerprint    TEXT NOT NULL,                 -- plaintext digest for dedupe/lookup
  quantity       INTEGER NOT NULL DEFAULT 1,
  total_minor    INTEGER NOT NULL DEFAULT 0,
  currency       TEXT NOT NULL DEFAULT 'USD',
  status         TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','quoted','ordered','archived')),
  notes          TEXT NOT NULL DEFAULT '',
  created_at     TEXT NOT NULL,
  updated_at     TEXT NOT NULL,
  deleted_at     TEXT
);
CREATE INDEX idx_config_owner ON configurations(owner_id, created_at DESC);
CREATE INDEX idx_config_status ON configurations(status, created_at DESC);
CREATE INDEX idx_config_product ON configurations(product_id, created_at DESC);
CREATE INDEX idx_config_fingerprint ON configurations(fingerprint);

-- Opaque, revocable read-only share links (A.5.15 access control).
CREATE TABLE configuration_shares (
  id          TEXT PRIMARY KEY,
  config_id   TEXT NOT NULL REFERENCES configurations(id) ON DELETE CASCADE,
  token_hash  TEXT NOT NULL UNIQUE,
  created_by  TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  expires_at  TEXT,
  revoked_at  TEXT,
  view_count  INTEGER NOT NULL DEFAULT 0,
  last_viewed_at TEXT,
  created_at  TEXT NOT NULL
);
CREATE INDEX idx_shares_config ON configuration_shares(config_id);

-- ---------------------------------------------------------------------------
-- Audit trail  (ISO/IEC 27001 A.8.15, A.8.16; NIST AU-2..AU-12)
-- ---------------------------------------------------------------------------
CREATE TABLE audit_log (
  id             TEXT PRIMARY KEY,
  seq            INTEGER NOT NULL UNIQUE,       -- total order for the chain
  occurred_at    TEXT NOT NULL,                 -- UTC ISO-8601, monotonic
  recorded_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  actor_id       TEXT,
  actor_email    TEXT,                          -- PII minimised: only for non-anonymous actors
  actor_role     TEXT,
  action         TEXT NOT NULL,
  resource_type  TEXT,
  resource_id    TEXT,
  outcome        TEXT NOT NULL CHECK (outcome IN ('SUCCESS','FAILURE','DENIED')),
  severity       TEXT NOT NULL CHECK (severity IN ('INFO','NOTICE','WARNING','CRITICAL')),
  ip_fp          TEXT,                          -- pseudonymised, never a raw address
  user_agent     TEXT,
  session_id     TEXT,
  correlation_id TEXT,
  message        TEXT NOT NULL DEFAULT '',
  details_json   TEXT NOT NULL DEFAULT '{}',
  prev_hash      TEXT NOT NULL,
  entry_hash     TEXT NOT NULL
);
CREATE INDEX idx_audit_time ON audit_log(occurred_at DESC);
CREATE INDEX idx_audit_actor ON audit_log(actor_id, occurred_at DESC);
CREATE INDEX idx_audit_action ON audit_log(action, occurred_at DESC);
CREATE INDEX idx_audit_outcome ON audit_log(outcome, occurred_at DESC);
CREATE INDEX idx_audit_severity ON audit_log(severity, occurred_at DESC);
CREATE INDEX idx_audit_resource ON audit_log(resource_type, resource_id);

-- Append-only enforcement. UPDATE/DELETE are rejected at the engine level so a
-- compromised application account still cannot rewrite history.
CREATE TRIGGER trg_audit_no_update
BEFORE UPDATE ON audit_log
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only: UPDATE is forbidden');
END;

CREATE TRIGGER trg_audit_no_delete
BEFORE DELETE ON audit_log
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only: DELETE is forbidden');
END;

-- Signed checkpoints. Each stores the chain head at a point in time, so
-- truncation of the tail is detectable by comparing the stored head hash.
CREATE TABLE audit_checkpoints (
  id            TEXT PRIMARY KEY,
  seq           INTEGER NOT NULL,
  head_hash     TEXT NOT NULL,
  entry_count   INTEGER NOT NULL,
  signature     TEXT NOT NULL,                 -- HMAC(head_hash || seq || at)
  created_at    TEXT NOT NULL,
  created_by    TEXT
);
CREATE INDEX idx_checkpoints_seq ON audit_checkpoints(seq DESC);

-- Security events raised by detection rules (brute force, privilege abuse...).
CREATE TABLE security_events (
  id            TEXT PRIMARY KEY,
  detected_at   TEXT NOT NULL,
  rule          TEXT NOT NULL,
  severity      TEXT NOT NULL CHECK (severity IN ('INFO','NOTICE','WARNING','CRITICAL')),
  subject       TEXT,
  summary       TEXT NOT NULL,
  details_json  TEXT NOT NULL DEFAULT '{}',
  correlation_id TEXT,
  acknowledged_at TEXT,
  acknowledged_by TEXT REFERENCES users(id) ON DELETE SET NULL
);
CREATE INDEX idx_events_time ON security_events(detected_at DESC);
CREATE INDEX idx_events_sev ON security_events(severity, detected_at DESC);

-- Report generation log: what was produced, by whom, with which filter.
CREATE TABLE report_exports (
  id            TEXT PRIMARY KEY,
  subject       TEXT NOT NULL,
  format        TEXT NOT NULL,
  requested_by  TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  row_count     INTEGER NOT NULL DEFAULT 0,
  byte_size     INTEGER NOT NULL DEFAULT 0,
  content_sha256 TEXT NOT NULL,                 -- proves the delivered file matches the record
  parameters_json TEXT NOT NULL DEFAULT '{}',
  correlation_id TEXT,
  created_at    TEXT NOT NULL,
  expires_at    TEXT
);
CREATE INDEX idx_reports_actor ON report_exports(requested_by, created_at DESC);
CREATE INDEX idx_reports_expiry ON report_exports(expires_at);

-- Outbox of audit records that could not be written to SQLite immediately
-- (disk pressure). Preserves the record rather than dropping it (A.8.15).
CREATE TABLE audit_outbox (
  id            TEXT PRIMARY KEY,
  payload_json  TEXT NOT NULL,
  queued_at     TEXT NOT NULL,
  flushed_at    TEXT
);
`;

export const MIGRATIONS: Migration[] = [
  { version: 1, name: 'core_schema', sql: V1_CORE },
];

export function ensureMigrationTable(): void {
  getDb().exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version     INTEGER PRIMARY KEY,
      name        TEXT NOT NULL,
      applied_at  TEXT NOT NULL
    );
  `);
}

export function appliedVersions(): Set<number> {
  const rows = getDb().prepare('SELECT version FROM schema_migrations').all() as Array<{
    version: number;
  }>;
  return new Set(rows.map((r) => Number(r.version)));
}

export function migrate(log = logger): number {
  ensureMigrationTable();
  const done = appliedVersions();
  let count = 0;

  for (const m of MIGRATIONS) {
    if (done.has(m.version)) continue;
    getDb().exec('BEGIN IMMEDIATE');
    try {
      getDb().exec(m.sql);
      run('INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)', m.version, m.name, new Date().toISOString());
      getDb().exec('COMMIT');
      log.info({ version: m.version, name: m.name }, 'migration applied');
      count++;
    } catch (err) {
      getDb().exec('ROLLBACK');
      log.error({ err, version: m.version, name: m.name }, 'migration failed');
      throw err;
    }
  }

  if (count === 0) log.debug('database already up to date');
  return count;
}
