/**
 * SQLite driver wrapper around the Node.js built-in `node:sqlite` module.
 *
 * Why the built-in driver instead of `better-sqlite3`:
 *   - Zero native addons -> no compiled code shipped to production, no node-gyp
 *     toolchain in hardened build pipelines (ISO/IEC 27001 A.8.19, OWASP A06).
 *   - Synchronous API matches SQLite's own concurrency model; every query in
 *     this service is parameterised via prepared statements, which is the
 *     primary defence against SQL injection (OWASP A03:2021).
 *
 * Hardening applied to every connection:
 *   - `foreign_keys = ON`     referential integrity is enforced, not hoped for
 *   - `journal_mode = WAL`    concurrent readers, crash-safe writes
 *   - `synchronous = FULL`    durability for the audit trail (A.8.14, A.8.15)
 *   - `trusted_schema = OFF`  blocks schema-based code execution
 *   - `secure_delete = ON`    overwrite deleted content (data remanence)
 */

import { DatabaseSync, type StatementSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { env } from '../config/env.js';
import { logger } from '../config/logger.js';

let db: DatabaseSync | null = null;
const stmtCache = new Map<string, StatementSync>();

/** node:sqlite only binds null/number/bigint/string/Uint8Array. */
export type BindValue = string | number | bigint | null | Uint8Array;
export type Row = Record<string, unknown>;

function connect(): DatabaseSync {
  mkdirSync(dirname(env.databasePath), { recursive: true });
  const handle = new DatabaseSync(env.databasePath);

  handle.exec('PRAGMA journal_mode = WAL');
  handle.exec('PRAGMA synchronous = FULL');
  handle.exec('PRAGMA foreign_keys = ON');
  handle.exec('PRAGMA trusted_schema = OFF');
  handle.exec('PRAGMA secure_delete = ON');
  handle.exec('PRAGMA busy_timeout = 5000');
  handle.exec('PRAGMA temp_store = MEMORY');

  logger.info({ path: env.databasePath }, 'database connection established');
  return handle;
}

export function getDb(): DatabaseSync {
  if (!db) db = connect();
  return db;
}

function prepare(sql: string): StatementSync {
  const hit = stmtCache.get(sql);
  if (hit) return hit;
  const stmt = getDb().prepare(sql);
  stmtCache.set(sql, stmt);
  return stmt;
}

/** Boolean -> 0/1, because SQLite has no native boolean affinity binding. */
function normalise(params: unknown[]): BindValue[] {
  return params.map((p) => {
    if (p === undefined || p === null) return null;
    if (typeof p === 'boolean') return p ? 1 : 0;
    if (typeof p === 'number' || typeof p === 'bigint' || typeof p === 'string') return p;
    if (p instanceof Uint8Array) return p;
    return String(p);
  });
}

export function run(sql: string, ...params: unknown[]): { changes: number; lastInsertRowid: number } {
  const r = prepare(sql).run(...normalise(params));
  return { changes: Number(r.changes), lastInsertRowid: Number(r.lastInsertRowid) };
}

export function get<T = Row>(sql: string, ...params: unknown[]): T | undefined {
  return prepare(sql).get(...normalise(params)) as T | undefined;
}

export function all<T = Row>(sql: string, ...params: unknown[]): T[] {
  return prepare(sql).all(...normalise(params)) as T[];
}

/**
 * Runs `fn` inside a transaction. SQLite has no nested transactions, so the
 * depth guard makes accidental nesting a no-op rather than a silent commit.
 */
let txDepth = 0;
export function transaction<T>(fn: () => T): T {
  const handle = getDb();
  if (txDepth > 0) return fn();
  handle.exec('BEGIN IMMEDIATE');
  txDepth++;
  try {
    const out = fn();
    handle.exec('COMMIT');
    return out;
  } catch (err) {
    try {
      handle.exec('ROLLBACK');
    } catch {
      /* rollback of an already-aborted tx is not itself an error worth raising */
    }
    throw err;
  } finally {
    txDepth--;
  }
}

export function closeDb(): void {
  stmtCache.clear();
  if (db) {
    try {
      db.close();
    } catch (err) {
      logger.warn({ err }, 'error closing database');
    }
    db = null;
  }
}

/** `INSERT ... ON CONFLICT DO NOTHING` helper used by migrations/seed. */
export function insertIgnore(sql: string, ...params: unknown[]): number {
  return run(sql, ...params).changes;
}

export function scalar(sql: string, ...params: unknown[]): number {
  const row = get<{ v: unknown }>(sql, ...params);
  return Number(row?.v ?? 0);
}
