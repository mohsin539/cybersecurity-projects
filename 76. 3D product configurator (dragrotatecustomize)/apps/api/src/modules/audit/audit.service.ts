/**
 * Tamper-evident audit trail service.
 *
 * Design goals (ISO/IEC 27001 A.8.15 logging, A.8.16 monitoring, A.8.17 clock,
 * A.5.28 collection of evidence; NIST SP 800-92 log management):
 *
 *  1. COMPLETENESS  - every security-relevant action passes through `record()`;
 *     the HTTP middleware makes it impossible to mutate state without logging.
 *  2. ORDER         - a monotonic integer `seq` gives a total order.
 *  3. INTEGRITY     - each entry is HMAC-chained to its predecessor. Editing or
 *     deleting an entry breaks the chain from that point forward.
 *  4. NON-REPUDIATION OF TRUNCATION - periodic signed checkpoints store the
 *     chain head, so deleting the *tail* is also detectable.
 *  5. PII MINIMISATION - IP addresses are pseudonymised (salted scrypt) and
 *     e-mail is only retained for identified actors.
 *  6. AVAILABILITY  - a synchronous outbox guarantees a record is never silently
 *     lost; failures to persist are escalated as CRITICAL.
 */

import { LIMITS, type AuditOutcome, type AuditSeverity } from '@prismforge/shared';
import { env } from '../../config/env.js';
import { logger } from '../../config/logger.js';
import { all, get, run, transaction } from '../../db/driver.js';
import { auditMac, canonicalJson } from '../../utils/crypto.js';
import { newId, nowIso } from '../../utils/ids.js';

export const GENESIS_HASH = '0'.repeat(64);

export interface AuditEntryInput {
  action: string;
  outcome: AuditOutcome;
  severity: AuditSeverity;
  actorId?: string | null;
  actorEmail?: string | null;
  actorRole?: string | null;
  resourceType?: string | null;
  resourceId?: string | null;
  ipFingerprint?: string | null;
  userAgent?: string | null;
  sessionId?: string | null;
  correlationId?: string | null;
  message?: string;
  details?: Record<string, unknown>;
  /** Overrides the wall clock; used by the deterministic verifier/tests. */
  occurredAt?: string;
}

export interface AuditRecord extends AuditEntryInput {
  id: string;
  seq: number;
  occurredAt: string;
  recordedAt: string;
  prevHash: string;
  entryHash: string;
}

export interface AuditRow {
  id: string;
  seq: number;
  occurred_at: string;
  recorded_at: string;
  actor_id: string | null;
  actor_email: string | null;
  actor_role: string | null;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  outcome: AuditOutcome;
  severity: AuditSeverity;
  ip_fp: string | null;
  user_agent: string | null;
  session_id: string | null;
  correlation_id: string | null;
  message: string;
  details_json: string;
  prev_hash: string;
  entry_hash: string;
}

/**
 * The exact field set covered by the MAC. Adding a field here invalidates
 * historical hashes, so it is intentionally explicit and versioned.
 */
interface HashedPayload {
  seq: number;
  occurred_at: string;
  actor_id: string | null;
  actor_email: string | null;
  actor_role: string | null;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  outcome: string;
  severity: string;
  ip_fp: string | null;
  session_id: string | null;
  correlation_id: string | null;
  message: string;
  details: unknown;
}

function payloadOf(r: {
  seq: number;
  occurredAt: string;
  actorId?: string | null;
  actorEmail?: string | null;
  actorRole?: string | null;
  action: string;
  resourceType?: string | null;
  resourceId?: string | null;
  outcome: string;
  severity: string;
  ipFingerprint?: string | null;
  sessionId?: string | null;
  correlationId?: string | null;
  message?: string;
  details?: Record<string, unknown>;
}): HashedPayload {
  return {
    seq: r.seq,
    occurred_at: r.occurredAt,
    actor_id: r.actorId ?? null,
    actor_email: r.actorEmail ?? null,
    actor_role: r.actorRole ?? null,
    action: r.action,
    resource_type: r.resourceType ?? null,
    resource_id: r.resourceId ?? null,
    outcome: r.outcome,
    severity: r.severity,
    ip_fp: r.ipFingerprint ?? null,
    session_id: r.sessionId ?? null,
    correlation_id: r.correlationId ?? null,
    message: r.message ?? '',
    details: r.details ?? {},
  };
}

/** Recomputes the MAC for a persisted row. Pure - used by the verifier. */
export function recomputeEntryHash(row: AuditRow): string {
  let details: unknown = {};
  try {
    details = JSON.parse(row.details_json);
  } catch {
    details = { __unparseable: row.details_json };
  }
  const payload = payloadOf({
    seq: Number(row.seq),
    occurredAt: row.occurred_at,
    actorId: row.actor_id,
    actorEmail: row.actor_email,
    actorRole: row.actor_role,
    action: row.action,
    resourceType: row.resource_type,
    resourceId: row.resource_id,
    outcome: row.outcome,
    severity: row.severity,
    ipFingerprint: row.ip_fp,
    sessionId: row.session_id,
    correlationId: row.correlation_id,
    message: row.message,
    details: details as Record<string, unknown>,
  });
  return auditMac(`${row.prev_hash}.${canonicalJson(payload)}`);
}

// ---------------------------------------------------------------------------
// Append
// ---------------------------------------------------------------------------

function head(): { seq: number; hash: string } {
  const row = get<{ seq: number; entry_hash: string }>(
    'SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1',
  );
  if (!row) return { seq: 0, hash: GENESIS_HASH };
  return { seq: Number(row.seq), hash: row.entry_hash };
}

/**
 * Appends one entry. Synchronous and transactional by design: the process
 * cannot acknowledge the request that caused the event until the event is
 * durably chained (synchronous = FULL).
 */
export function record(input: AuditEntryInput): AuditRecord {
  const occurredAt = input.occurredAt ?? nowIso();
  const details = input.details ?? {};

  const built = transaction(() => {
    const prev = head();
    const seq = prev.seq + 1;
    const id = newId('aud');
    const payload = payloadOf({ ...input, seq, occurredAt });
    const prevHash = prev.hash;
    const entryHash = auditMac(`${prevHash}.${canonicalJson(payload)}`);

    run(
      `INSERT INTO audit_log
         (id, seq, occurred_at, actor_id, actor_email, actor_role, action,
          resource_type, resource_id, outcome, severity, ip_fp, user_agent,
          session_id, correlation_id, message, details_json, prev_hash, entry_hash)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      id,
      seq,
      occurredAt,
      input.actorId ?? null,
      input.actorEmail ?? null,
      input.actorRole ?? null,
      input.action,
      input.resourceType ?? null,
      input.resourceId ?? null,
      input.outcome,
      input.severity,
      input.ipFingerprint ?? null,
      input.userAgent ?? null,
      input.sessionId ?? null,
      input.correlationId ?? null,
      input.message ?? '',
      canonicalJson(details),
      prevHash,
      entryHash,
    );

    return {
      id,
      seq,
      occurredAt,
      recordedAt: occurredAt,
      actorId: input.actorId ?? null,
      actorEmail: input.actorEmail ?? null,
      actorRole: input.actorRole ?? null,
      action: input.action,
      resourceType: input.resourceType ?? null,
      resourceId: input.resourceId ?? null,
      outcome: input.outcome,
      severity: input.severity,
      ipFingerprint: input.ipFingerprint ?? null,
      userAgent: input.userAgent ?? null,
      sessionId: input.sessionId ?? null,
      correlationId: input.correlationId ?? null,
      message: input.message ?? '',
      details,
      prevHash,
      entryHash,
    } satisfies AuditRecord;
  });

  if (env.auditLogToStdout) {
    logger.info(
      {
        audit: {
          seq: built.seq,
          action: built.action,
          outcome: built.outcome,
          severity: built.severity,
          actor: built.actorEmail ?? built.actorId ?? 'anonymous',
          resource: built.resourceId ?? null,
          correlationId: built.correlationId,
          entryHash: built.entryHash.slice(0, 16),
        },
      },
      built.message || built.action,
    );
  }

  return built;
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

export interface ChainVerification {
  valid: boolean;
  verifiedEntries: number;
  firstSeq: number;
  lastSeq: number;
  headHash: string | null;
  checkedAt: string;
  durationMs: number;
  errors: Array<{ seq: number; reason: string; expected?: string; actual?: string }>;
  /** Populated when a signed checkpoint disagrees with the live chain head. */
  checkpoint: {
    ok: boolean;
    seq: number;
    headHash: string;
    note: string;
  } | null;
  /** Truncation heuristic: gaps in the seq sequence indicate removed rows. */
  sequenceGaps: number[];
}

export interface VerifyOptions {
  fromSeq?: number;
  toSeq?: number;
  /** Also compare the newest signed checkpoint against the live head. */
  checkCheckpoint?: boolean;
  /** Hard cap on rows walked in one verification pass. */
  maxEntries?: number;
}

export function verifyChain(options: VerifyOptions = {}): ChainVerification {
  const started = Date.now();
  const errors: ChainVerification['errors'] = [];
  const gaps: number[] = [];

  const fromSeq = Math.max(0, options.fromSeq ?? 0);
  const toSeq = options.toSeq ?? Number.MAX_SAFE_INTEGER;
  const maxEntries = options.maxEntries ?? 500_000;

  const rows = all<AuditRow>(
    `SELECT * FROM audit_log WHERE seq >= ? AND seq <= ? ORDER BY seq ASC LIMIT ?`,
    fromSeq,
    toSeq,
    maxEntries + 1,
  );

  const truncated = rows.length > maxEntries;
  if (truncated) rows.length = maxEntries;

  // Establish the expected predecessor for the first examined row.
  let expectedPrev = GENESIS_HASH;
  if (fromSeq > 0) {
    const prior = get<{ entry_hash: string }>('SELECT entry_hash FROM audit_log WHERE seq = ?', fromSeq - 1);
    expectedPrev = prior?.entry_hash ?? GENESIS_HASH;
  }

  // The chain is 1-based, so a full verification starts by expecting seq 1.
  let expectedSeq = fromSeq === 0 ? 1 : fromSeq;
  let lastHash: string | null = null;

  for (const row of rows) {
    const seq = Number(row.seq);
    if (seq !== expectedSeq) {
      gaps.push(expectedSeq);
      errors.push({ seq, reason: 'SEQUENCE_GAP', expected: String(expectedSeq), actual: String(seq) });
      expectedSeq = seq;
    }

    if (row.prev_hash !== expectedPrev) {
      errors.push({
        seq,
        reason: 'PREV_HASH_MISMATCH',
        expected: expectedPrev,
        actual: row.prev_hash,
      });
    }

    const recomputed = recomputeEntryHash(row);
    if (recomputed !== row.entry_hash) {
      errors.push({
        seq,
        reason: 'ENTRY_HASH_MISMATCH',
        expected: recomputed,
        actual: row.entry_hash,
      });
    }

    expectedPrev = row.entry_hash;
    lastHash = row.entry_hash;
    expectedSeq = seq + 1;
  }

  let checkpoint: ChainVerification['checkpoint'] = null;
  if (options.checkCheckpoint !== false) {
    const cp = get<{ seq: number; head_hash: string; signature: string; created_at: string }>(
      'SELECT seq, head_hash, signature, created_at FROM audit_checkpoints ORDER BY seq DESC LIMIT 1',
    );
    if (cp) {
      const expectedSig = auditMac(`${cp.head_hash}.${cp.seq}.${cp.created_at}`);
      const sigOk = expectedSig === cp.signature;
      const liveRow = get<{ entry_hash: string }>(
        'SELECT entry_hash FROM audit_log WHERE seq = ?',
        cp.seq,
      );
      const headOk = Boolean(liveRow) && liveRow!.entry_hash === cp.head_hash;
      checkpoint = {
        ok: sigOk && headOk,
        seq: Number(cp.seq),
        headHash: cp.head_hash,
        note: !sigOk
          ? 'Checkpoint signature invalid - the checkpoint row was tampered with.'
          : !liveRow
            ? `Checkpoint references seq ${cp.seq} which no longer exists - the log was truncated.`
            : !headOk
              ? 'Recorded hash at the checkpoint sequence no longer matches - the log was rewritten.'
              : 'Checkpoint signature valid and consistent with the live chain.',
      };
      if (!checkpoint.ok) {
        errors.push({ seq: cp.seq, reason: 'CHECKPOINT_MISMATCH', expected: cp.head_hash, actual: liveRow?.entry_hash ?? '<missing>' });
      }
    }
  }

  if (truncated) {
    errors.push({ seq: -1, reason: 'VERIFICATION_TRUNCATED', expected: `<= ${maxEntries}` });
  }

  return {
    valid: errors.length === 0,
    verifiedEntries: rows.length,
    firstSeq: rows.length ? Number(rows[0]!.seq) : fromSeq,
    lastSeq: rows.length ? Number(rows[rows.length - 1]!.seq) : fromSeq,
    headHash: lastHash,
    checkedAt: nowIso(),
    durationMs: Date.now() - started,
    errors: errors.slice(0, 200),
    checkpoint,
    sequenceGaps: gaps.slice(0, 200),
  };
}

// ---------------------------------------------------------------------------
// Checkpoints
// ---------------------------------------------------------------------------

export function createCheckpoint(createdBy?: string | null): { seq: number; headHash: string; signature: string } {
  const h = head();
  const createdAt = nowIso();
  const signature = auditMac(`${h.hash}.${h.seq}.${createdAt}`);
  const count = Number(get<{ c: number }>('SELECT COUNT(*) AS c FROM audit_log')?.c ?? 0);
  run(
    'INSERT INTO audit_checkpoints (id, seq, head_hash, entry_count, signature, created_at, created_by) VALUES (?,?,?,?,?,?,?)',
    newId('ckp'),
    h.seq,
    h.hash,
    count,
    signature,
    createdAt,
    createdBy ?? null,
  );
  return { seq: h.seq, headHash: h.hash, signature };
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

export interface AuditQuery {
  page: number;
  pageSize: number;
  order: 'asc' | 'desc';
  actor?: string;
  action?: string;
  outcome?: AuditOutcome;
  minSeverity?: AuditSeverity;
  from?: string;
  to?: string;
  correlationId?: string;
}

export interface AuditPage {
  rows: AuditRecord[];
  total: number;
  page: number;
  pageSize: number;
}

const SEVERITY_RANK: Record<AuditSeverity, number> = {
  INFO: 0,
  NOTICE: 1,
  WARNING: 2,
  CRITICAL: 3,
};

function toRecord(row: AuditRow): AuditRecord {
  let details: Record<string, unknown> = {};
  try {
    details = JSON.parse(row.details_json) as Record<string, unknown>;
  } catch {
    details = {};
  }
  return {
    id: row.id,
    seq: Number(row.seq),
    occurredAt: row.occurred_at,
    recordedAt: row.recorded_at,
    actorId: row.actor_id,
    actorEmail: row.actor_email,
    actorRole: row.actor_role,
    action: row.action,
    resourceType: row.resource_type,
    resourceId: row.resource_id,
    outcome: row.outcome,
    severity: row.severity,
    ipFingerprint: row.ip_fp,
    userAgent: row.user_agent,
    sessionId: row.session_id,
    correlationId: row.correlation_id,
    message: row.message,
    details,
    prevHash: row.prev_hash,
    entryHash: row.entry_hash,
  };
}

/**
 * Builds a parameterised WHERE clause. Values are always bound, never
 * interpolated - the only interpolated fragments are fixed column names chosen
 * from a hard-coded allow-list, which is what makes this injection-proof.
 */
export function queryAudit(q: AuditQuery): AuditPage {
  const where: string[] = [];
  const params: unknown[] = [];

  if (q.actor) {
    where.push('(actor_id = ? OR actor_email = ?)');
    params.push(q.actor, q.actor.toLowerCase());
  }
  if (q.action) {
    where.push('action LIKE ?');
    params.push(`${q.action.replace(/[%_]/g, (m) => `\\${m}`)}%`);
  }
  if (q.outcome) {
    where.push('outcome = ?');
    params.push(q.outcome);
  }
  if (q.minSeverity) {
    const allowed = (Object.keys(SEVERITY_RANK) as AuditSeverity[]).filter(
      (s) => SEVERITY_RANK[s] >= SEVERITY_RANK[q.minSeverity!],
    );
    where.push(`severity IN (${allowed.map(() => '?').join(',')})`);
    params.push(...allowed);
  }
  if (q.from) {
    where.push('occurred_at >= ?');
    params.push(q.from);
  }
  if (q.to) {
    where.push('occurred_at <= ?');
    params.push(q.to);
  }
  if (q.correlationId) {
    where.push('correlation_id = ?');
    params.push(q.correlationId);
  }

  const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const order = q.order === 'asc' ? 'ASC' : 'DESC';
  const pageSize = Math.min(Math.max(1, q.pageSize), LIMITS.pageSizeMax);
  const page = Math.max(1, q.page);

  const total = Number(
    get<{ c: number }>(`SELECT COUNT(*) AS c FROM audit_log ${clause}`, ...params)?.c ?? 0,
  );

  const rows = all<AuditRow>(
    `SELECT * FROM audit_log ${clause} ORDER BY seq ${order} LIMIT ? OFFSET ?`,
    ...params,
    pageSize,
    (page - 1) * pageSize,
  );

  return { rows: rows.map(toRecord), total, page, pageSize };
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

export interface AuditStats {
  windowDays: number;
  from: string;
  to: string;
  total: number;
  byOutcome: Record<string, number>;
  bySeverity: Record<string, number>;
  byAction: Array<{ action: string; count: number }>;
  byActor: Array<{ actor: string; count: number }>;
  daily: Array<{ date: string; count: number; failures: number; denied: number }>;
  topRiskyActors: Array<{ actor: string; failures: number; denied: number }>;
  chain: { headSeq: number; headHash: string; count: number };
}

export function auditStats(days: number): AuditStats {
  const to = nowIso();
  const from = new Date(Date.now() - days * 86_400_000).toISOString();

  const total = Number(
    get<{ c: number }>('SELECT COUNT(*) AS c FROM audit_log WHERE occurred_at >= ? AND occurred_at <= ?', from, to)?.c ?? 0,
  );

  const group = (column: string, extra = '') =>
    all<{ k: string | null; c: number }>(
      `SELECT ${column} AS k, COUNT(*) AS c FROM audit_log
        WHERE occurred_at >= ? AND occurred_at <= ? ${extra}
        GROUP BY ${column} ORDER BY c DESC`,
      from,
      to,
    );

  const byOutcome: Record<string, number> = {};
  for (const r of group('outcome')) byOutcome[String(r.k)] = Number(r.c);

  const bySeverity: Record<string, number> = {};
  for (const r of group('severity')) bySeverity[String(r.k)] = Number(r.c);

  const byAction = group('action')
    .slice(0, 25)
    .map((r) => ({ action: String(r.k), count: Number(r.c) }));

  const byActor = all<{ k: string | null; c: number }>(
    `SELECT COALESCE(actor_email, actor_id, 'anonymous') AS k, COUNT(*) AS c
       FROM audit_log WHERE occurred_at >= ? AND occurred_at <= ?
      GROUP BY k ORDER BY c DESC LIMIT 15`,
    from,
    to,
  ).map((r) => ({ actor: String(r.k), count: Number(r.c) }));

  const topRiskyActors = all<{ k: string; f: number; d: number }>(
    `SELECT COALESCE(actor_email, actor_id, 'anonymous') AS k,
            SUM(CASE WHEN outcome = 'FAILURE' THEN 1 ELSE 0 END) AS f,
            SUM(CASE WHEN outcome = 'DENIED'  THEN 1 ELSE 0 END) AS d
       FROM audit_log
      WHERE occurred_at >= ? AND occurred_at <= ? AND outcome IN ('FAILURE','DENIED')
      GROUP BY k ORDER BY (f + d) DESC LIMIT 10`,
    from,
    to,
  ).map((r) => ({ actor: String(r.k), failures: Number(r.f), denied: Number(r.d) }));

  const daily = all<{ date: string; c: number; f: number; d: number }>(
    `SELECT substr(occurred_at, 1, 10) AS date,
            COUNT(*) AS c,
            SUM(CASE WHEN outcome = 'FAILURE' THEN 1 ELSE 0 END) AS f,
            SUM(CASE WHEN outcome = 'DENIED'  THEN 1 ELSE 0 END) AS d
       FROM audit_log
      WHERE occurred_at >= ? AND occurred_at <= ?
      GROUP BY date ORDER BY date ASC`,
    from,
    to,
  ).map((r) => ({ date: String(r.date), count: Number(r.c), failures: Number(r.f), denied: Number(r.d) }));

  const h = head();
  const chainCount = Number(get<{ c: number }>('SELECT COUNT(*) AS c FROM audit_log')?.c ?? 0);

  return {
    windowDays: days,
    from,
    to,
    total,
    byOutcome,
    bySeverity,
    byAction,
    byActor,
    daily,
    topRiskyActors,
    chain: { headSeq: h.seq, headHash: h.hash, count: chainCount },
  };
}

// ---------------------------------------------------------------------------
// Security events (detection rules)
// ---------------------------------------------------------------------------

export interface SecurityEventInput {
  rule: string;
  severity: AuditSeverity;
  summary: string;
  subject?: string | null;
  details?: Record<string, unknown>;
  correlationId?: string | null;
}

export function raiseSecurityEvent(input: SecurityEventInput): string {
  const id = newId('sec');
  run(
    'INSERT INTO security_events (id, detected_at, rule, severity, subject, summary, details_json, correlation_id) VALUES (?,?,?,?,?,?,?,?)',
    id,
    nowIso(),
    input.rule,
    input.severity,
    input.subject ?? null,
    input.summary,
    canonicalJson(input.details ?? {}),
    input.correlationId ?? null,
  );
  record({
    action: `security.${input.rule}`,
    outcome: 'FAILURE',
    severity: input.severity,
    resourceType: 'security_event',
    resourceId: id,
    message: input.summary,
    details: { rule: input.rule, subject: input.subject, ...input.details },
    correlationId: input.correlationId,
  });
  return id;
}

export function listSecurityEvents(limit = 50) {
  return all<{
    id: string;
    detected_at: string;
    rule: string;
    severity: AuditSeverity;
    subject: string | null;
    summary: string;
    details_json: string;
    acknowledged_at: string | null;
  }>('SELECT * FROM security_events ORDER BY detected_at DESC LIMIT ?', Math.min(limit, 200));
}

export function acknowledgeSecurityEvent(id: string, userId: string): boolean {
  const r = run(
    'UPDATE security_events SET acknowledged_at = ?, acknowledged_by = ? WHERE id = ? AND acknowledged_at IS NULL',
    nowIso(),
    userId,
    id,
  );
  return r.changes > 0;
}

export function currentHead() {
  return head();
}

export function flushOutbox(): number {
  const rows = all<{ id: string; payload_json: string }>(
    'SELECT id, payload_json FROM audit_outbox WHERE flushed_at IS NULL ORDER BY queued_at ASC LIMIT 500',
  );
  let flushed = 0;
  for (const row of rows) {
    try {
      record(JSON.parse(row.payload_json) as AuditEntryInput);
      run('UPDATE audit_outbox SET flushed_at = ? WHERE id = ?', nowIso(), row.id);
      flushed++;
    } catch (err) {
      logger.error({ err, outboxId: row.id }, 'audit outbox flush failed; record retained');
    }
  }
  return flushed;
}
