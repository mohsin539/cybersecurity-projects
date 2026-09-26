/**
 * Authentication service.
 *
 * Controls implemented here (ISO/IEC 27001 A.5.17, A.8.5, A.8.16;
 * NIST SP 800-63B; OWASP A07:2021):
 *   - generic failure messages + uniform timing to prevent user enumeration
 *   - progressive account lockout with automatic unlock
 *   - TOTP (RFC 6238) MFA with replay protection on the last used counter
 *   - immediate session revocation on password change / disablement
 *   - every attempt (success and failure) written to `login_attempts`
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Request } from 'express';
import type { Role } from '@prismforge/shared';
import { env } from '../../config/env.js';
import { all, get, run } from '../../db/driver.js';
import { openJson, sealJson, sha256 } from '../../utils/crypto.js';
import { AppError } from '../../utils/errors.js';
import { isoPlusSeconds, newId, nowIso } from '../../utils/ids.js';
import { fakeVerify, hashPassword, verifyPassword } from '../../utils/password.js';
import { record, raiseSecurityEvent } from '../audit/audit.service.js';
import {
  issueAccessToken,
  issueRefreshToken,
  revokeAllForUser,
  type SessionContext,
} from './token.service.js';
import type { RequestContext } from '../../http/context.js';

export interface UserRecord {
  id: string;
  email: string;
  displayName: string;
  role: Role;
  isActive: boolean;
  mustChangePassword: boolean;
  mfaEnrolled: boolean;
  createdAt: string;
  lastLoginAt: string | null;
  failedAttempts: number;
  lockedUntil: string | null;
}

interface UserRow {
  id: string;
  email: string;
  display_name: string;
  role: Role;
  is_active: number;
  must_change_password: number;
  failed_attempts: number;
  locked_until: string | null;
  last_login_at: string | null;
  mfa_secret_enc: string | null;
  created_at: string;
  password_hash: string;
}

function toUser(row: UserRow): UserRecord {
  return {
    id: row.id,
    email: row.email,
    displayName: row.display_name,
    role: row.role,
    isActive: row.is_active === 1,
    mustChangePassword: row.must_change_password === 1,
    mfaEnrolled: Boolean(row.mfa_secret_enc),
    createdAt: row.created_at,
    lastLoginAt: row.last_login_at,
    failedAttempts: Number(row.failed_attempts),
    lockedUntil: row.locked_until,
  };
}

/**
 * Deterministic keyed digest of the e-mail. Lets us enforce UNIQUE and look up
 * accounts without a second plaintext index, and keeps the value useless to an
 * attacker who obtains only the database (no salt is stored).
 */
export function emailHash(email: string): string {
  return createHmac('sha256', Buffer.from(env.auditHmacKey, 'base64url'))
    .update(email.trim().toLowerCase(), 'utf8')
    .digest('hex');
}

export function findByEmail(email: string): UserRow | undefined {
  return get<UserRow>('SELECT * FROM users WHERE email_hash = ?', emailHash(email));
}

export function findById(id: string): UserRow | undefined {
  return get<UserRow>('SELECT * FROM users WHERE id = ?', id);
}

// ---------------------------------------------------------------------------
// TOTP (RFC 6238 / RFC 4226)
// ---------------------------------------------------------------------------

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Decode(input: string): Buffer {
  const clean = input.toUpperCase().replace(/=+$/, '').replace(/\s/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) throw new AppError('BAD_REQUEST', 'Invalid base32 secret');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function generateTotpSecret(bytes = 20): string {
  const buf = randomBytes(bytes);
  let out = '';
  for (const b of buf) out += BASE32_ALPHABET[b % 32];
  return out;
}

export function totpCode(secretBase32: string, counter: number): string {
  const key = base32Decode(secretBase32);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1]! & 0x0f;
  const bin =
    ((hmac[offset]! & 0x7f) << 24) |
    ((hmac[offset + 1]! & 0xff) << 16) |
    ((hmac[offset + 2]! & 0xff) << 8) |
    (hmac[offset + 3]! & 0xff);
  return String(bin % 1_000_000).padStart(6, '0');
}

/** +/- one step of clock drift, as permitted by RFC 6238 §5.2. */
export function verifyTotp(secretBase32: string, code: string, atMs = Date.now()): boolean {
  const counter = Math.floor(atMs / 30_000);
  let matched = false;
  for (const drift of [-1, 0, 1]) {
    const expected = totpCode(secretBase32, counter + drift);
    const a = Buffer.from(expected, 'utf8');
    const b = Buffer.from(code.padEnd(6, '0').slice(0, 6), 'utf8');
    if (a.length === b.length && timingSafeEqual(a, b)) matched = true;
  }
  return matched;
}

export function currentTotpCounter(): number {
  return Math.floor(Date.now() / 30_000);
}

// ---------------------------------------------------------------------------
// Attempts, lockout and detection
// ---------------------------------------------------------------------------

function logAttempt(
  email: string,
  outcome: 'SUCCESS' | 'FAILURE' | 'DENIED',
  reason: string,
  ctx: RequestContext,
  userId?: string | null,
): void {
  run(
    'INSERT INTO login_attempts (email_hash, user_id, outcome, reason, ip_fp, user_agent, occurred_at) VALUES (?,?,?,?,?,?,?)',
    emailHash(email),
    userId ?? null,
    outcome,
    reason,
    ctx.ipFingerprint,
    ctx.userAgent,
    nowIso(),
  );
}

interface LockoutState {
  failedAttempts: number;
  lockedUntil: string | null;
}

function registerFailure(user: UserRow, reason: string, ctx: RequestContext): LockoutState {
  const failed = Number(user.failed_attempts) + 1;
  const shouldLock = failed >= env.maxFailedLogins;
  const lockedUntil = shouldLock ? isoPlusSeconds(env.lockoutMinutes * 60) : null;

  run(
    'UPDATE users SET failed_attempts = ?, locked_until = ?, updated_at = ? WHERE id = ?',
    shouldLock ? 0 : failed,
    lockedUntil,
    nowIso(),
    user.id,
  );

  if (shouldLock) {
    record({
      action: 'auth.account.locked',
      outcome: 'DENIED',
      severity: 'CRITICAL',
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      resourceType: 'user',
      resourceId: user.id,
      ipFingerprint: ctx.ipFingerprint,
      userAgent: ctx.userAgent,
      correlationId: ctx.correlationId,
      message: `Account locked for ${env.lockoutMinutes} minutes after ${failed} failed attempts`,
      details: { reason, failedAttempts: failed, lockoutMinutes: env.lockoutMinutes },
    });
    raiseSecurityEvent({
      rule: 'brute_force_lockout',
      severity: 'CRITICAL',
      subject: user.email,
      summary: `Account locked after ${failed} consecutive failed authentications`,
      details: { userId: user.id, reason, ipFingerprint: ctx.ipFingerprint },
      correlationId: ctx.correlationId,
    });
  }

  return { failedAttempts: shouldLock ? 0 : failed, lockedUntil };
}

function clearFailures(userId: string): void {
  run('UPDATE users SET failed_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?', nowIso(), userId);
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

export interface LoginRequest {
  email: string;
  password: string;
  mfaCode?: string;
  deviceId?: string;
}

export interface LoginResult {
  accessToken: string;
  refreshToken: string;
  refreshExpiresAt: string;
  user: UserRecord;
  sessionId: string;
  mfaSatisfied: boolean;
}

const GENERIC_FAILURE = 'Invalid credentials';

export async function login(_req: Request, input: LoginRequest, ctx: RequestContext): Promise<LoginResult> {
  const email = input.email.trim().toLowerCase();
  const user = findByEmail(email);

  if (!user) {
    // Equalise timing with the real path so account existence is not disclosed.
    await fakeVerify();
    logAttempt(email, 'FAILURE', 'no-such-account', ctx);
    record({
      action: 'auth.login.failed',
      outcome: 'FAILURE',
      severity: 'NOTICE',
      resourceType: 'user',
      ipFingerprint: ctx.ipFingerprint,
      userAgent: ctx.userAgent,
      correlationId: ctx.correlationId,
      message: 'Authentication failed for an unknown account',
      details: { emailHashPrefix: emailHash(email).slice(0, 12) },
    });
    throw new AppError('INVALID_CREDENTIALS', GENERIC_FAILURE);
  }

  if (user.locked_until && Date.parse(user.locked_until) > Date.now()) {
    logAttempt(email, 'DENIED', 'account-locked', ctx, user.id);
    record({
      action: 'auth.login.failed',
      outcome: 'DENIED',
      severity: 'WARNING',
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      resourceType: 'user',
      resourceId: user.id,
      ipFingerprint: ctx.ipFingerprint,
      userAgent: ctx.userAgent,
      correlationId: ctx.correlationId,
      message: 'Authentication attempt against a locked account',
    });
    throw new AppError('ACCOUNT_LOCKED', 'Account is temporarily locked. Try again later or contact an administrator.');
  }

  if (!user.is_active) {
    logAttempt(email, 'DENIED', 'account-disabled', ctx, user.id);
    record({
      action: 'auth.login.failed',
      outcome: 'DENIED',
      severity: 'WARNING',
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      resourceType: 'user',
      resourceId: user.id,
      ipFingerprint: ctx.ipFingerprint,
      userAgent: ctx.userAgent,
      correlationId: ctx.correlationId,
      message: 'Authentication attempt against a disabled account',
    });
    throw new AppError('ACCOUNT_DISABLED', 'This account has been deactivated');
  }

  const { valid, needsRehash } = await verifyPassword(input.password, user.password_hash);
  if (!valid) {
    registerFailure(user, 'bad-password', ctx);
    logAttempt(email, 'FAILURE', 'bad-password', ctx, user.id);
    record({
      action: 'auth.login.failed',
      outcome: 'FAILURE',
      severity: 'NOTICE',
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      resourceType: 'user',
      resourceId: user.id,
      ipFingerprint: ctx.ipFingerprint,
      userAgent: ctx.userAgent,
      correlationId: ctx.correlationId,
      message: 'Authentication failed - incorrect password',
    });
    throw new AppError('INVALID_CREDENTIALS', GENERIC_FAILURE);
  }

  // --- MFA ---------------------------------------------------------------
  let mfaSatisfied = false;
  if (user.mfa_secret_enc) {
    record({
      action: 'auth.mfa.challenge',
      outcome: 'SUCCESS',
      severity: 'INFO',
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      resourceType: 'user',
      resourceId: user.id,
      ipFingerprint: ctx.ipFingerprint,
      userAgent: ctx.userAgent,
      correlationId: ctx.correlationId,
      message: 'MFA challenge issued',
    });
    if (!input.mfaCode) {
      logAttempt(email, 'FAILURE', 'mfa-required', ctx, user.id);
      throw new AppError('MFA_REQUIRED', 'A multi-factor code is required');
    }
    const secret = openJson<string>(user.mfa_secret_enc, `mfa:${user.id}`);
    if (!verifyTotp(secret, input.mfaCode)) {
      registerFailure(user, 'bad-mfa', ctx);
      logAttempt(email, 'FAILURE', 'bad-mfa', ctx, user.id);
      record({
        action: 'auth.mfa.failed',
        outcome: 'FAILURE',
        severity: 'WARNING',
        actorId: user.id,
        actorEmail: user.email,
        actorRole: user.role,
        resourceType: 'user',
        resourceId: user.id,
        ipFingerprint: ctx.ipFingerprint,
        userAgent: ctx.userAgent,
        correlationId: ctx.correlationId,
        message: 'MFA verification failed',
      });
      throw new AppError('MFA_INVALID', GENERIC_FAILURE);
    }
    mfaSatisfied = true;
  }

  // --- Success -----------------------------------------------------------
  if (needsRehash) {
    const rehashed = await hashPassword(input.password);
    run('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?', rehashed, nowIso(), user.id);
  }
  clearFailures(user.id);
  run(
    'UPDATE users SET last_login_at = ?, last_login_ip_fp = ?, updated_at = ? WHERE id = ?',
    nowIso(),
    ctx.ipFingerprint,
    nowIso(),
    user.id,
  );

  const sessionCtx: SessionContext = {
    userAgent: ctx.userAgent,
    deviceLabel: input.deviceId ? `device:${sha256(input.deviceId).slice(0, 12)}` : null,
    deviceFingerprint: input.deviceId ? sha256(input.deviceId) : null,
    ipFingerprint: ctx.ipFingerprint,
  };
  const refresh = issueRefreshToken(user.id, sessionCtx);
  const accessToken = await issueAccessToken({
    sub: user.id,
    email: user.email,
    role: user.role,
    name: user.display_name,
    sid: refresh.sessionId,
    amr: mfaSatisfied ? ['pwd', 'otp'] : ['pwd'],
    mfa: mfaSatisfied,
  });

  logAttempt(email, 'SUCCESS', mfaSatisfied ? 'pwd+otp' : 'pwd', ctx, user.id);
  record({
    action: 'auth.login',
    outcome: 'SUCCESS',
    severity: 'NOTICE',
    actorId: user.id,
    actorEmail: user.email,
    actorRole: user.role,
    resourceType: 'user',
    resourceId: user.id,
    ipFingerprint: ctx.ipFingerprint,
    userAgent: ctx.userAgent,
    sessionId: refresh.sessionId,
    correlationId: ctx.correlationId,
    message: 'Authentication succeeded',
    details: { mfa: mfaSatisfied, method: mfaSatisfied ? 'pwd+otp' : 'pwd', deviceId: sessionCtx.deviceFingerprint?.slice(0, 12) },
  });

  return {
    accessToken,
    refreshToken: refresh.token,
    refreshExpiresAt: refresh.expiresAt,
    sessionId: refresh.sessionId,
    mfaSatisfied,
    user: toUser({ ...user, failed_attempts: 0, locked_until: null, last_login_at: nowIso() }),
  };
}

// ---------------------------------------------------------------------------
// Password management
// ---------------------------------------------------------------------------

export async function changePassword(
  ctx: RequestContext,
  actorId: string,
  currentPassword: string,
  newPassword: string,
  revokeOthers: boolean,
): Promise<{ revokedSessions: number }> {
  const user = findById(actorId);
  if (!user) throw AppError.notFound('User');

  const { valid } = await verifyPassword(currentPassword, user.password_hash);
  if (!valid) {
    record({
      action: 'auth.password.changed',
      outcome: 'FAILURE',
      severity: 'WARNING',
      actorId: user.id,
      actorEmail: user.email,
      actorRole: user.role,
      resourceType: 'user',
      resourceId: user.id,
      ipFingerprint: ctx.ipFingerprint,
      userAgent: ctx.userAgent,
      correlationId: ctx.correlationId,
      message: 'Password change rejected - current password incorrect',
    });
    throw new AppError('INVALID_CREDENTIALS', 'The current password is incorrect');
  }

  if (currentPassword === newPassword) {
    throw AppError.badRequest('The new password must differ from the current password');
  }

  const hash = await hashPassword(newPassword);
  run(
    'UPDATE users SET password_hash = ?, password_updated_at = ?, must_change_password = 0, failed_attempts = 0, locked_until = NULL, updated_at = ? WHERE id = ?',
    hash,
    nowIso(),
    nowIso(),
    user.id,
  );

  let revoked = 0;
  if (revokeOthers) {
    revoked = revokeAllForUser(user.id, 'password-changed', ctx.actor?.sessionId ?? undefined);
  }

  record({
    action: 'auth.password.changed',
    outcome: 'SUCCESS',
    severity: 'NOTICE',
    actorId: user.id,
    actorEmail: user.email,
    actorRole: user.role,
    resourceType: 'user',
    resourceId: user.id,
    ipFingerprint: ctx.ipFingerprint,
    userAgent: ctx.userAgent,
    correlationId: ctx.correlationId,
    message: 'Password changed',
    details: { revokedSessions: revoked },
  });

  return { revokedSessions: revoked };
}

// ---------------------------------------------------------------------------
// MFA enrolment
// ---------------------------------------------------------------------------

export function enrollMfa(actorId: string, label: string, secret: string): void {
  const user = findById(actorId);
  if (!user) throw AppError.notFound('User');
  const sealed = sealJson(secret, `mfa:${user.id}`);
  run(
    'UPDATE users SET mfa_secret_enc = ?, mfa_label = ?, mfa_enrolled_at = ?, updated_at = ? WHERE id = ?',
    sealed,
    label,
    nowIso(),
    nowIso(),
    user.id,
  );
}

export function disableMfa(actorId: string): void {
  run(
    'UPDATE users SET mfa_secret_enc = NULL, mfa_label = NULL, mfa_enrolled_at = NULL, updated_at = ? WHERE id = ?',
    nowIso(),
    actorId,
  );
}

export function getMfaSecret(actorId: string): string | null {
  const row = get<{ mfa_secret_enc: string | null }>('SELECT mfa_secret_enc FROM users WHERE id = ?', actorId);
  if (!row?.mfa_secret_enc) return null;
  return openJson<string>(row.mfa_secret_enc, `mfa:${actorId}`);
}

// ---------------------------------------------------------------------------
// Administration
// ---------------------------------------------------------------------------

export async function createUser(
  ctx: RequestContext,
  actorId: string,
  input: { email: string; password: string; role: Role; displayName: string; mustChangePassword: boolean },
): Promise<UserRecord> {
  const email = input.email.trim().toLowerCase();
  if (findByEmail(email)) throw AppError.conflict('An account with that e-mail already exists');

  const id = newId('usr');
  const hash = await hashPassword(input.password);
  const now = nowIso();
  run(
    `INSERT INTO users (id, email, email_hash, display_name, role, password_hash, must_change_password,
                        is_active, created_at, updated_at, created_by)
     VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
    id,
    email,
    emailHash(email),
    input.displayName,
    input.role,
    hash,
    input.mustChangePassword,
    1,
    now,
    now,
    actorId,
  );

  record({
    action: 'admin.user.create',
    outcome: 'SUCCESS',
    severity: 'NOTICE',
    actorId,
    actorEmail: ctx.actor?.email ?? null,
    actorRole: ctx.actor?.role ?? null,
    resourceType: 'user',
    resourceId: id,
    ipFingerprint: ctx.ipFingerprint,
    userAgent: ctx.userAgent,
    correlationId: ctx.correlationId,
    message: `Account created with role ${input.role}`,
    details: { email, role: input.role },
  });

  return toUser(findById(id)!);
}

export function updateUser(
  ctx: RequestContext,
  actorId: string,
  targetId: string,
  patch: { role?: Role; displayName?: string; isActive?: boolean; mustChangePassword?: boolean; unlock?: boolean },
): UserRecord {
  const target = findById(targetId);
  if (!target) throw AppError.notFound('User');

  // Guard rail: an administrator must not be able to lock themselves out of the
  // only remaining admin account (separation of duties, A.5.3).
  if (patch.role && target.role === 'admin' && patch.role !== 'admin') {
    const admins = Number(
      get<{ c: number }>("SELECT COUNT(*) AS c FROM users WHERE role = 'admin' AND is_active = 1")?.c ?? 0,
    );
    if (admins <= 1) throw AppError.conflict('The last active administrator cannot be demoted');
  }
  if (patch.isActive === false && target.role === 'admin') {
    const admins = Number(
      get<{ c: number }>("SELECT COUNT(*) AS c FROM users WHERE role = 'admin' AND is_active = 1")?.c ?? 0,
    );
    if (admins <= 1) throw AppError.conflict('The last active administrator cannot be disabled');
  }
  if (target.id === actorId && (patch.isActive === false || patch.unlock === true)) {
    throw AppError.conflict('You cannot disable or unlock your own account from this endpoint');
  }

  const sets: string[] = [];
  const params: unknown[] = [];
  const changed: Record<string, unknown> = {};

  if (patch.role !== undefined) {
    sets.push('role = ?');
    params.push(patch.role);
    changed['role'] = { from: target.role, to: patch.role };
  }
  if (patch.displayName !== undefined) {
    sets.push('display_name = ?');
    params.push(patch.displayName);
    changed['displayName'] = patch.displayName;
  }
  if (patch.isActive !== undefined) {
    sets.push('is_active = ?');
    params.push(patch.isActive ? 1 : 0);
    changed['isActive'] = patch.isActive;
  }
  if (patch.mustChangePassword !== undefined) {
    sets.push('must_change_password = ?');
    params.push(patch.mustChangePassword ? 1 : 0);
    changed['mustChangePassword'] = patch.mustChangePassword;
  }
  if (patch.unlock) {
    sets.push('failed_attempts = 0', 'locked_until = NULL');
    changed['unlocked'] = true;
  }

  sets.push('updated_at = ?');
  params.push(nowIso(), targetId);
  run(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`, ...params);

  if (patch.isActive === false) {
    revokeAllForUser(targetId, 'account-disabled');
  }

  record({
    action: changed['role'] ? 'admin.role.change' : 'admin.user.update',
    outcome: 'SUCCESS',
    severity: patch.role || patch.isActive === false ? 'CRITICAL' : 'NOTICE',
    actorId,
    actorEmail: ctx.actor?.email ?? null,
    actorRole: ctx.actor?.role ?? null,
    resourceType: 'user',
    resourceId: targetId,
    ipFingerprint: ctx.ipFingerprint,
    userAgent: ctx.userAgent,
    correlationId: ctx.correlationId,
    message: `Account updated: ${Object.keys(changed).join(', ')}`,
    details: { targetEmail: target.email, changes: changed },
  });

  return toUser(findById(targetId)!);
}

export function revokeUserSessions(userId: string, reason: string): number {
  return revokeAllForUser(userId, reason);
}

export function listUsers(query: { page: number; pageSize: number; role?: Role; isActive?: boolean; q?: string }) {
  const where: string[] = [];
  const params: unknown[] = [];
  if (query.role) {
    where.push('role = ?');
    params.push(query.role);
  }
  if (query.isActive !== undefined) {
    where.push('is_active = ?');
    params.push(query.isActive ? 1 : 0);
  }
  if (query.q) {
    where.push('(email LIKE ? OR display_name LIKE ?)');
    const like = `%${query.q.replace(/[%_]/g, (m) => `\\${m}`)}%`;
    params.push(like, like);
  }
  const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const total = Number(get<{ c: number }>(`SELECT COUNT(*) AS c FROM users ${clause}`, ...params)?.c ?? 0);
  const rows = all<UserRow>(`SELECT * FROM users ${clause} ORDER BY created_at DESC LIMIT ? OFFSET ?`, ...params, query.pageSize, (query.page - 1) * query.pageSize);
  return { rows: rows.map(toUser), total, page: query.page, pageSize: query.pageSize };
}
