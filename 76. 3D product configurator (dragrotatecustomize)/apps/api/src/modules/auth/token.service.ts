/**
 * Token service.
 *
 * Access tokens: short-lived, signed JWT (RS256-equivalent via HMAC-SHA256 with
 *   a dedicated sub-key), sent as `Authorization: Bearer` and held in memory
 *   only by the SPA - never in localStorage, so XSS cannot exfiltrate it
 *   (OWASP A07:2021).
 * Refresh tokens: 256-bit opaque secrets, delivered in an httpOnly SameSite
 *   cookie, stored server-side as SHA-256 digests, rotated on every use with
 *   family-wide reuse detection (session hijack containment, A07:2021).
 */

import { createHash } from 'node:crypto';
import { SignJWT, jwtVerify, type JWTPayload } from 'jose';
import type { Role } from '@prismforge/shared';
import { env } from '../../config/env.js';
import { all, get, run, transaction } from '../../db/driver.js';
import { AppError } from '../../utils/errors.js';
import { isoPlusSeconds, newId, newSecret, nowIso } from '../../utils/ids.js';

const ISSUER = 'prismforge-api';
const AUDIENCE = 'prismforge-web';

let signingKey: Uint8Array | null = null;
function key(): Uint8Array {
  if (!signingKey) signingKey = new TextEncoder().encode(env.jwtSigningKey);
  return signingKey;
}

export interface AccessTokenClaims {
  sub: string;
  email: string;
  role: Role;
  name: string;
  sid: string | null;
  /** Authentication methods actually performed (NIST SP 800-63 AAL). */
  amr: string[];
  mfa: boolean;
}

export async function issueAccessToken(claims: AccessTokenClaims): Promise<string> {
  return new SignJWT({
    email: claims.email,
    role: claims.role,
    name: claims.name,
    sid: claims.sid,
    amr: claims.amr,
    mfa: claims.mfa,
  })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT', kid: 'pf-access-v1' })
    .setSubject(claims.sub)
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setIssuedAt()
    .setJti(newId('jti'))
    .setExpirationTime(`${env.accessTokenTtlSeconds}s`)
    .sign(key());
}

export async function verifyAccessToken(token: string): Promise<AccessTokenClaims & JWTPayload> {
  try {
    const { payload } = await jwtVerify(token, key(), {
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithms: ['HS256'], // pinned: prevents "alg: none" and RS256->HS256 confusion
      clockTolerance: 5,
    });
    if (typeof payload.sub !== 'string') throw new Error('missing subject');
    return payload as AccessTokenClaims & JWTPayload;
  } catch (err) {
    const expired = err instanceof Error && /expired/i.test(err.message);
    throw new AppError(expired ? 'TOKEN_EXPIRED' : 'TOKEN_INVALID', expired ? 'Access token expired' : 'Access token is not valid', {
      cause: err,
    });
  }
}

// ---------------------------------------------------------------------------
// Refresh tokens
// ---------------------------------------------------------------------------

export const REFRESH_COOKIE = 'pf_refresh';

export function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

export interface IssuedRefresh {
  token: string;
  sessionId: string;
  familyId: string;
  expiresAt: string;
  absoluteExpiresAt: string;
}

export interface SessionContext {
  userAgent: string | null;
  deviceLabel: string | null;
  deviceFingerprint: string | null;
  ipFingerprint: string | null;
}

interface SessionRow {
  id: string;
  user_id: string;
  family_id: string;
  token_hash: string;
  expires_at: string;
  absolute_expires_at: string;
  revoked_at: string | null;
  rotated_at: string | null;
}

export function issueRefreshToken(userId: string, ctx: SessionContext, familyId?: string): IssuedRefresh {
  const token = newSecret(32);
  const now = Date.now();
  const expiresAt = isoPlusSeconds(env.refreshTokenTtlSeconds);
  const absoluteExpiresAt = new Date(
    Math.min(now + env.refreshAbsoluteTtlSeconds * 1000, Date.parse(expiresAt)),
  ).toISOString();
  const sessionId = newId('ses');
  const fam = familyId ?? newId('fam');

  run(
    `INSERT INTO sessions
       (id, user_id, family_id, token_hash, device_label, device_fp, ip_fp, user_agent,
        issued_at, expires_at, absolute_expires_at, created_at)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
    sessionId,
    userId,
    fam,
    hashToken(token),
    ctx.deviceLabel,
    ctx.deviceFingerprint,
    ctx.ipFingerprint,
    ctx.userAgent?.slice(0, 300) ?? null,
    new Date(now).toISOString(),
    expiresAt,
    absoluteExpiresAt,
    new Date(now).toISOString(),
  );

  return { token, sessionId, familyId: fam, expiresAt, absoluteExpiresAt };
}

export interface RotationResult {
  userId: string;
  sessionId: string;
  familyId: string;
  rotated: IssuedRefresh;
}

/**
 * Single-use rotation. Presenting an already-rotated (or revoked) token is
 * treated as theft: the entire family is revoked and the caller is told to
 * re-authenticate. This is the OWASP session-management requirement for
 * detecting replay of a stolen refresh token.
 */
export function rotateRefreshToken(token: string, ctx: SessionContext): RotationResult {
  const digest = hashToken(token);

  return transaction((): RotationResult => {
    const row = get<SessionRow>('SELECT * FROM sessions WHERE token_hash = ?', digest);
    if (!row) throw new AppError('TOKEN_INVALID', 'Refresh token is not recognised');

    if (row.revoked_at) {
      run(
        `UPDATE sessions SET revoked_at = COALESCE(revoked_at, ?), revoked_reason = COALESCE(revoked_reason, 'family-revoked-after-reuse')
          WHERE family_id = ?`,
        nowIso(),
        row.family_id,
      );
      throw new AppError('TOKEN_REUSE', 'Refresh token reuse detected; all sessions in this family were revoked');
    }

    if (row.rotated_at) {
      run(
        `UPDATE sessions SET revoked_at = COALESCE(revoked_at, ?), revoked_reason = COALESCE(revoked_reason, 'family-revoked-after-reuse')
          WHERE family_id = ?`,
        nowIso(),
        row.family_id,
      );
      throw new AppError('TOKEN_REUSE', 'Refresh token replay detected; all sessions in this family were revoked');
    }

    const now = Date.now();
    if (Date.parse(row.expires_at) <= now || Date.parse(row.absolute_expires_at) <= now) {
      run('UPDATE sessions SET revoked_at = ?, revoked_reason = ? WHERE id = ?', nowIso(), 'expired', row.id);
      throw new AppError('TOKEN_EXPIRED', 'Session has expired; sign in again');
    }

    run('UPDATE sessions SET rotated_at = ? WHERE id = ?', nowIso(), row.id);
    const rotated = issueRefreshToken(row.user_id, ctx, row.family_id);
    return { userId: row.user_id, sessionId: rotated.sessionId, familyId: row.family_id, rotated };
  });
}

export function revokeSession(token: string, reason: string): boolean {
  const r = run(
    'UPDATE sessions SET revoked_at = ?, revoked_reason = ? WHERE token_hash = ? AND revoked_at IS NULL',
    nowIso(),
    reason,
    hashToken(token),
  );
  return r.changes > 0;
}

export function revokeAllForUser(userId: string, reason: string, exceptSessionId?: string): number {
  const r = exceptSessionId
    ? run(
        'UPDATE sessions SET revoked_at = ?, revoked_reason = ? WHERE user_id = ? AND revoked_at IS NULL AND id <> ?',
        nowIso(),
        reason,
        userId,
        exceptSessionId,
      )
    : run(
        'UPDATE sessions SET revoked_at = ?, revoked_reason = ? WHERE user_id = ? AND revoked_at IS NULL',
        nowIso(),
        reason,
        userId,
      );
  return r.changes;
}

export function revokeFamily(familyId: string, reason: string): number {
  return run(
    'UPDATE sessions SET revoked_at = COALESCE(revoked_at, ?), revoked_reason = COALESCE(revoked_reason, ?) WHERE family_id = ?',
    nowIso(),
    reason,
    familyId,
  ).changes;
}

/** Housekeeping: drop sessions that expired more than 30 days ago. */
export function pruneSessions(): number {
  return run('DELETE FROM sessions WHERE expires_at < ?', new Date(Date.now() - 30 * 86_400_000).toISOString()).changes;
}

export function activeSessionCount(userId: string): number {
  return Number(
    get<{ c: number }>(
      'SELECT COUNT(*) AS c FROM sessions WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?',
      userId,
      nowIso(),
    )?.c ?? 0,
  );
}

export interface SessionSummary {
  id: string;
  familyId: string;
  deviceLabel: string | null;
  userAgent: string | null;
  issuedAt: string;
  expiresAt: string;
  absoluteExpiresAt: string;
  revokedAt: string | null;
  revokedReason: string | null;
  rotatedAt: string | null;
}

export function listSessions(userId: string): SessionSummary[] {
  return all<SessionSummary>(
    `SELECT id, family_id AS familyId, device_label AS deviceLabel, user_agent AS userAgent,
            issued_at AS issuedAt, expires_at AS expiresAt, absolute_expires_at AS absoluteExpiresAt,
            revoked_at AS revokedAt, revoked_reason AS revokedReason, rotated_at AS rotatedAt
       FROM sessions WHERE user_id = ? ORDER BY issued_at DESC LIMIT 50`,
    userId,
  );
}
