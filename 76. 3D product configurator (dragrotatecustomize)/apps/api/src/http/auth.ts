/**
 * Authentication & authorisation middleware.
 *
 * - `authenticate` resolves a Bearer access token into `req.ctx.actor`.
 *   It is *optional* by design: public catalogue browsing works unauthenticated
 *   but is still audited, which gives a complete record either way.
 * - `requireAuth` rejects anonymous requests (OWASP A01:2021).
 * - `requireRole` enforces least privilege using the shared role ladder
 *   (ISO/IEC 27001 A.5.15, A.5.18).
 */

import type { RequestHandler } from 'express';
import { hasAtLeast, type Role } from '@prismforge/shared';
import { AppError } from '../utils/errors.js';
import { get } from '../db/driver.js';
import type { Actor } from './context.js';
import { verifyAccessToken } from '../modules/auth/token.service.js';

interface UserRow {
  id: string;
  email: string;
  display_name: string;
  role: Role;
  is_active: number;
  must_change_password: number;
  mfa_secret_enc: string | null;
}

export const authenticate: RequestHandler = async (req, _res, next) => {
  const header = req.header('authorization');
  if (!header || !/^Bearer\s+\S{20,4096}$/i.test(header)) return next();

  try {
    const token = header.replace(/^Bearer\s+/i, '');
    const claims = await verifyAccessToken(token);

    // Re-read the principal: a token can be valid while the account has since
    // been disabled or downgraded. Never trust the token alone for authorisation.
    const user = get<UserRow>(
      'SELECT id, email, display_name, role, is_active, must_change_password, mfa_secret_enc FROM users WHERE id = ?',
      claims.sub,
    );
    if (!user) return next();
    if (!user.is_active) throw new AppError('ACCOUNT_DISABLED', 'This account has been deactivated');

    const actor: Actor = {
      id: user.id,
      email: user.email,
      role: user.role,
      displayName: user.display_name,
      sessionId: (claims.sid as string | null) ?? null,
      authenticated: true,
      mfaEnrolled: Boolean(user.mfa_secret_enc),
    };
    req.ctx.actor = actor;

    if (user.must_change_password && !req.path.includes('/auth/')) {
      // Not an error, but the client is told to force a rotation.
      _res.setHeader('X-Must-Change-Password', 'true');
    }
    return next();
  } catch (err) {
    if (err instanceof AppError && err.code === 'ACCOUNT_DISABLED') return next(err);
    // An invalid/expired token on an optional-auth route is treated as anonymous
    // for public reads; protected routes will fail in requireAuth with 401.
    if (err instanceof AppError && (err.code === 'TOKEN_EXPIRED' || err.code === 'TOKEN_INVALID')) {
      req.ctx.actor = null;
      return next();
    }
    return next(err);
  }
};

export const requireAuth: RequestHandler = (req, _res, next) => {
  if (!req.ctx.actor?.authenticated) {
    return next(new AppError('UNAUTHENTICATED', 'Authentication is required for this resource'));
  }
  return next();
};

/** Requires the caller to hold at least `role` on the privilege ladder. */
export function requireRole(role: Role): RequestHandler {
  return (req, _res, next) => {
    const actor = req.ctx.actor;
    if (!actor?.authenticated) {
      return next(new AppError('UNAUTHENTICATED', 'Authentication is required for this resource'));
    }
    if (!hasAtLeast(actor.role, role)) {
      return next(
        new AppError('FORBIDDEN', `This operation requires the '${role}' role or higher`, {
          details: { required: role, current: actor.role },
        }),
      );
    }
    return next();
  };
}

/**
 * Object-level authorisation helper (OWASP A01:2021 - IDOR defence).
 * A `viewer` may only read their own rows; every elevated role may read any.
 */
export function canAccessOwned(actor: Actor, ownerId: string): boolean {
  if (actor.id === ownerId) return true;
  return hasAtLeast(actor.role, 'auditor');
}
