/**
 * Authentication routes.
 *
 * Every endpoint is rate limited, CSRF protected where cookie-authenticated,
 * and writes a mandatory audit record. Failures use generic wording so the API
 * never confirms whether an account exists (OWASP A07:2021).
 */

import { Router, type Request, type Response } from 'express';
import {
  changePasswordSchema,
  loginSchema,
  mfaEnrolSchema,
  refreshSchema,
  type ChangePasswordInput,
  type LoginInput,
  type MfaEnrolInput,
  type RefreshInput,
} from '@prismforge/shared';
import { env } from '../../config/env.js';
import { asyncHandler } from '../../http/context.js';
import { requireAuth } from '../../http/auth.js';
import { authAccountLimiter, authLimiter, issueCsrfToken } from '../../http/security.js';
import { validate } from '../../http/validate.js';
import { writeAudit } from '../../http/audit.middleware.js';
import { AppError } from '../../utils/errors.js';
import { nowIso } from '../../utils/ids.js';
import { record } from '../audit/audit.service.js';
import {
  changePassword,
  disableMfa,
  enrollMfa,
  findById,
  generateTotpSecret,
  getMfaSecret,
  login,
} from './auth.service.js';
import {
  activeSessionCount,
  issueAccessToken,
  listSessions,
  REFRESH_COOKIE,
  revokeAllForUser,
  revokeSession,
  rotateRefreshToken,
} from './token.service.js';

export const authRouter = Router();

const REFRESH_COOKIE_MAX_AGE = env.refreshAbsoluteTtlSeconds * 1000;

function setRefreshCookie(res: Response, token: string): void {
  res.cookie(REFRESH_COOKIE, token, {
    httpOnly: true, // inaccessible to JavaScript -> XSS cannot steal it
    secure: env.cookieSecure,
    sameSite: env.cookieSameSite,
    path: '/api/v1/auth',
    maxAge: REFRESH_COOKIE_MAX_AGE,
  });
}

function clearRefreshCookie(res: Response): void {
  res.clearCookie(REFRESH_COOKIE, {
    httpOnly: true,
    secure: env.cookieSecure,
    sameSite: env.cookieSameSite,
    path: '/api/v1/auth',
  });
}

/** Issues (or re-issues) the double-submit CSRF token. */
authRouter.get(
  '/csrf',
  issueCsrfToken,
  asyncHandler((req, res) => {
    res.json({
      data: { csrfToken: res.getHeader('X-CSRF-Token') },
      correlationId: req.ctx.correlationId,
    });
  }),
);

authRouter.post(
  '/login',
  authLimiter(),
  authAccountLimiter(),
  validate(loginSchema),
  asyncHandler(async (req, res) => {
    const body = req.body as LoginInput;
    const result = await login(req, body, req.ctx);

    setRefreshCookie(res, result.refreshToken);
    res.setHeader('X-Correlation-Id', req.ctx.correlationId);
    res.setHeader('Cache-Control', 'no-store');

    res.json({
      data: {
        accessToken: result.accessToken,
        expiresIn: env.accessTokenTtlSeconds,
        tokenType: 'Bearer',
        mfaSatisfied: result.mfaSatisfied,
        mustChangePassword: result.user.mustChangePassword,
        user: {
          id: result.user.id,
          email: result.user.email,
          displayName: result.user.displayName,
          role: result.user.role,
          mfaEnrolled: result.user.mfaEnrolled,
        },
      },
      correlationId: req.ctx.correlationId,
    });
  }),
);

authRouter.post(
  '/refresh',
  authLimiter(),
  validate(refreshSchema),
  asyncHandler(async (req: Request, res: Response) => {
    const body = req.body as RefreshInput;
    const cookieToken = (req.cookies?.[REFRESH_COOKIE] as string | undefined) ?? body.refreshToken;

    if (!cookieToken) throw new AppError('UNAUTHENTICATED', 'No refresh token presented');

    try {
      const result = rotateRefreshToken(cookieToken, {
        userAgent: req.ctx.userAgent,
        deviceLabel: null,
        deviceFingerprint: body.deviceId ?? null,
        ipFingerprint: req.ctx.ipFingerprint,
      });

      const user = findById(result.userId);
      if (!user || !user.is_active) throw new AppError('ACCOUNT_DISABLED', 'Account is no longer active');

      const accessToken = await issueAccessToken({
        sub: user.id,
        email: user.email,
        role: user.role,
        name: user.display_name,
        sid: result.sessionId,
        amr: ['pwd'],
        mfa: Boolean(user.mfa_secret_enc),
      });

      setRefreshCookie(res, result.rotated.token);
      res.setHeader('Cache-Control', 'no-store');

      writeAudit(req, {
        action: 'auth.token.refresh',
        outcome: 'SUCCESS',
        severity: 'INFO',
        resourceType: 'session',
        resourceId: result.sessionId,
        message: 'Access token refreshed and refresh token rotated',
      });

      res.json({
        data: {
          accessToken,
          expiresIn: env.accessTokenTtlSeconds,
          tokenType: 'Bearer',
          user: { id: user.id, email: user.email, displayName: user.display_name, role: user.role },
        },
        correlationId: req.ctx.correlationId,
      });
    } catch (err) {
      clearRefreshCookie(res);
      if (err instanceof AppError && err.code === 'TOKEN_REUSE') {
        record({
          action: 'auth.token.reuse_detected',
          outcome: 'DENIED',
          severity: 'CRITICAL',
          ipFingerprint: req.ctx.ipFingerprint,
          userAgent: req.ctx.userAgent,
          correlationId: req.ctx.correlationId,
          message: 'Refresh token reuse detected - the entire session family was revoked',
        });
        req.ctx.auditHandled = true;
      }
      throw err;
    }
  }),
);

authRouter.post(
  '/logout',
  asyncHandler(async (req: Request, res: Response) => {
    const token = req.cookies?.[REFRESH_COOKIE] as string | undefined;
    clearRefreshCookie(res);
    if (token) revokeSession(token, 'user-logout');

    writeAudit(req, {
      action: 'auth.logout',
      outcome: 'SUCCESS',
      severity: 'INFO',
      resourceType: 'session',
      resourceId: req.ctx.actor?.sessionId ?? null,
      message: 'User signed out',
    });

    res.json({ data: { ok: true }, correlationId: req.ctx.correlationId });
  }),
);

authRouter.get(
  '/me',
  requireAuth,
  asyncHandler(async (req, res) => {
    const actor = req.ctx.actor!;
    const user = findById(actor.id);
    res.json({
      data: {
        id: actor.id,
        email: actor.email,
        displayName: actor.displayName,
        role: actor.role,
        mfaEnrolled: user?.mfa_secret_enc != null,
        mustChangePassword: user?.must_change_password === 1,
        lastLoginAt: user?.last_login_at ?? null,
        activeSessions: activeSessionCount(actor.id),
        permissions: buildPermissions(actor.role),
      },
      correlationId: req.ctx.correlationId,
    });
  }),
);

authRouter.get(
  '/sessions',
  requireAuth,
  asyncHandler(async (req, res) => {
    const actor = req.ctx.actor!;
    res.json({ data: listSessions(actor.id), correlationId: req.ctx.correlationId });
  }),
);

authRouter.delete(
  '/sessions',
  requireAuth,
  asyncHandler(async (req, res) => {
    const actor = req.ctx.actor!;
    const revoked = revokeAllForUser(actor.id, 'user-requested-global-logout');
    writeAudit(req, {
      action: 'auth.logout',
      outcome: 'SUCCESS',
      severity: 'NOTICE',
      message: 'All sessions revoked by the account holder',
      details: { revoked },
    });
    clearRefreshCookie(res);
    res.json({ data: { revoked }, correlationId: req.ctx.correlationId });
  }),
);

authRouter.post(
  '/password',
  requireAuth,
  authLimiter(),
  validate(changePasswordSchema),
  asyncHandler(async (req, res) => {
    const body = req.body as ChangePasswordInput;
    const actor = req.ctx.actor!;
    const result = await changePassword(
      req.ctx,
      actor.id,
      body.currentPassword,
      body.newPassword,
      body.revokeOtherSessions,
    );
    req.ctx.auditHandled = true;
    res.json({
      data: { ok: true, revokedSessions: result.revokedSessions },
      correlationId: req.ctx.correlationId,
    });
  }),
);

authRouter.post(
  '/mfa/enrol',
  requireAuth,
  authLimiter(),
  validate(mfaEnrolSchema),
  asyncHandler(async (req, res) => {
    const body = req.body as MfaEnrolInput;
    const actor = req.ctx.actor!;
    enrollMfa(actor.id, body.label, body.secret);
    writeAudit(req, {
      action: 'auth.mfa.challenge',
      outcome: 'SUCCESS',
      severity: 'NOTICE',
      resourceType: 'user',
      resourceId: actor.id,
      message: 'TOTP multi-factor authentication enrolled',
    });
    res.json({ data: { ok: true }, correlationId: req.ctx.correlationId });
  }),
);

authRouter.post(
  '/mfa/secret',
  requireAuth,
  asyncHandler(async (req, res) => {
    // The secret is returned ONCE, over TLS, to the enrolling client only.
    res.json({ data: { secret: generateTotpSecret() }, correlationId: req.ctx.correlationId });
  }),
);

authRouter.delete(
  '/mfa',
  requireAuth,
  asyncHandler(async (req, res) => {
    const actor = req.ctx.actor!;
    if (!getMfaSecret(actor.id)) throw AppError.notFound('MFA enrolment');
    disableMfa(actor.id);
    writeAudit(req, {
      action: 'admin.user.update',
      outcome: 'SUCCESS',
      severity: 'CRITICAL',
      resourceType: 'user',
      resourceId: actor.id,
      message: 'Multi-factor authentication removed by the account holder',
    });
    res.json({ data: { ok: true, disabledAt: nowIso() }, correlationId: req.ctx.correlationId });
  }),
);

export function buildPermissions(role: string): string[] {
  const map: Record<string, string[]> = {
    viewer: ['config:read'],
    configurator: ['config:read', 'config:write', 'report:config', 'report:pricing'],
    auditor: [
      'config:read',
      'config:write',
      'report:config',
      'report:pricing',
      'report:register',
      'report:audit',
      'audit:read',
      'audit:verify',
      'audit:export',
      'access:review',
    ],
    security_officer: [
      'config:read',
      'config:write',
      'report:config',
      'report:pricing',
      'report:register',
      'report:audit',
      'report:integrity',
      'report:access-review',
      'report:security-posture',
      'audit:read',
      'audit:verify',
      'audit:export',
      'access:review',
      'security:events',
      'security:ack',
    ],
    admin: ['*'],
  };
  return map[role] ?? [];
}
