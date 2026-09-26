/**
 * Automatic audit trail emission.
 *
 * Design: a route *declares* what it does by setting `req.ctx.auditAction`.
 * The middleware then writes the record once the response status is known, so
 * SUCCESS vs FAILURE is always accurate and can never be forgotten by a
 * developer. A route that mutates state without declaring an action is caught
 * by `assertAuditCoverage` in development and test environments.
 */

import type { RequestHandler } from 'express';
import { CRITICAL_ACTIONS, type AuditOutcome, type AuditSeverity } from '@prismforge/shared';
import { logger } from '../config/logger.js';
import { isAppError } from '../utils/errors.js';
import { record } from '../modules/audit/audit.service.js';

const MUTATING = new Set(['POST', 'PATCH', 'PUT', 'DELETE']);

function classify(status: number): AuditOutcome {
  if (status >= 500) return 'FAILURE';
  if (status === 401 || status === 403 || status === 423) return 'DENIED';
  if (status >= 400) return 'FAILURE';
  return 'SUCCESS';
}

function severityFor(action: string, outcome: AuditOutcome): AuditSeverity {
  if (CRITICAL_ACTIONS.has(action)) return 'CRITICAL';
  if (outcome === 'DENIED') return 'WARNING';
  if (outcome === 'FAILURE') return 'NOTICE';
  return 'INFO';
}

export const auditMiddleware: RequestHandler = (req, res, next) => {
  res.on('finish', () => {
    const ctx = req.ctx;
    if (!ctx || ctx.auditHandled) return;
    if (!MUTATING.has(req.method) && !ctx.auditAction) return;

    const action = ctx.auditAction;
    if (!action) {
      if (MUTATING.has(req.method) && req.path.startsWith('/api/v1')) {
        logger.warn(
          { path: req.path, method: req.method, correlationId: ctx.correlationId },
          'mutating route executed without a declared audit action',
        );
      }
      return;
    }

    const outcome = classify(res.statusCode);

    try {
      record({
        action,
        outcome,
        severity: severityFor(action, outcome),
        actorId: ctx.actor?.id ?? null,
        actorEmail: ctx.actor?.email ?? null,
        actorRole: ctx.actor?.role ?? null,
        resourceType: ctx.auditResourceType ?? null,
        resourceId: ctx.auditResourceId ?? null,
        ipFingerprint: ctx.ipFingerprint,
        userAgent: ctx.userAgent,
        sessionId: ctx.actor?.sessionId ?? null,
        correlationId: ctx.correlationId,
        message: ctx.auditMessage ?? '',
        details: {
          ...ctx.auditDetails,
          method: req.method,
          route: req.route?.path ?? req.path,
          status: res.statusCode,
          durationMs: Date.now() - ctx.startedAt,
        },
      });
    } catch (err) {
      // Losing an audit record is a security incident in itself - shout loudly.
      logger.error({ err, action, correlationId: ctx.correlationId }, 'FAILED TO PERSIST AUDIT RECORD');
    }
  });
  next();
};

/** Explicit, single-shot audit write for routes that need custom detail. */
export function writeAudit(
  req: Parameters<RequestHandler>[0],
  entry: {
    action: string;
    outcome: AuditOutcome;
    severity?: AuditSeverity;
    resourceType?: string | null;
    resourceId?: string | null;
    message?: string;
    details?: Record<string, unknown>;
  },
): void {
  const ctx = req.ctx;
  record({
    action: entry.action,
    outcome: entry.outcome,
    severity: entry.severity ?? severityFor(entry.action, entry.outcome),
    actorId: ctx.actor?.id ?? null,
    actorEmail: ctx.actor?.email ?? null,
    actorRole: ctx.actor?.role ?? null,
    resourceType: entry.resourceType ?? null,
    resourceId: entry.resourceId ?? null,
    ipFingerprint: ctx.ipFingerprint,
    userAgent: ctx.userAgent,
    sessionId: ctx.actor?.sessionId ?? null,
    correlationId: ctx.correlationId,
    message: entry.message ?? '',
    details: { ...entry.details, method: req.method, path: req.path, durationMs: Date.now() - ctx.startedAt },
  });
  ctx.auditHandled = true;
}

export { classify as classifyOutcome, isAppError };
