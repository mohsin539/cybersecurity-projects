/**
 * Audit API.
 *
 *   GET  /api/v1/audit              paginated, filterable trail
 *   GET  /api/v1/audit/stats        aggregate statistics for dashboards
 *   POST /api/v1/audit/verify       full hash-chain verification
 *   POST /api/v1/audit/checkpoint   mint a signed chain checkpoint
 *   GET  /api/v1/audit/events       security events raised by detection rules
 *   POST /api/v1/audit/events/:id/ack  acknowledge a security event
 *
 * Read access to the trail is itself privileged: an auditor or above only.
 * Every read of the trail is recorded, so reads of the log are also auditable.
 */

import { Router } from 'express';
import { auditQuerySchema, auditStatsQuerySchema, idParamSchema, verifyAuditSchema } from '@prismforge/shared';
import { asyncHandler } from '../../http/context.js';
import { requireAuth, requireRole } from '../../http/auth.js';
import { validate } from '../../http/validate.js';
import { writeAudit } from '../../http/audit.middleware.js';
import { AppError } from '../../utils/errors.js';
import {
  acknowledgeSecurityEvent,
  auditStats,
  createCheckpoint,
  listSecurityEvents,
  queryAudit,
  verifyChain,
} from './audit.service.js';

export const auditRouter = Router();

auditRouter.use(requireAuth, requireRole('auditor'));

auditRouter.get(
  '/',
  validate(auditQuerySchema, 'query'),
  asyncHandler(async (req, res) => {
    const query = req.query as unknown as import('@prismforge/shared').AuditQueryInput;
    const result = queryAudit(query);

    writeAudit(req, {
      action: 'audit.read',
      outcome: 'SUCCESS',
      severity: 'INFO',
      resourceType: 'audit_log',
      resourceId: null,
      message: `Audit trail queried (page ${query.page}, ${result.total} matching records)`,
      details: {
        filters: {
          action: query.action ?? null,
          outcome: query.outcome ?? null,
          minSeverity: query.minSeverity ?? null,
          from: query.from ?? null,
          to: query.to ?? null,
          actor: query.actor ?? null,
        },
        returned: result.rows.length,
      },
    });

    res.json({ data: result, correlationId: req.ctx.correlationId });
  }),
);

auditRouter.get(
  '/stats',
  validate(auditStatsQuerySchema, 'query'),
  asyncHandler(async (req, res) => {
    const { days } = req.query as unknown as { days: number };
    const stats = auditStats(days);
    req.ctx.auditHandled = true;
    res.json({ data: stats, correlationId: req.ctx.correlationId });
  }),
);

auditRouter.post(
  '/verify',
  requireRole('security_officer'),
  validate(verifyAuditSchema),
  asyncHandler(async (req, res) => {
    const { fromSeq, toSeq } = req.body as { fromSeq: number; toSeq?: number };
    const result = verifyChain({ fromSeq, toSeq });

    if (!result.valid) {
      // A failed integrity check is escalated as a security event in its own right.
      writeAudit(req, {
        action: 'audit.verify',
        outcome: 'FAILURE',
        severity: 'CRITICAL',
        resourceType: 'audit_log',
        message: `INTEGRITY FAILURE: ${result.errors.length} discrepancies detected`,
        details: { fromSeq, toSeq, errors: result.errors.slice(0, 20) },
      });
      throw new AppError('INTEGRITY_FAILURE', 'Audit chain verification FAILED - the log has been modified or truncated', {
        details: result,
      });
    }

    writeAudit(req, {
      action: 'audit.verify',
      outcome: 'SUCCESS',
      severity: 'NOTICE',
      resourceType: 'audit_log',
      message: `Audit chain verified: ${result.verifiedEntries} entries, no discrepancies`,
      details: { fromSeq, toSeq, headHash: result.headHash, durationMs: result.durationMs },
    });

    res.json({ data: result, correlationId: req.ctx.correlationId });
  }),
);

auditRouter.post(
  '/checkpoint',
  requireRole('security_officer'),
  asyncHandler(async (req, res) => {
    const cp = createCheckpoint(req.ctx.actor!.id);
    writeAudit(req, {
      action: 'audit.verify',
      outcome: 'SUCCESS',
      severity: 'NOTICE',
      resourceType: 'audit_checkpoint',
      resourceId: String(cp.seq),
      message: `Signed checkpoint created at seq ${cp.seq}`,
      details: cp,
    });
    res.status(201).json({ data: cp, correlationId: req.ctx.correlationId });
  }),
);

auditRouter.get(
  '/events',
  requireRole('security_officer'),
  asyncHandler(async (req, res) => {
    req.ctx.auditHandled = true;
    res.json({
      data: listSecurityEvents(100).map((e) => ({ ...e, details: JSON.parse(e.details_json) })),
      correlationId: req.ctx.correlationId,
    });
  }),
);

auditRouter.post(
  '/events/:id/ack',
  requireRole('security_officer'),
  validate(idParamSchema, 'params'),
  asyncHandler(async (req, res) => {
    const { id } = req.params as { id: string };
    const ok = acknowledgeSecurityEvent(id, req.ctx.actor!.id);
    if (!ok) throw AppError.conflict('Event was already acknowledged or does not exist');

    writeAudit(req, {
      action: 'audit.verify',
      outcome: 'SUCCESS',
      severity: 'NOTICE',
      resourceType: 'security_event',
      resourceId: id,
      message: 'Security event acknowledged',
    });
    res.json({ data: { ok }, correlationId: req.ctx.correlationId });
  }),
);
