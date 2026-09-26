/**
 * Administration routes - user lifecycle, integrity checks, system posture.
 * All routes require the `admin` role and are CRITICAL-audited.
 */

import { Router } from 'express';
import {
  createUserSchema,
  idParamSchema,
  listUsersSchema,
  updateUserSchema,
  type CreateUserInput,
  type ListUsersQuery,
  type UpdateUserInput,
} from '@prismforge/shared';
import { asyncHandler } from '../../http/context.js';
import { requireAuth, requireRole } from '../../http/auth.js';
import { validate } from '../../http/validate.js';
import { writeAudit } from '../../http/audit.middleware.js';
import { all, get } from '../../db/driver.js';
import { createUser, listUsers, updateUser } from '../auth/auth.service.js';
import { createCheckpoint, verifyChain } from '../audit/audit.service.js';
import { REPORT_FORMATS, REPORT_SUBJECTS, ROLES, ACCESSORY_LIST, FINISH_LIST, PART_LIST } from '@prismforge/shared';

export const adminRouter = Router();

adminRouter.use(requireAuth, requireRole('admin'));

adminRouter.get(
  '/users',
  validate(listUsersSchema, 'query'),
  asyncHandler(async (req, res) => {
    const query = req.query as unknown as ListUsersQuery;
    res.json({ data: listUsers(query), correlationId: req.ctx.correlationId });
  }),
);

adminRouter.post(
  '/users',
  validate(createUserSchema),
  asyncHandler(async (req, res) => {
    const body = req.body as CreateUserInput;
    const user = await createUser(req.ctx, req.ctx.actor!.id, body);
    req.ctx.auditHandled = true;
    res.status(201).json({ data: user, correlationId: req.ctx.correlationId });
  }),
);

adminRouter.patch(
  '/users/:id',
  validate(idParamSchema, 'params'),
  validate(updateUserSchema),
  asyncHandler(async (req, res) => {
    const { id } = req.params as { id: string };
    const patch = req.body as UpdateUserInput;
    const user = updateUser(req.ctx, req.ctx.actor!.id, id, patch);
    req.ctx.auditHandled = true;
    res.json({ data: user, correlationId: req.ctx.correlationId });
  }),
);

adminRouter.get(
  '/integrity',
  asyncHandler(async (req, res) => {
    const result = verifyChain({ fromSeq: 0 });
    writeAudit(req, {
      action: 'admin.integrity.check',
      outcome: result.valid ? 'SUCCESS' : 'FAILURE',
      severity: result.valid ? 'INFO' : 'CRITICAL',
      resourceType: 'audit_log',
      message: result.valid
        ? `Integrity check passed over ${result.verifiedEntries} entries`
        : `Integrity check FAILED with ${result.errors.length} discrepancies`,
      details: { errors: result.errors.slice(0, 20) },
    });
    res.json({ data: result, correlationId: req.ctx.correlationId });
  }),
);

adminRouter.post(
  '/integrity/checkpoint',
  asyncHandler(async (req, res) => {
    const cp = createCheckpoint(req.ctx.actor!.id);
    writeAudit(req, {
      action: 'admin.integrity.check',
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

/** Read-only system posture snapshot for the admin console. */
adminRouter.get(
  '/system',
  asyncHandler(async (req, res) => {
    const counts = {
      users: Number(get<{ c: number }>('SELECT COUNT(*) AS c FROM users')?.c ?? 0),
      activeUsers: Number(get<{ c: number }>('SELECT COUNT(*) AS c FROM users WHERE is_active = 1')?.c ?? 0),
      configurations: Number(get<{ c: number }>('SELECT COUNT(*) AS c FROM configurations WHERE deleted_at IS NULL')?.c ?? 0),
      deletedConfigurations: Number(get<{ c: number }>('SELECT COUNT(*) AS c FROM configurations WHERE deleted_at IS NOT NULL')?.c ?? 0),
      sessions: Number(get<{ c: number }>('SELECT COUNT(*) AS c FROM sessions WHERE revoked_at IS NULL')?.c ?? 0),
      auditEntries: Number(get<{ c: number }>('SELECT COUNT(*) AS c FROM audit_log')?.c ?? 0),
      shareLinks: Number(get<{ c: number }>('SELECT COUNT(*) AS c FROM configuration_shares WHERE revoked_at IS NULL')?.c ?? 0),
      reportExports: Number(get<{ c: number }>('SELECT COUNT(*) AS c FROM report_exports')?.c ?? 0),
      securityEvents: Number(get<{ c: number }>('SELECT COUNT(*) AS c FROM security_events')?.c ?? 0),
      openSecurityEvents: Number(
        get<{ c: number }>('SELECT COUNT(*) AS c FROM security_events WHERE acknowledged_at IS NULL')?.c ?? 0,
      ),
    };

    const byRole = all<{ role: string; c: number }>('SELECT role, COUNT(*) AS c FROM users GROUP BY role');

    res.json({
      data: {
        counts,
        byRole,
        capabilities: {
          roles: ROLES,
          reportSubjects: REPORT_SUBJECTS,
          reportFormats: REPORT_FORMATS,
          parts: PART_LIST.length,
          finishes: FINISH_LIST.length,
          accessories: ACCESSORY_LIST.length,
        },
        node: process.version,
        platform: process.platform,
        uptimeSeconds: Math.round(process.uptime()),
      },
      correlationId: req.ctx.correlationId,
    });
  }),
);
