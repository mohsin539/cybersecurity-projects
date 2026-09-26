/**
 * Configuration routes.
 *
 * Route table:
 *   GET    /api/v1/configurations           list own (or all, for auditors)
 *   POST   /api/v1/configurations           create (+ optional share link)
 *   GET    /api/v1/configurations/:id       read one (ownership checked)
 *   PATCH  /api/v1/configurations/:id       update with expectedVersion
 *   DELETE /api/v1/configurations/:id       soft delete
 *   GET    /api/v1/configurations/:id/audit audit trail for this record
 *   POST   /api/v1/configurations/:id/share mint a share link
 *   DELETE /api/v1/configurations/:id/share revoke all share links
 *   GET    /api/v1/share/:publicId          anonymous read via ?t=<token>
 */

import { Router } from 'express';
import {
  createConfigurationSchema,
  idParamSchema,
  listConfigurationsSchema,
  shareToken,
  updateConfigurationSchema,
  type CreateConfigurationInput,
  type ListConfigurationsQuery,
  type UpdateConfigurationInput,
} from '@prismforge/shared';
import { z } from 'zod';
import { env } from '../../config/env.js';
import { asyncHandler } from '../../http/context.js';
import { requireAuth, requireRole } from '../../http/auth.js';
import { validate } from '../../http/validate.js';
import { AppError } from '../../utils/errors.js';
import { record } from '../audit/audit.service.js';
import {
  configurationAuditTrail,
  createConfiguration,
  createShare,
  deleteConfiguration,
  listConfigurations,
  readConfiguration,
  resolveShare,
  revokeShare,
  updateConfiguration,
} from './configurations.service.js';

export const configurationRouter = Router();
export const shareRouter = Router();

const shareQuerySchema = z.object({ t: shareToken }).strict();

configurationRouter.use(requireAuth);

configurationRouter.get(
  '/',
  validate(listConfigurationsSchema, 'query'),
  asyncHandler(async (req, res) => {
    const query = req.query as unknown as ListConfigurationsQuery;
    const result = listConfigurations(req.ctx.actor!, query);
    res.json({ data: result, correlationId: req.ctx.correlationId });
  }),
);

configurationRouter.post(
  '/',
  requireRole('configurator'),
  validate(createConfigurationSchema),
  asyncHandler(async (req, res) => {
    const body = req.body as CreateConfigurationInput;
    const result = createConfiguration(req.ctx.actor!, body.spec, {
      share: body.share,
      publicWebOrigin: env.publicWebOrigin,
    });

    req.ctx.auditAction = 'config.create';
    req.ctx.auditResourceType = 'configuration';
    req.ctx.auditResourceId = result.configuration.id;
    req.ctx.auditSeverity = 'NOTICE';
    req.ctx.auditMessage = `Configuration "${result.configuration.name}" created`;
    req.ctx.auditDetails = {
      productId: body.spec.productId,
      quantity: body.spec.quantity,
      totalMinor: result.configuration.totalMinor,
      currency: result.configuration.totalMinor,
      fingerprint: result.configuration.fingerprint,
      shared: body.share,
    };

    res.status(201).json({
      data: { ...result.configuration, shareUrl: result.shareUrl },
      correlationId: req.ctx.correlationId,
    });
  }),
);

configurationRouter.get(
  '/:id',
  validate(idParamSchema, 'params'),
  asyncHandler(async (req, res) => {
    const { id } = req.params as { id: string };
    const configuration = readConfiguration(req.ctx.actor!, id);

    record({
      action: 'config.read',
      outcome: 'SUCCESS',
      severity: 'INFO',
      actorId: req.ctx.actor!.id,
      actorEmail: req.ctx.actor!.email,
      actorRole: req.ctx.actor!.role,
      resourceType: 'configuration',
      resourceId: id,
      ipFingerprint: req.ctx.ipFingerprint,
      userAgent: req.ctx.userAgent,
      sessionId: req.ctx.actor!.sessionId,
      correlationId: req.ctx.correlationId,
      message: 'Configuration read',
    });
    req.ctx.auditHandled = true;

    res.setHeader('ETag', `W/"v${configuration.version}"`);
    res.json({ data: configuration, correlationId: req.ctx.correlationId });
  }),
);

configurationRouter.patch(
  '/:id',
  requireRole('configurator'),
  validate(idParamSchema, 'params'),
  validate(updateConfigurationSchema),
  asyncHandler(async (req, res) => {
    const { id } = req.params as { id: string };
    const body = req.body as UpdateConfigurationInput;
    const configuration = updateConfiguration(req.ctx.actor!, id, body);

    req.ctx.auditAction = 'config.update';
    req.ctx.auditResourceType = 'configuration';
    req.ctx.auditResourceId = id;
    req.ctx.auditSeverity = 'NOTICE';
    req.ctx.auditMessage = `Configuration updated to version ${configuration.version}`;
    req.ctx.auditDetails = {
      version: configuration.version,
      totalMinor: configuration.totalMinor,
      fingerprint: configuration.fingerprint,
    };

    res.setHeader('ETag', `W/"v${configuration.version}"`);
    res.json({ data: configuration, correlationId: req.ctx.correlationId });
  }),
);

configurationRouter.delete(
  '/:id',
  requireRole('configurator'),
  validate(idParamSchema, 'params'),
  asyncHandler(async (req, res) => {
    const { id } = req.params as { id: string };
    deleteConfiguration(req.ctx.actor!, id);

    req.ctx.auditAction = 'config.delete';
    req.ctx.auditResourceType = 'configuration';
    req.ctx.auditResourceId = id;
    req.ctx.auditSeverity = 'WARNING';
    req.ctx.auditMessage = 'Configuration soft-deleted';

    res.status(204).end();
  }),
);

configurationRouter.get(
  '/:id/audit',
  requireRole('auditor'),
  validate(idParamSchema, 'params'),
  asyncHandler(async (req, res) => {
    const { id } = req.params as { id: string };
    const trail = configurationAuditTrail(req.ctx.actor!, id);
    req.ctx.auditHandled = true;
    record({
      action: 'audit.read',
      outcome: 'SUCCESS',
      severity: 'INFO',
      actorId: req.ctx.actor!.id,
      actorEmail: req.ctx.actor!.email,
      actorRole: req.ctx.actor!.role,
      resourceType: 'configuration',
      resourceId: id,
      ipFingerprint: req.ctx.ipFingerprint,
      userAgent: req.ctx.userAgent,
      correlationId: req.ctx.correlationId,
      message: 'Per-configuration audit trail requested',
    });
    res.json({ data: trail, correlationId: req.ctx.correlationId });
  }),
);

configurationRouter.post(
  '/:id/share',
  requireRole('configurator'),
  validate(idParamSchema, 'params'),
  asyncHandler(async (req, res) => {
    const { id } = req.params as { id: string };
    const share = createShare(req.ctx.actor!, id);

    req.ctx.auditAction = 'config.share.created';
    req.ctx.auditResourceType = 'configuration';
    req.ctx.auditResourceId = id;
    req.ctx.auditSeverity = 'WARNING';
    req.ctx.auditMessage = 'Read-only share link minted';
    req.ctx.auditDetails = { expiresAt: share.expiresAt };

    res.status(201).json({
      data: { url: `${env.publicWebOrigin.replace(/\/$/, '')}${share.url}`, expiresAt: share.expiresAt },
      correlationId: req.ctx.correlationId,
    });
  }),
);

configurationRouter.delete(
  '/:id/share',
  requireRole('configurator'),
  validate(idParamSchema, 'params'),
  asyncHandler(async (req, res) => {
    const { id } = req.params as { id: string };
    const revoked = revokeShare(req.ctx.actor!, id);
    if (revoked === 0) throw AppError.notFound('Active share link');

    req.ctx.auditAction = 'config.share.revoked';
    req.ctx.auditResourceType = 'configuration';
    req.ctx.auditResourceId = id;
    req.ctx.auditSeverity = 'WARNING';
    req.ctx.auditMessage = `${revoked} share link(s) revoked`;

    res.json({ data: { revoked }, correlationId: req.ctx.correlationId });
  }),
);

// ---------------------------------------------------------------------------
// Public share resolution (no authentication)
// ---------------------------------------------------------------------------

shareRouter.get(
  '/:publicId',
  validate(z.object({ publicId: idParamSchema }).strict(), 'params'),
  validate(shareQuerySchema, 'query'),
  asyncHandler(async (req, res) => {
    const { publicId } = req.params as { publicId: string };
    const { t } = req.query as unknown as { t: string };

    let resolved;
    try {
      resolved = resolveShare(publicId, t);
    } catch (err) {
      record({
        action: 'config.share.accessed',
        outcome: err instanceof AppError && err.status < 500 ? 'DENIED' : 'FAILURE',
        severity: 'WARNING',
        resourceType: 'configuration',
        resourceId: publicId,
        ipFingerprint: req.ctx.ipFingerprint,
        userAgent: req.ctx.userAgent,
        correlationId: req.ctx.correlationId,
        message: 'Rejected share link access attempt',
        details: { reason: err instanceof Error ? err.message : 'unknown' },
      });
      req.ctx.auditHandled = true;
      throw err;
    }

    record({
      action: 'config.share.accessed',
      outcome: 'SUCCESS',
      severity: 'NOTICE',
      resourceType: 'configuration',
      resourceId: resolved.configuration.id,
      ipFingerprint: req.ctx.ipFingerprint,
      userAgent: req.ctx.userAgent,
      correlationId: req.ctx.correlationId,
      message: 'Share link resolved',
      details: { publicId },
    });
    req.ctx.auditHandled = true;

    res.setHeader('Cache-Control', 'no-store');
    res.json({ data: resolved, correlationId: req.ctx.correlationId });
  }),
);
