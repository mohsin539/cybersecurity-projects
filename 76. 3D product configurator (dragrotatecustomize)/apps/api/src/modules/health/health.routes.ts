/**
 * Health & liveness endpoints.
 *
 * Split so an orchestrator can probe cheaply (`/live`) while a readiness check
 * verifies the real dependency (`/ready`). Neither endpoint leaks version or
 * dependency detail unless explicitly asked for, and both are unauthenticated
 * yet strictly rate limited (ISO/IEC 27001 A.8.6).
 */

import { Router, type Request, type Response } from 'express';
import { healthQuerySchema } from '@prismforge/shared';
import { asyncHandler } from '../../http/context.js';
import { validate } from '../../http/validate.js';
import { all, get } from '../../db/driver.js';
import { env } from '../../config/env.js';
import { createCheckpoint, verifyChain } from '../audit/audit.service.js';

export function healthRouter(): Router {
  const router = Router();

  router.get('/live', (_req: Request, res: Response) => {
    res.json({ status: 'alive', uptimeSeconds: Math.round(process.uptime()) });
  });
  router.get(
    '/ready',
    asyncHandler(async (_req, res) => {
      const checks: Record<string, { ok: boolean; detail?: string }> = {};

      try {
        get<{ c: number }>('SELECT COUNT(*) AS c FROM audit_log');
        const migrations = Number(get<{ c: number }>('SELECT COUNT(*) AS c FROM schema_migrations')?.c ?? 0);
        checks['database'] = { ok: migrations > 0, detail: `${migrations} migration(s) applied` };
      } catch (err) {
        checks['database'] = { ok: false, detail: err instanceof Error ? err.message : 'unavailable' };
      }

      const ready = Object.values(checks).every((c) => c.ok);
      res.status(ready ? 200 : 503).json({ status: ready ? 'ready' : 'degraded', checks });
    }),
  );

  router.get(
    '/verbose',
    validate(healthQuerySchema, 'query'),
    asyncHandler(async (req, res) => {
      const { verbose } = req.query as unknown as { verbose: boolean };
      const base = {
        status: 'ok',
        environment: env.nodeEnv,
        uptimeSeconds: Math.round(process.uptime()),
        correlationId: req.ctx.correlationId,
      };
      if (!verbose) {
        res.json(base);
        return;
      }

      // The deep view is auditor-level because it discloses internal state.
      const actor = req.ctx.actor;
      const allowed = actor && ['auditor', 'security_officer', 'admin'].includes(actor.role);
      if (!allowed) {
        res.json({
          ...base,
          detail: 'Set ?verbose=1 and authenticate with an auditor role for dependency detail',
        });
        return;
      }

      const chain = verifyChain({ fromSeq: 0 });
      res.json({
        ...base,
        node: process.version,
        platform: process.platform,
        memory: process.memoryUsage(),
        database: {
          path: env.databasePath,
          auditEntries: Number(get<{ c: number }>('SELECT COUNT(*) AS c FROM audit_log')?.c ?? 0),
          activeSessions: Number(
            get<{ c: number }>('SELECT COUNT(*) AS c FROM sessions WHERE revoked_at IS NULL')?.c ?? 0,
          ),
        },
        auditChain: {
          valid: chain.valid,
          entries: chain.verifiedEntries,
          headHash: chain.headHash,
          discrepancies: chain.errors.length,
        },
        security: {
          corsOrigins: env.corsOrigins,
          cookieSecure: env.cookieSecure,
          hstsEnabled: env.isProd,
          accessTokenTtlSeconds: env.accessTokenTtlSeconds,
          maxFailedLogins: env.maxFailedLogins,
          lockoutMinutes: env.lockoutMinutes,
        },
        recentMigrations: all<{ version: number; name: string; applied_at: string }>(
          'SELECT version, name, applied_at FROM schema_migrations ORDER BY version DESC LIMIT 5',
        ),
      });
    }),
  );

  /** Housekeeping hook for the retention / checkpointing job. */
  router.post(
    '/maintenance',
    asyncHandler(async (req, res) => {
      const actor = req.ctx.actor;
      if (!actor || !['security_officer', 'admin'].includes(actor.role)) {
        res.status(403).json({
          error: { code: 'FORBIDDEN', message: 'Requires the security_officer role', correlationId: req.ctx.correlationId },
        });
        return;
      }
      const pruned = Number(
        get<{ c: number }>(
          "SELECT COUNT(*) AS c FROM sessions WHERE expires_at < datetime('now','-30 days')",
        )?.c ?? 0,
      );
      const checkpoint = createCheckpoint(actor.id);
      res.json({ data: { expiredSessions: pruned, checkpoint }, correlationId: req.ctx.correlationId });
    }),
  );

  return router;
}
