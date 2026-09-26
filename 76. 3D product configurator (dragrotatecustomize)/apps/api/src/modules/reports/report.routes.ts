/**
 * Report generation endpoint.
 *
 *   POST /api/v1/reports/generate
 *   GET  /api/v1/reports/formats   (capability discovery)
 *
 * Controls applied:
 *   - authentication required; the subject's minimum role is enforced in the
 *     service layer before any data is read
 *   - dedicated rate limiter (report generation is CPU/IO heavy)
 *   - a CRITICAL audit entry is written for BOTH the request and the download
 *   - the response is `no-store`, is served with a sanitised filename, and the
 *     SHA-256 of the delivered bytes is recorded in `report_exports`
 */

import { Router, type Request, type Response } from 'express';
import {
  REPORT_FORMATS,
  REPORT_FORMATS_MIME,
  REPORT_SUBJECTS,
  reportRequestSchema,
  type ReportRequest,
} from '@prismforge/shared';
import { asyncHandler } from '../../http/context.js';
import { requireAuth, requireRole } from '../../http/auth.js';
import { reportLimiter } from '../../http/security.js';
import { validate } from '../../http/validate.js';
import { get, run } from '../../db/driver.js';
import { sha256 } from '../../utils/crypto.js';
import { isoPlusSeconds, newId, nowIso } from '../../utils/ids.js';
import { record } from '../audit/audit.service.js';
import { env } from '../../config/env.js';
import { buildReport, REPORT_SCHEMA_VERSION, assertSubjectAllowed } from './report.service.js';
import { render } from './renderers.js';

export const reportRouter = Router();

reportRouter.use(requireAuth);

reportRouter.get(
  '/formats',
  asyncHandler(async (req, res) => {
    const role = req.ctx.actor!.role;
    const rank: Record<string, number> = {
      viewer: 0,
      configurator: 1,
      auditor: 2,
      security_officer: 3,
      admin: 4,
    };
    const required: Record<string, string> = {
      configuration: 'configurator',
      pricing: 'configurator',
      configurations: 'auditor',
      audit: 'auditor',
      integrity: 'security_officer',
      'access-review': 'security_officer',
      'security-posture': 'security_officer',
    };
    const myRank = rank[role] ?? 0;
    res.json({
      data: {
        formats: REPORT_FORMATS.map((f) => ({ id: f, mime: REPORT_FORMATS_MIME[f] })),
        subjects: REPORT_SUBJECTS.map((s) => {
          const need = required[s] ?? 'admin';
          return { id: s, requiredRole: need, allowed: myRank >= (rank[need] ?? Number.MAX_SAFE_INTEGER) };
        }),
        schemaVersion: REPORT_SCHEMA_VERSION,
      },
      correlationId: req.ctx.correlationId,
    });
  }),
);

reportRouter.post(
  '/generate',
  requireRole('configurator'),
  reportLimiter(),
  validate(reportRequestSchema),
  asyncHandler(async (req: Request, res: Response) => {
    const body = req.body as ReportRequest;
    const actor = req.ctx.actor!;

    // Fail fast with 403 before touching the data layer.
    assertSubjectAllowed(actor, body.subject);

    const model = buildReport({
      actor,
      subject: body.subject,
      format: body.format,
      correlationId: req.ctx.correlationId,
      configurationId: body.configurationId,
      spec: body.spec,
      from: body.from,
      to: body.to,
      action: body.action,
      outcome: body.outcome,
      minSeverity: body.minSeverity,
      snapshot: body.includeSnapshot ? body.snapshot || undefined : undefined,
    });

    const rendered = await render(model);
    const digest = sha256(rendered.body.toString('base64'));
    const rowCount = model.sections.reduce((a, s) => a + s.rows.length, 0);

    // Register the export so the delivered file can be proven authentic later.
    run(
      `INSERT INTO report_exports
         (id, subject, format, requested_by, row_count, byte_size, content_sha256,
          parameters_json, correlation_id, created_at, expires_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
      newId('rpt'),
      body.subject,
      body.format,
      actor.id,
      rowCount,
      rendered.body.byteLength,
      digest,
      JSON.stringify({
        configurationId: body.configurationId ?? null,
        from: body.from ?? null,
        to: body.to ?? null,
        includeSnapshot: body.includeSnapshot,
        sections: model.sections.map((s) => s.heading),
      }),
      req.ctx.correlationId,
      nowIso(),
      isoPlusSeconds(env.exportRetentionDays * 86_400),
    );

    // CRITICAL: bulk data extraction is a monitored event, always.
    record({
      action: 'report.generate',
      outcome: 'SUCCESS',
      severity: 'CRITICAL',
      actorId: actor.id,
      actorEmail: actor.email,
      actorRole: actor.role,
      resourceType: 'report',
      resourceId: body.subject,
      ipFingerprint: req.ctx.ipFingerprint,
      userAgent: req.ctx.userAgent,
      sessionId: actor.sessionId,
      correlationId: req.ctx.correlationId,
      message: `${body.subject} report generated as ${body.format.toUpperCase()}`,
      details: {
        rowCount,
        bytes: rendered.body.byteLength,
        contentSha256: digest,
        classification: model.meta.classification,
      },
    });
    req.ctx.auditHandled = true;

    record({
      action: 'report.download',
      outcome: 'SUCCESS',
      severity: 'CRITICAL',
      actorId: actor.id,
      actorEmail: actor.email,
      actorRole: actor.role,
      resourceType: 'report',
      resourceId: rendered.filename,
      ipFingerprint: req.ctx.ipFingerprint,
      userAgent: req.ctx.userAgent,
      sessionId: actor.sessionId,
      correlationId: req.ctx.correlationId,
      message: `Report delivered: ${rendered.filename}`,
      details: { contentSha256: digest, byteSize: rendered.body.byteLength },
    });

    res.setHeader('Content-Type', rendered.mime);
    res.setHeader('Content-Length', String(rendered.body.byteLength));
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('X-Content-SHA256', digest);
    res.setHeader('X-Report-Classification', model.meta.classification);
    res.setHeader('X-Correlation-Id', req.ctx.correlationId);
    // `filename*` (RFC 5987) carries the UTF-8 name; the ASCII fallback covers
    // older clients. The name is generated server-side, never client-supplied.
    const asciiName = rendered.filename.replace(/[^A-Za-z0-9._-]/g, '_');
    res.setHeader('Content-Disposition', `attachment; filename="${asciiName}"; filename*=UTF-8''${encodeURIComponent(rendered.filename)}`);

    res.end(rendered.body);
  }),
);

/** Provenance lookup: proves a delivered export matches a recorded hash. */
reportRouter.get(
  '/:id/provenance',
  requireRole('auditor'),
  asyncHandler(async (req, res) => {
    const id = (req.params as { id: string }).id;
    const row = get<{
      id: string;
      subject: string;
      format: string;
      requested_by: string;
      row_count: number;
      byte_size: number;
      content_sha256: string;
      created_at: string;
      expires_at: string | null;
      parameters_json: string;
    }>('SELECT * FROM report_exports WHERE id = ?', id);
    if (!row) {
      res.status(404).json({ error: { code: 'NOT_FOUND', message: 'No such export', correlationId: req.ctx.correlationId } });
      return;
    }
    res.json({ data: { ...row, parameters: JSON.parse(row.parameters_json) }, correlationId: req.ctx.correlationId });
  }),
);
