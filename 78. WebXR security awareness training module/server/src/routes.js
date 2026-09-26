'use strict';
/**
 * routes.js — REST API surface (architecture.md §4.1 services).
 * Every route: rate-limited, auth-gated (deny-by-default), validated.
 */

const { createApp, readJsonBody } = require('./http');
const auth = require('./auth');
const sessions = require('./sessions');
const campaigns = require('./campaigns');
const frameworks = require('./frameworks');
const { MODULES, CATEGORIES, catalogEntry } = require('./modules');
const { rateLimit, isSafeId, AuditChain } = require('./securityUtils');
const { DATA_DIR, IS_LOCAL, VERSION, RETENTION } = require('./config');
const path = require('node:path');

/** Retention schedule published in the evidence pack (memory.md §3). */
const RETENTION_POLICY = {
  auditLogDays: RETENTION.auditDays,
  sessionDays: RETENTION.sessionDays,
  note: 'Raw telemetry 90d → aggregated 2y; k≥20 cohort aggregation (GDPR Art.25).',
};

/** Audit chain singleton (A.8.15 — immutable, hash-chained). */
const audit = new AuditChain(path.join(DATA_DIR, 'audit.log'));

function json(res, status, obj) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.end(JSON.stringify(obj));
}

/** Standard error responder (no stack traces leaked — ASVS V7). */
function fail(res, status, code, extra = {}) {
  json(res, status, { error: code, ...extra });
}

/** Rate limit wrapper keyed by IP + bucket. */
function limit(req, res, bucket, cfg) {
  const rl = rateLimit(`${bucket}:${req.socket.remoteAddress || 'unknown'}`, cfg);
  if (!rl.allowed) {
    res.setHeader('Retry-After', String(rl.retryAfter));
    fail(res, 429, 'rate_limited', { retryAfter: rl.retryAfter });
    return false;
  }
  return true;
}

function createRoutes() {
  const app = createApp();

  // ─── Health / metadata ────────────────────────────────────────────────
  app.get('/api/health', (req, res) => {
    json(res, 200, {
      status: 'ok',
      service: 'webxr-security-training',
      version: VERSION,
      auditChainValid: audit.verify().valid,
      time: new Date().toISOString(),
    });
  });

  // ─── Auth (OWASP A07; NIST AC-7) ──────────────────────────────────────
  app.post('/api/auth/login', async (req, res) => {
    if (!limit(req, res, 'login', { windowMs: 60000, max: 5 })) return;
    let body;
    try {
      body = await readJsonBody(req, 4096);
    } catch (e) {
      return fail(res, 400, e.message);
    }
    const result = auth.login(body.email, body.password, {
      ip: req.socket.remoteAddress || 'unknown',
    });
    if (result.error === 'too_many_attempts') {
      res.setHeader('Retry-After', String(result.retryAfter));
      return fail(res, 429, result.error, { retryAfter: result.retryAfter });
    }
    if (result.error) return fail(res, 401, result.error);
    audit.append({ actor: result.user.id, action: 'auth.login', detail: { method: 'password' } });
    json(res, 200, result);
  });

  app.post('/api/auth/demo-login', (req, res) => {
    if (!IS_LOCAL) return fail(res, 404, 'not_found');
    if (!limit(req, res, 'demo', { windowMs: 60000, max: 10 })) return;
    const result = auth.demoLogin({ ip: req.socket.remoteAddress || 'unknown' });
    if (result.error) return fail(res, 429, result.error);
    audit.append({ actor: result.user.id, action: 'auth.demo_login', detail: { mode: 'local' } });
    json(res, 200, result);
  });

  app.get('/api/auth/me', (req, res) => {
    const user = auth.requireAuth(req, res);
    if (!user) return;
    const full = auth.getUserById(user.sub);
    if (!full) return fail(res, 404, 'user_not_found');
    json(res, 200, { user: auth.publicUser(full) });
  });

  // ─── Module catalog (authenticated) ───────────────────────────────────
  app.get('/api/modules', (req, res) => {
    if (!auth.requireAuth(req, res)) return;
    json(res, 200, {
      modules: MODULES.map(catalogEntry),
      categories: CATEGORIES,
      capabilities: {
        deviceClasses: sessions.DEVICE_CLASSES,
        telemetryEvents: sessions.TELEMETRY_EVENTS,
        actions: campaigns.ACTIONS,
      },
    });
  });

  // ─── Sessions ─────────────────────────────────────────────────────────
  app.post('/api/sessions/start', async (req, res) => {
    if (!auth.requireAuth(req, res)) return;
    if (!limit(req, res, 'start', { windowMs: 60000, max: 30 })) return;
    let body;
    try {
      body = await readJsonBody(req, 2048);
    } catch (e) {
      return fail(res, 400, e.message);
    }
    if (!isSafeId(body.moduleId)) return fail(res, 400, 'invalid_module_id');
    const result = sessions.startSession(req.user, body.moduleId, { deviceClass: body.deviceClass });
    if (result.error) return fail(res, 404, result.error);
    audit.append({
      actor: req.user.sub,
      action: 'session.start',
      detail: {
        sessionId: result.session.id,
        moduleId: body.moduleId,
        deviceClass: result.session.deviceClass,
      },
    });
    json(res, 201, result);
  });

  app.post('/api/sessions/:id/telemetry', async (req, res) => {
    if (!auth.requireAuth(req, res)) return;
    if (!limit(req, res, 'telemetry', { windowMs: 60000, max: 120 })) return;
    if (!isSafeId(req.params.id)) return fail(res, 400, 'invalid_session_id');
    let body;
    try {
      body = await readJsonBody(req, 8192);
    } catch (e) {
      return fail(res, 400, e.message);
    }
    const result = sessions.recordTelemetry(req.user, req.params.id, body.events);
    if (result.error === 'not_found') return fail(res, 404, result.error);
    if (result.error) return fail(res, 400, result.error);
    json(res, 200, result);
  });

  app.post('/api/sessions/:id/complete', async (req, res) => {
    if (!auth.requireAuth(req, res)) return;
    if (!limit(req, res, 'complete', { windowMs: 60000, max: 30 })) return;
    if (!isSafeId(req.params.id)) return fail(res, 400, 'invalid_session_id');
    let body;
    try {
      body = await readJsonBody(req, 16384);
    } catch (e) {
      return fail(res, 400, e.message);
    }
    const result = sessions.completeSession(req.user, req.params.id, body.results);
    if (result.error === 'not_found') return fail(res, 404, result.error);
    if (result.error) return fail(res, 400, result.error);
    audit.append({
      actor: req.user.sub,
      action: 'session.complete',
      detail: {
        sessionId: req.params.id,
        riskScore: result.score.riskScore,
        trapHits: result.score.trapHits,
        deviceClass: result.session.deviceClass,
      },
    });
    json(res, 200, result);
  });

  app.get('/api/sessions/:id', (req, res) => {
    if (!auth.requireAuth(req, res)) return;
    if (!isSafeId(req.params.id)) return fail(res, 400, 'invalid_session_id');
    const s = sessions.getSession(req.user, req.params.id);
    if (!s) return fail(res, 404, 'not_found');
    json(res, 200, { session: s });
  });

  app.get('/api/sessions', (req, res) => {
    if (!auth.requireAuth(req, res)) return;
    const all = req.query.all === '1' && req.user.role === 'admin';
    json(res, 200, { sessions: sessions.listSessions(req.user, { all }) });
  });

  app.get('/api/stats/risk', (req, res) => {
    if (!auth.requireAuth(req, res)) return;
    json(res, 200, sessions.riskStats(req.user));
  });

  // ─── Simulated threat inbox (Campaign Svc — ISO A.6.3) ────────────────
  app.get('/api/campaigns/inbox', (req, res) => {
    if (!auth.requireAuth(req, res)) return;
    json(res, 200, {
      messages: campaigns.inboxFor(req.user),
      metrics: campaigns.userMetrics(req.user),
    });
  });

  app.post('/api/campaigns/:id/triage', async (req, res) => {
    if (!auth.requireAuth(req, res)) return;
    if (!limit(req, res, 'triage', { windowMs: 60000, max: 30 })) return;
    let body;
    try {
      body = await readJsonBody(req, 2048);
    } catch (e) {
      return fail(res, 400, e.message);
    }
    const result = campaigns.triage(req.user, req.params.id, body.messageId, body.action);
    if (result.error === 'not_found') return fail(res, 404, result.error);
    if (result.error) return fail(res, 400, result.error);
    audit.append({
      actor: req.user.sub,
      action: 'campaign.triage',
      detail: {
        campaignId: req.params.id,
        action: body.action,
        correct: result.message.correct,
      },
    });
    json(res, 200, result);
  });

  // ─── Framework alignment reference data (Compliance view) ─────────────
  app.get('/api/frameworks', (req, res) => {
    if (!auth.requireAuth(req, res)) return;
    json(res, 200, frameworks);
  });

  // ─── Admin: user provisioning (SCIM-style) ────────────────────────────
  app.get('/api/admin/users', (req, res) => {
    if (!auth.requireRole(req, res, ['admin'])) return;
    json(res, 200, { users: auth.listUsers() });
  });

  app.post('/api/admin/users', async (req, res) => {
    if (!auth.requireRole(req, res, ['admin'])) return;
    if (!limit(req, res, 'admin-users', { windowMs: 60000, max: 20 })) return;
    let body;
    try {
      body = await readJsonBody(req, 4096);
    } catch (e) {
      return fail(res, 400, e.message);
    }
    const result = auth.createUser({
      email: body.email,
      name: body.name,
      role: body.role,
      password: body.password,
    });
    if (result.error) return fail(res, 400, result.error);
    audit.append({
      actor: req.user.sub,
      action: 'admin.user_created',
      detail: { userId: result.user.id, role: result.user.role },
    });
    json(res, 201, result);
  });

  // ─── Admin: campaign orchestration + org analytics ────────────────────
  app.get('/api/admin/campaigns', (req, res) => {
    if (!auth.requireRole(req, res, ['admin'])) return;
    json(res, 200, {
      campaigns: campaigns.listCampaigns(),
      templates: campaigns.TEMPLATES,
      organization: campaigns.organizationMetrics(),
    });
  });

  app.post('/api/admin/campaigns', async (req, res) => {
    if (!auth.requireRole(req, res, ['admin'])) return;
    if (!limit(req, res, 'admin-campaigns', { windowMs: 60000, max: 20 })) return;
    let body;
    try {
      body = await readJsonBody(req, 4096);
    } catch (e) {
      return fail(res, 400, e.message);
    }
    const result = campaigns.createCampaign({
      name: body.name,
      templateId: body.templateId,
      targetRole: body.targetRole,
      createdBy: req.user.sub,
    });
    if (result.error === 'unknown_template') return fail(res, 400, result.error);
    if (result.error) return fail(res, 409, result.error);
    audit.append({
      actor: req.user.sub,
      action: 'admin.campaign_created',
      detail: { campaignId: result.campaign.id, templateId: body.templateId, targetRole: result.campaign.targetRole },
    });
    json(res, 201, result);
  });

  app.get('/api/admin/analytics', (req, res) => {
    if (!auth.requireRole(req, res, ['admin'])) return;
    json(res, 200, {
      organization: sessions.organizationAnalytics(auth.listUsers()),
      campaigns: campaigns.organizationMetrics(),
    });
  });

  /**
   * Compliance evidence pack (ISO A.6.3 / A.8.15 / SOC 2 CC7.2).
   * A single verifiable JSON artifact: cohort completion, risk posture,
   * simulation funnel and audit-chain integrity proof.
   */
  app.get('/api/admin/evidence', (req, res) => {
    if (!auth.requireRole(req, res, ['admin'])) return;
    const chain = audit.verify();
    const org = sessions.organizationAnalytics(auth.listUsers());
    const pack = {
      artifact: 'ISO27001-A.6.3-awareness-evidence',
      generatedAt: new Date().toISOString(),
      generatedBy: req.user.sub,
      service: 'webxr-security-training',
      version: VERSION,
      auditChain: chain,
      training: org.totals,
      moduleCoverage: org.moduleHeat,
      learners: org.users.map((u) => ({ name: u.name, role: u.role, completed: u.completed, avgScore: u.avgScore })),
      simulation: campaigns.organizationMetrics(),
      retention: RETENTION_POLICY,
    };
    audit.append({
      actor: req.user.sub,
      action: 'admin.evidence_exported',
      detail: { chainValid: chain.valid, completed: org.totals.completed },
    });
    json(res, 200, pack);
  });

  // ─── Admin: audit log verification (A.8.15 evidence export) ───────────
  app.get('/api/admin/audit/verify', (req, res) => {
    if (!auth.requireRole(req, res, ['admin'])) return;
    json(res, 200, audit.verify());
  });

  app.get('/api/admin/audit', (req, res) => {
    if (!auth.requireRole(req, res, ['admin'])) return;
    const fs = require('node:fs');
    const file = path.join(DATA_DIR, 'audit.log');
    if (!fs.existsSync(file)) return json(res, 200, { entries: [] });
    const entries = fs
      .readFileSync(file, 'utf8')
      .split('\n')
      .filter(Boolean)
      .slice(-500)
      .map((l) => {
        try {
          return JSON.parse(l);
        } catch {
          return { corrupt: true };
        }
      });
    json(res, 200, { entries });
  });

  return app;
}

module.exports = { createRoutes, audit };
