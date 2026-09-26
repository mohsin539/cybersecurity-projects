'use strict';
/**
 * sessions.js — Training session lifecycle + xAPI-style record keeping.
 * Scores are computed server-side only (OWASP A04 — clients never decide scores).
 */

const crypto = require('node:crypto');
const { load, save } = require('./db');
const { getModule, bundleEntry, scoreSession } = require('./modules');
const { isSafeId } = require('./securityUtils');

const SESSIONS_FILE = 'sessions';

/** Device classes accepted from client capability telemetry (architecture.md §6). */
const DEVICE_CLASSES = ['vr', 'ar', 'desktop', 'mobile', 'tablet'];

/** Aggregate telemetry event allow-list (GDPR Art.25 — no gaze, no biometrics). */
const TELEMETRY_EVENTS = [
  'scene.enter',
  'choice.make',
  'feedback.view',
  'xr.session.start',
  'xr.session.end',
  'integrity.checked',
];

/**
 * Start a training session. Validates module id; returns the signed scenario
 * bundle descriptor with a SHA-256 integrity hash the client verifies before
 * rendering (architecture.md §6 "Content Integrity Verifier", NIST SI-7).
 */
function startSession(user, moduleId, { deviceClass = null } = {}) {
  const mod = getModule(moduleId);
  if (!mod) return { error: 'unknown_module' };

  const device = DEVICE_CLASSES.includes(deviceClass) ? deviceClass : 'desktop';
  const sessions = load(SESSIONS_FILE);
  const session = {
    id: `s-${crypto.randomBytes(12).toString('hex')}`,
    userId: user.sub,
    moduleId,
    deviceClass: device,
    status: 'active',
    startedAt: Date.now(),
    completedAt: null,
    riskScore: null,
    correct: null,
    total: null,
    trapHits: null,
    telemetry: {},
    xapi: [], // xAPI-style statements (actor = server, never client-asserted)
  };
  sessions.push(session);
  save(SESSIONS_FILE, sessions);

  return { session, module: bundleEntry(mod) };
}

/**
 * Complete a session with results. Server recomputes the score from the
 * scenario definition — client-reported scores are ignored (A04).
 */
function completeSession(user, sessionId, results) {
  if (!Array.isArray(results) || results.length === 0 || results.length > 100) {
    return { error: 'invalid_results' };
  }
  if (!isSafeId(sessionId)) return { error: 'invalid_session_id' };
  const sessions = load(SESSIONS_FILE);
  const s = sessions.find((x) => x.id === sessionId && x.userId === user.sub);
  if (!s) return { error: 'not_found' };
  if (s.status !== 'active') return { error: 'already_completed' };

  const mod = getModule(s.moduleId);
  if (!mod) return { error: 'unknown_module' };

  // Sanitize: each result must reference a real node with a real option
  const clean = [];
  const seen = new Set();
  for (const r of results) {
    if (!r || typeof r !== 'object') continue;
    if (!isSafeId(r.nodeId) || !isSafeId(r.choice)) continue;
    if (seen.has(r.nodeId)) continue; // first answer per node wins (anti-replay)
    const node = mod.nodes.find((n) => n.id === r.nodeId);
    if (!node) continue;
    const choice = node.options.find((o) => o.id === r.choice);
    if (!choice) continue;
    seen.add(node.id);
    clean.push({ nodeId: node.id, choice: choice.id });
  }
  if (clean.length === 0) return { error: 'invalid_results' };

  const score = scoreSession(mod, clean);
  s.status = 'completed';
  s.completedAt = Date.now();
  s.riskScore = score.riskScore;
  s.correct = score.correct;
  s.total = score.total;
  s.trapHits = score.trapHits;
  s.results = clean;
  s.xapi.push({
    verb: 'completed',
    object: { id: s.moduleId, definition: { name: mod.ref } },
    result: {
      score: { scaled: score.riskScore / 100, raw: score.riskScore, min: 0, max: 100 },
      success: score.riskScore >= 70,
      completion: true,
    },
    context: { device: s.deviceClass, extensions: `https://w3id.org/xapi/xr/${s.deviceClass}` },
    timestamp: new Date().toISOString(),
  });
  save(SESSIONS_FILE, sessions);

  return { session: s, score, debrief: buildDebrief(mod, clean) };
}

/**
 * Per-node debrief. Shows the learner's answer beside the correct one with the
 * rationale — the learning moment (ISO A.6.3 effectiveness, not just attendance).
 */
function buildDebrief(mod, results) {
  const byNode = new Map(results.map((r) => [r.nodeId, r.choice]));
  return {
    moduleId: mod.id,
    ref: mod.ref,
    nodes: mod.nodes.map((node) => {
      const chosenId = byNode.get(node.id) || null;
      const chosen = node.options.find((o) => o.id === chosenId) || null;
      const correct = node.options.find((o) => o.id === node.correct) || null;
      return {
        nodeId: node.id,
        scene: node.scene || mod.scene,
        prompt: node.prompt,
        chosenText: chosen ? chosen.text : 'No answer recorded',
        correctId: node.correct,
        correctText: correct ? correct.text : '',
        isCorrect: chosenId === node.correct,
        trapped: Boolean(chosen && chosen.isTrap),
        explain: node.explain,
      };
    }),
  };
}

/** Aggregate-only telemetry ingestion. Counts per event type, never raw data. */
function recordTelemetry(user, sessionId, events) {
  if (!isSafeId(sessionId)) return { error: 'invalid_session_id' };
  if (!Array.isArray(events) || events.length === 0 || events.length > 200) {
    return { error: 'invalid_results' };
  }
  const sessions = load(SESSIONS_FILE);
  const s = sessions.find((x) => x.id === sessionId && x.userId === user.sub);
  if (!s) return { error: 'not_found' };
  if (s.telemetry === undefined) s.telemetry = {};

  for (const e of events) {
    const type = e && typeof e.type === 'string' ? e.type : null;
    if (!type || !TELEMETRY_EVENTS.includes(type)) continue; // deny-by-default allow-list
    s.telemetry[type] = (s.telemetry[type] || 0) + 1;
  }
  s.telemetryLastAt = Date.now();
  save(SESSIONS_FILE, sessions);
  return { telemetry: s.telemetry };
}

/** Get one session owned by the caller (object-level authz — OWASP A01). */
function getSession(user, sessionId) {
  return load(SESSIONS_FILE).find((x) => x.id === sessionId && x.userId === user.sub) || null;
}

/** List sessions for the caller. Admins may pass all=true. */
function listSessions(user, { all = false, limit = 200 } = {}) {
  const sessions = load(SESSIONS_FILE);
  const scoped = all && user.role === 'admin' ? sessions : sessions.filter((s) => s.userId === user.sub);
  return scoped.slice(-limit);
}

/** Aggregate risk stats for dashboards (org-wide for admins, self for learners). */
function riskStats(user) {
  const sessions = listSessions(user, { all: user.role === 'admin' });
  const done = sessions.filter((s) => s.status === 'completed');
  const avg = done.length ? Math.round(done.reduce((a, s) => a + s.riskScore, 0) / done.length) : null;
  const byModule = {};
  for (const s of done) {
    byModule[s.moduleId] = byModule[s.moduleId] || { count: 0, sum: 0, trapHits: 0 };
    byModule[s.moduleId].count += 1;
    byModule[s.moduleId].sum += s.riskScore;
    byModule[s.moduleId].trapHits += s.trapHits || 0;
  }
  for (const k of Object.keys(byModule)) {
    byModule[k].avgScore = Math.round(byModule[k].sum / byModule[k].count);
    byModule[k].trapRate = Math.round((byModule[k].trapHits / byModule[k].count) * 100) / 100;
    delete byModule[k].sum;
  }
  const rank = Object.entries(byModule).sort((a, b) => a[1].avgScore - b[1].avgScore);
  return {
    totalSessions: sessions.length,
    completed: done.length,
    active: sessions.filter((s) => s.status === 'active').length,
    avgRiskScore: avg,
    totalTrapHits: done.reduce((a, s) => a + (s.trapHits || 0), 0),
    byModule,
    strongestModule: rank.length ? rank[rank.length - 1][0] : null,
    weakestModule: rank.length ? rank[0][0] : null,
  };
}

/**
 * Organization analytics (admin) — ISO 27001 A.6.3 / SOC 2 evidence rollup.
 * Aggregated per user; no PII beyond display name and role.
 */
function organizationAnalytics(users) {
  const sessions = load(SESSIONS_FILE);
  const done = sessions.filter((s) => s.status === 'completed');
  const byUser = new Map();
  for (const s of done) {
    const rec = byUser.get(s.userId) || { completed: 0, sum: 0, traps: 0, modules: new Set() };
    rec.completed += 1;
    rec.sum += s.riskScore || 0;
    rec.traps += s.trapHits || 0;
    rec.modules.add(s.moduleId);
    byUser.set(s.userId, rec);
  }
  const rows = users
    .map((u) => {
      const rec = byUser.get(u.id);
      return {
        userId: u.id,
        name: u.name,
        role: u.role,
        completed: rec ? rec.completed : 0,
        avgScore: rec ? Math.round(rec.sum / rec.completed) : null,
        trapHits: rec ? rec.traps : 0,
        coverage: rec ? rec.modules.size : 0,
      };
    })
    .sort((a, b) => (b.avgScore ?? -1) - (a.avgScore ?? -1));

  const catalog = require('./modules').MODULES;
  const completionRate = sessions.length ? Math.round((done.length / sessions.length) * 100) : 0;
  return {
    totals: {
      users: users.length,
      sessions: sessions.length,
      completed: done.length,
      active: sessions.filter((s) => s.status === 'active').length,
      completionRate,
      avgScore: done.length ? Math.round(done.reduce((a, s) => a + s.riskScore, 0) / done.length) : null,
      coveragePct: catalog.length ? Math.round((new Set(done.map((s) => s.moduleId)).size / catalog.length) * 100) : 0,
      atRiskUsers: rows.filter((r) => r.avgScore !== null && r.avgScore < 60).length,
      untrainedUsers: rows.filter((r) => r.completed === 0).length,
    },
    users: rows,
    moduleHeat: catalog.map((m) => {
      const rel = done.filter((s) => s.moduleId === m.id);
      return {
        moduleId: m.id,
        title: m.title,
        visual: m.visual,
        completed: rel.length,
        avgScore: rel.length ? Math.round(rel.reduce((a, s) => a + s.riskScore, 0) / rel.length) : null,
      };
    }),
  };
}

module.exports = {
  startSession,
  completeSession,
  recordTelemetry,
  getSession,
  listSessions,
  riskStats,
  organizationAnalytics,
  DEVICE_CLASSES,
  TELEMETRY_EVENTS,
};
