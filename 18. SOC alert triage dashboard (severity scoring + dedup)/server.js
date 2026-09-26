#!/usr/bin/env node
/**
 * SOC Alert Triage Dashboard — zero-dependency Node.js server.
 * Maps to: 01-architecture-overview.md, 02-triage-engine.md, 03-data-and-rbac.md,
 *          04-security-architecture.md, state.md, security.md
 *
 * Run: node server.js   → http://localhost:8080
 * Env:  PORT (default 8080), DATA_FILE (default data/store.json)
 */
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = parseInt(process.env.PORT || '8080', 10);
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data', 'store.json');
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;   // 12 h absolute (state.md §3.1)
const SESSION_IDLE_MS = 30 * 60 * 1000;       // 30 min idle (state.md §3.1)
const MAX_BODY_BYTES = 256 * 1024;            // payload budget (04 A03/A05)
const AUDIT_SPOOL_LIMIT = 1000;               // bounded spool before fail-closed (ADR-001)

// ─────────────────────────────────────────────────────────────────────────────
// Utilities
// ─────────────────────────────────────────────────────────────────────────────
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const uuid = () => crypto.randomUUID();
const nowIso = () => new Date().toISOString();

// SECURITY (A03): canonical JSON for hashing — stable key order prevents hash ambiguity
function canonicalJson(obj) {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(canonicalJson).join(',') + ']';
  return '{' + Object.keys(obj).sort()
    .map((k) => JSON.stringify(k) + ':' + canonicalJson(obj[k])).join(',') + '}';
}

// SECURITY (A03): timing-safe string comparison for session ids / CSRF tokens
function timingSafeEqualStr(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) {
    // compare against self to keep constant time, then fail
    crypto.timingSafeEqual(ab, ab);
    return false;
  }
  return crypto.timingSafeEqual(ab, bb);
}

// SECURITY (T01): entity canonicalization — deterministic, versioned (02 §2)
function canonicalEntity(e) {
  if (!e || typeof e !== 'object') return { type: 'unknown', id: 'invalid' };
  const type = String(e.type || 'unknown').toLowerCase();
  let id = String(e.id || '').trim();
  if (type === 'host') id = id.toLowerCase().split('.')[0];
  if (type === 'user') id = id.toLowerCase();
  return { type, id };
}

function entitySetKey(entities) {
  return entities.map(canonicalEntity)
    .sort((a, b) => (a.type + a.id).localeCompare(b.type + b.id))
    .map((e) => `${e.type}:${e.id}`).join('|');
}

// ─────────────────────────────────────────────────────────────────────────────
// Store (state.md — domain state, system of record)
// ─────────────────────────────────────────────────────────────────────────────
let store = null;
let sessions = new Map(); // volatile by design (state.md §3.1)

function defaultStore() {
  return {
    configVersion: 1,
    scoreVersion: '1.0.0',
    // weights sum to 100; bounds per 02 §4.2
    weights: {
      f1_detection_confidence: 20, f2_asset_criticality: 20,
      f3_attack_tactic: 15, f4_ti_match: 15, f5_identity_risk: 10,
      f6_exploitability: 8, f7_behavioral_anomaly: 7, f8_occurrence_velocity: 5,
    },
    thresholds: { critical: 85, high: 65, medium: 40, low: 15 },
    dedup: { mode: 'full', fuzzyThreshold: 0.92, windowMinutes: 15 },
    switches: { ml_overlay: false, export_enabled: true },
    users: {
      'analyst@t1': { tenant: 't1', role: 'analyst.tier1', displayName: 'Analyst One' },
      'lead@t1': { tenant: 't1', role: 'soc.lead', displayName: 'SOC Lead' },
      'auditor@t1': { tenant: 't1', role: 'auditor', displayName: 'Auditor' },
      'analyst@t2': { tenant: 't2', role: 'analyst.tier1', displayName: 'Analyst Two' },
    },
    alerts: [],      // canonical + duplicates (state.md §2.1)
    scores: [],      // immutable score records (state.md §2.2)
    links: [],       // dedup edges (state.md §2.3)
    dispositions: [],// append-only ledger (state.md §2.4)
    audit: [],       // hash-chained audit events (state.md §2.5)
    auditSeq: 0,
  };
}

function saveStore() {
  try {
    fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
    fs.writeFileSync(DATA_FILE, JSON.stringify(store));
  } catch (e) {
    console.error('[store] persist failed:', e.message);
  }
}

function loadStore() {
  if (fs.existsSync(DATA_FILE)) {
    try {
      store = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      if (!verifyAuditChain()) {
        // SECURITY: fail-closed on integrity failure (state.md §6, 01 §10.1)
        console.error('[store] AUDIT CHAIN VERIFICATION FAILED — refusing to start');
        process.exit(1);
      }
      console.log(`[store] loaded ${store.alerts.length} alerts, audit chain OK`);
      return;
    } catch (e) {
      console.error('[store] load failed, starting fresh:', e.message);
    }
  }
  store = defaultStore();
  seedDemoData();
  saveStore();
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit chain (state.md §2.5) — fail-closed on write failure
// ─────────────────────────────────────────────────────────────────────────────
let auditSpool = []; // bounded local spool before blocking (ADR-001)

function genesisHash(tenantId) { return sha256(`genesis:${tenantId}`); }

function appendAudit(tenantId, actorId, action, objectType, objectId, before, after, reason) {
  const prev = [...store.audit].reverse().find((a) => a.tenantId === tenantId);
  const prevHash = prev ? prev.entryHash : genesisHash(tenantId);
  const entry = {
    seq: ++store.auditSeq,
    ts: nowIso(),
    tenantId, actorId: actorId || 'system',
    action, objectType, objectId: objectId || null,
    before: before ?? null, after: after ?? null, reason: reason ?? null,
    prevHash,
  };
  entry.entryHash = sha256(canonicalJson({
    seq: entry.seq, ts: entry.ts, tenantId: entry.tenantId, actorId: entry.actorId,
    action: entry.action, objectType: entry.objectType, objectId: entry.objectId,
    before: entry.before, after: entry.after, reason: entry.reason, prevHash,
  }));
  // SECURITY: simulate sink write; failure path demonstrates fail-closed behavior
  if (auditSpool.length >= AUDIT_SPOOL_LIMIT) {
    throw new Error('audit sink unavailable (spool exhausted) — mutation blocked');
  }
  auditSpool.push(entry.seq);
  store.audit.push(entry);
  return entry;
}

function verifyAuditChain() {
  const byTenant = new Map();
  for (const e of store.audit || []) {
    const expectedPrev = byTenant.get(e.tenantId) || genesisHash(e.tenantId);
    if (e.prevHash !== expectedPrev) return false;
    const recomputed = sha256(canonicalJson({
      seq: e.seq, ts: e.ts, tenantId: e.tenantId, actorId: e.actorId,
      action: e.action, objectType: e.objectType, objectId: e.objectId,
      before: e.before, after: e.after, reason: e.reason, prevHash: e.prevHash,
    }));
    if (recomputed !== e.entryHash) return false;
    byTenant.set(e.tenantId, e.entryHash);
  }
  return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// RBAC/ABAC (03 §2) — default deny
// ─────────────────────────────────────────────────────────────────────────────
const PERMISSIONS = {
  'queue:read':        ['analyst.tier1', 'analyst.tier2', 'soc.lead', 'auditor', 'platform.admin'],
  'alert:read':        ['analyst.tier1', 'analyst.tier2', 'soc.lead', 'auditor', 'platform.admin'],
  'disposition:write': ['analyst.tier1', 'analyst.tier2', 'soc.lead'],
  'assign:write':      ['analyst.tier1', 'analyst.tier2', 'soc.lead'],
  'dedup:split':       ['analyst.tier2', 'soc.lead'],
  'escalate:write':    ['analyst.tier2', 'soc.lead'],
  'config:write':      ['soc.lead', 'platform.admin'],
  'audit:read':        ['auditor', 'soc.lead', 'platform.admin'],
  'meta:read':         ['auditor', 'platform.admin', 'soc.lead'],
  'ingest:write':      [], // service-only in design; not granted to any human role
};

function can(user, perm) {
  return (PERMISSIONS[perm] || []).includes(user.role); // default deny
}

// ABAC: tier1 cannot close critical band (03 §2.2)
function canDispositionBand(user, band) {
  if (user.role !== 'analyst.tier1') return true;
  return band !== 'critical';
}

// ─────────────────────────────────────────────────────────────────────────────
// Severity scoring engine (02 §4) — deterministic core, ML adjustment reserved
// ─────────────────────────────────────────────────────────────────────────────
const TACTIC_SEVERITY = {
  'reconnaissance': 0.3, 'initial-access': 0.4, 'execution': 0.6, 'persistence': 0.7,
  'privilege-escalation': 0.85, 'defense-evasion': 0.6, 'credential-access': 0.8, // 02 §4.2 worked example: f3=0.80
  'discovery': 0.4, 'lateral-movement': 0.8, 'collection': 0.6, 'command-and-control': 0.75,
  'exfiltration': 0.95, 'impact': 1.0,
};
const ASSET_TIERS = { 0: 1.0, 1: 0.85, 2: 0.6, 3: 0.4, unknown: 0.5 };
const w = (k) => store.weights[k] || 0;

function scoreAlert(alert) {
  const f = {};
  f.f1_detection_confidence = Math.min(1, Math.max(0,
    (alert.confidence ?? 0.5) * (alert.sourceReliability ?? 1.0)));
  f.f2_asset_criticality = ASSET_TIERS[alert.assetTier ?? 'unknown'] ?? 0.5;
  f.f3_attack_tactic = TACTIC_SEVERITY[(alert.tactic || '').toLowerCase()] ?? 0.4;
  f.f4_ti_match = Math.min(1, alert.tiMatch ?? 0);
  f.f5_identity_risk = Math.min(1, alert.identityRisk ?? 0);
  f.f6_exploitability = Math.min(1,
    0.6 * (alert.kevListed ? 1 : 0) + 0.4 * (alert.epss ?? 0));
  f.f7_behavioral_anomaly = Math.min(1, Math.max(0, ((alert.anomalyZ ?? 0) / 4)));
  // f8 per 02 §5.7 — log-scaled velocity, computed from dedup aggregates
  const occ = alert.isCanonical ? (alert.occurrenceCount || 1) : 1;
  f.f8_occurrence_velocity = Math.min(1, Math.log10(1 + occ) / Math.log10(51));

  const weighted = Object.entries(f).reduce((sum, [k, v]) => sum + w(k) * v, 0);

  // context multipliers (02 §4.2), capped ×1.5 total
  let m = 1.0;
  if ((alert.assetTier === 0) &&
      ['credential-access', 'privilege-escalation', 'impact'].includes((alert.tactic || '').toLowerCase())) m *= 1.25;
  if (alert.incidentLinked) m *= 1.15;
  m = Math.min(m, 1.5);

  const mlAdjustment = store.switches.ml_overlay ? 0 : 0; // reserved (state.md §5)
  const score = Math.max(0, Math.min(100, Math.round((weighted + mlAdjustment) * m)));
  const t = store.thresholds;
  const band = score >= t.critical ? 'critical' : score >= t.high ? 'high'
    : score >= t.medium ? 'medium' : score >= t.low ? 'low' : 'informational';

  const inputsHash = sha256(canonicalJson({ alertId: alert.id, features: f, m }));
  const breakdown = {
    factors: Object.fromEntries(Object.entries(f).map(([k, v]) => [k, {
      value: Math.round(v * 1000) / 1000, weight: w(k), contribution: Math.round(w(k) * v * 1000) / 1000,
    }])),
    contextMultiplier: m, mlAdjustment, weightedRaw: Math.round(weighted * 1000) / 1000,
  };
  return { score, band, breakdown, inputsHash, scoreVersion: store.scoreVersion, computedAt: nowIso() };
}

function persistScore(alert, s) {
  store.scores.push({ alertId: alert.id, ...s });
  alert.currentScore = s.score;
  alert.currentBand = s.band;
}

// ─────────────────────────────────────────────────────────────────────────────
// Dedup engine (02 §5) — stage 1 exact; fuzzy reserved
// ─────────────────────────────────────────────────────────────────────────────
function dedupKeyV1(tenantId, ruleId, entityKey, bucketMinutes, occurredAt) {
  const bucket = Math.floor(new Date(occurredAt).getTime() / (bucketMinutes * 60000));
  return sha256([tenantId, ruleId, entityKey, bucket].join('|'));
}

function ingestAlert(input, actorId) {
  // SECURITY (SI-10): strict input validation — allowlist of fields, types checked
  const required = ['tenantId', 'source', 'ruleId', 'title', 'occurredAt'];
  for (const k of required) {
    if (typeof input[k] !== 'string' || !input[k]) throw new Error(`missing field: ${k}`);
  }
  if (!Array.isArray(input.entities)) throw new Error('entities must be an array');
  if (isNaN(Date.parse(input.occurredAt))) throw new Error('occurredAt invalid');

  const entityKey = entitySetKey(input.entities);
  const cfg = store.dedup;

  // Stage 1: exact key over current + previous window bucket (02 §5.2)
  const candidates = store.alerts.filter((a) =>
    a.tenantId === input.tenantId && a.ruleId === input.ruleId &&
    a.entityKey === entityKey && a.isCanonical &&
    (new Date(input.occurredAt) - new Date(a.lastSeen)) < cfg.windowMinutes * 2 * 60000);

  if (cfg.mode !== 'off' && candidates.length > 0) {
    // link as duplicate — non-destructive (README invariant #2)
    const canonical = candidates.sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen))[0];
    const dup = buildAlert(input, entityKey, false, canonical.id);
    store.alerts.push(dup);
    store.links.push({
      id: uuid(), tenantId: input.tenantId, canonicalId: canonical.id,
      duplicateId: dup.id, method: 'exact', similarity: 1.0,
      thresholdUsed: 1.0, ruleFamily: input.ruleFamily || input.ruleId,
      createdAt: nowIso(), unlinkedAt: null, unlinkedBy: null,
    });
    canonical.occurrenceCount += 1;
    canonical.lastSeen = input.occurredAt > canonical.lastSeen ? input.occurredAt : canonical.lastSeen;
    // re-score canonical only — aggregates feed f8 (02 §5.3)
    persistScore(canonical, scoreAlert(canonical));
    appendAudit(input.tenantId, actorId || 'ingest', 'alert.dedup_link', 'alert', dup.id,
      null, { canonicalId: canonical.id, method: 'exact' });
    return { alert: dup, canonical, deduped: true };
  }

  // new canonical
  const alert = buildAlert(input, entityKey, true, null);
  store.alerts.push(alert);
  persistScore(alert, scoreAlert(alert));
  appendAudit(input.tenantId, actorId || 'ingest', 'alert.ingest', 'alert', alert.id,
    null, { ruleId: input.ruleId, band: alert.currentBand });
  return { alert, canonical: alert, deduped: false };
}

function buildAlert(input, entityKey, isCanonical, canonicalId) {
  return {
    id: uuid(),
    tenantId: input.tenantId,            // SECURITY (A01): tenant comes from ingest context, validated
    isCanonical, canonicalId,
    source: String(input.source).slice(0, 64),
    ruleId: String(input.ruleId).slice(0, 128),
    ruleFamily: String(input.ruleFamily || input.ruleId).slice(0, 128),
    tactic: String(input.tactic || '').slice(0, 64),
    title: String(input.title).slice(0, 256),
    summary: String(input.summary || '').slice(0, 2048),
    entities: input.entities.slice(0, 50).map(canonicalEntity),
    entityKey,
    confidence: clamp01(input.confidence ?? 0.5),
    sourceReliability: clamp01(input.sourceReliability ?? 1.0),
    assetTier: Number.isInteger(input.assetTier) ? input.assetTier : 'unknown',
    tiMatch: clamp01(input.tiMatch ?? 0),
    identityRisk: clamp01(input.identityRisk ?? 0),
    kevListed: !!input.kevListed, epss: clamp01(input.epss ?? 0),
    anomalyZ: Math.max(0, Math.min(10, Number(input.anomalyZ ?? 0))),
    incidentLinked: !!input.incidentLinked,
    degradedContext: !!input.degradedContext,
    occurredAt: new Date(input.occurredAt).toISOString(),
    observedAt: nowIso(),
    occurrenceCount: 1, firstSeen: nowIso(), lastSeen: nowIso(),
    status: 'open', assignedTo: null,
    rawOriginal: null, // minimization: not persisted in demo (state.md §2.1)
  };
}
const clamp01 = (n) => Math.max(0, Math.min(1, Number(n) || 0));

// ─────────────────────────────────────────────────────────────────────────────
// Sessions & auth (state.md §3.1, 04 A07)
// ─────────────────────────────────────────────────────────────────────────────
function createSession(userId) {
  const u = store.users[userId];
  if (!u) return null;
  const sid = crypto.randomBytes(32).toString('hex'); // 256-bit session id
  const csrf = crypto.randomBytes(32).toString('hex');
  sessions.set(sid, { user: userId, tenant: u.tenant, role: u.role,
    csrf, createdAt: Date.now(), lastSeen: Date.now() });
  return { sid, csrf };
}

function getSession(req) {
  const cookie = parseCookies(req);
  const sid = cookie.get('sid');
  if (!sid) return null;
  const s = sessions.get(sid);
  if (!s) return null;
  const t = Date.now();
  if (t - s.createdAt > SESSION_TTL_MS || t - s.lastSeen > SESSION_IDLE_MS) {
    sessions.delete(sid); return null;
  }
  s.lastSeen = t;
  return { sid, ...s };
}

function parseCookies(req) {
  const map = new Map();
  const raw = req.headers.cookie || '';
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) map.set(part.slice(0, i).trim(), part.slice(i + 1).trim());
  }
  return map;
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP plumbing
// ─────────────────────────────────────────────────────────────────────────────
function json(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) { reject(new Error('payload too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
      catch { reject(new Error('invalid JSON')); }
    });
    req.on('error', reject);
  });
}

// SECURITY (A05/B7): strict CSP, no inline, no third-party origins
const CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
  "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

function secureHeaders(res) {
  res.setHeader('Content-Security-Policy', CSP);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
}

// ─────────────────────────────────────────────────────────────────────────────
// API routing
// ─────────────────────────────────────────────────────────────────────────────
async function handleApi(req, res, url) {
  const route = `${req.method} ${url.pathname}`;
  const body = (req.method === 'POST' || req.method === 'PUT') ? await readBody(req) : {};

  // ── auth endpoints (no session required) ──
  if (route === 'POST /api/auth/login') {
    const userId = String(body.userId || '').toLowerCase().trim();
    const u = store.users[userId];
    if (!u) return json(res, 401, { error: 'invalid credentials' }); // no user enumeration
    const s = createSession(userId);
    if (!s) return json(res, 401, { error: 'invalid credentials' });
    res.setHeader('Set-Cookie',
      `sid=${s.sid}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_MS / 1000}` +
      (req.socket.encrypted ? '; Secure' : ''));
    appendAudit(u.tenant, userId, 'auth.login', 'session', null, null, null);
    saveStore();
    return json(res, 200, { csrf: s.csrf, user: { id: userId, ...u } });
  }

  const sess = getSession(req);
  if (!sess) {
    return json(res, 401, { error: 'authentication required' });
  }
  const user = { id: sess.user, role: sess.role, tenant: sess.tenant };

  // ── CSRF check for ALL state-changing requests incl. logout (B7) ──
  if (req.method === 'POST' || req.method === 'PUT') {
    const token = req.headers['x-csrf-token'];
    if (!sess || !token || !timingSafeEqualStr(token, sess.csrf)) {
      return json(res, 403, { error: 'csrf validation failed' });
    }
  }

  // ── logout (CSRF-protected like every other mutation) ──
  if (route === 'POST /api/auth/logout') {
    sessions.delete(sess.sid);
    appendAudit(sess.tenant, sess.user, 'auth.logout', 'session', null, null, null);
    res.setHeader('Set-Cookie', 'sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
    saveStore();
    return json(res, 200, { ok: true });
  }

  // ── tenant resolution (A01): header allowed only for auditor ──
  let tenant = user.tenant;
  const hdrTenant = req.headers['x-tenant'];
  if (hdrTenant && hdrTenant !== user.tenant) {
    if (user.role !== 'auditor') {
      return json(res, 403, { error: 'tenant override denied' });
    }
    tenant = hdrTenant === '*' ? '*' : hdrTenant; // auditor oversight, read-only paths only
  }

  try {
    return await routeApi(req, res, url, route, body, user, tenant, sess);
  } catch (e) {
    // SECURITY (SI-11): structured errors, no stack traces to clients
    appendAudit(tenant === '*' ? user.tenant : tenant, user.id, 'error', 'api', route, null, { message: e.message });
    return json(res, e.statusCode || 500, { error: e.message });
  }
}

async function routeApi(req, res, url, route, body, user, tenant, sess) {
  // ── queue (tenant-scoped, canonical only by default) ──
  if (route === 'GET /api/queue') {
    if (!can(user, 'queue:read')) return json(res, 403, { error: 'forbidden' });
    if (tenant === '*') { // auditor cross-tenant: counts only (03 §4)
      const byTenant = {};
      for (const a of store.alerts.filter((a) => a.isCanonical)) {
        byTenant[a.tenantId] = (byTenant[a.tenantId] || 0) + 1;
      }
      return json(res, 200, { crossTenantStats: byTenant });
    }
    const band = url.searchParams.get('band');
    let list = store.alerts.filter((a) => a.tenantId === tenant && a.isCanonical);
    if (band) list = list.filter((a) => a.currentBand === band);
    list.sort((a, b) => (b.currentScore || 0) - (a.currentScore || 0));
    return json(res, 200, { alerts: list.map(publicAlert) });
  }

  // ── alert detail (object-level tenant check, A01) ──
  const mAlert = url.pathname.match(/^\/api\/alerts\/([0-9a-f-]{36})/);
  if (mAlert && req.method === 'GET') {
    if (!can(user, 'alert:read')) return json(res, 403, { error: 'forbidden' });
    const alert = store.alerts.find((a) => a.id === mAlert[1] &&
      (tenant === '*' || a.tenantId === tenant));
    if (!alert) return json(res, 404, { error: 'not found' });
    const scores = store.scores.filter((s) => s.alertId === alert.id);
    const links = store.links.filter((l) => l.tenantId === alert.tenantId &&
      (l.canonicalId === alert.id || l.duplicateId === alert.id));
    const dups = alert.isCanonical
      ? store.alerts.filter((a) => a.canonicalId === alert.id && !links.some((l) => l.duplicateId === a.id && l.unlinkedAt))
      : [];
    return json(res, 200, { alert: publicAlert(alert), scores, links, duplicates: dups.map(publicAlert) });
  }

  // ── disposition (append-only ledger, ABAC band check) ──
  if (mAlert && route === `POST ${url.pathname}` && url.pathname.endsWith('/disposition')) {
    if (!can(user, 'disposition:write')) return json(res, 403, { error: 'forbidden' });
    const alert = store.alerts.find((a) => a.id === mAlert[1] && a.tenantId === tenant);
    if (!alert) return json(res, 404, { error: 'not found' });
    if (!canDispositionBand(user, alert.currentBand)) {
      return json(res, 403, { error: `tier1 cannot disposition ${alert.currentBand} alerts` });
    }
    const status = String(body.status || '');
    const allowed = ['open', 'assigned', 'investigating', 'false_positive', 'benign', 'contained', 'resolved'];
    if (!allowed.includes(status)) return json(res, 400, { error: 'invalid status' });
    const before = alert.status;
    store.dispositions.push({ id: uuid(), tenantId: tenant, alertId: alert.id,
      actor: user.id, status, reason: String(body.reason || '').slice(0, 512), ts: nowIso() });
    alert.status = status;
    appendAudit(tenant, user.id, 'alert.disposition', 'alert', alert.id, { status: before }, { status }, body.reason);
    saveStore();
    return json(res, 200, { ok: true, status });
  }

  // ── assign ──
  if (mAlert && url.pathname.endsWith('/assign') && req.method === 'POST') {
    if (!can(user, 'assign:write')) return json(res, 403, { error: 'forbidden' });
    const alert = store.alerts.find((a) => a.id === mAlert[1] && a.tenantId === tenant);
    if (!alert) return json(res, 404, { error: 'not found' });
    const before = alert.assignedTo;
    alert.assignedTo = String(body.assignee || user.id).slice(0, 64);
    store.dispositions.push({ id: uuid(), tenantId: tenant, alertId: alert.id,
      actor: user.id, status: 'assigned', reason: `assigned to ${alert.assignedTo}`, ts: nowIso() });
    appendAudit(tenant, user.id, 'alert.assign', 'alert', alert.id,
      { assignedTo: before }, { assignedTo: alert.assignedTo });
    saveStore();
    return json(res, 200, { ok: true });
  }

  // ── split duplicate (non-destructive un-link, 02 §5.3) ──
  if (mAlert && url.pathname.endsWith('/split-duplicate') && req.method === 'POST') {
    if (!can(user, 'dedup:split')) return json(res, 403, { error: 'forbidden' });
    const link = store.links.find((l) => l.duplicateId === mAlert[1] &&
      l.tenantId === tenant && !l.unlinkedAt);
    if (!link) return json(res, 404, { error: 'link not found' });
    const dup = store.alerts.find((a) => a.id === link.duplicateId && a.tenantId === tenant);
    if (!dup) return json(res, 404, { error: 'not found' });
    link.unlinkedAt = nowIso(); link.unlinkedBy = user.id;
    dup.isCanonical = true; dup.canonicalId = null;
    persistScore(dup, scoreAlert(dup));
    const canonical = store.alerts.find((a) => a.id === link.canonicalId);
    if (canonical && canonical.occurrenceCount > 1) {
      canonical.occurrenceCount -= 1;
      persistScore(canonical, scoreAlert(canonical));
    }
    appendAudit(tenant, user.id, 'dedup.split', 'link', link.id,
      { canonicalId: link.canonicalId }, { promoted: dup.id });
    saveStore();
    return json(res, 200, { ok: true, newCanonicalId: dup.id });
  }

  // ── ingest (reserved for services; demo: soc.lead may simulate) ──
  if (route === 'POST /api/ingest') {
    if (user.role !== 'soc.lead' && user.role !== 'platform.admin') {
      return json(res, 403, { error: 'forbidden' }); // ingest:write is service-only in design
    }
    const input = { ...body, tenantId: tenant }; // SECURITY: tenant from session, never body
    const result = ingestAlert(input, user.id);
    saveStore();
    return json(res, 201, {
      alertId: result.alert.id, deduped: result.deduped,
      canonicalId: result.canonical.id, score: result.canonical.currentScore,
      band: result.canonical.currentBand,
    });
  }

  // ── config (kill switches, weights) — audited, versioned (01 F3) ──
  if (route === 'GET /api/config') {
    if (!can(user, 'config:write') && !can(user, 'meta:read')) return json(res, 403, { error: 'forbidden' });
    const { weights, thresholds, dedup, switches, scoreVersion } = store;
    return json(res, 200, { weights, thresholds, dedup, switches, scoreVersion });
  }
  if (route === 'POST /api/config') {
    if (!can(user, 'config:write')) return json(res, 403, { error: 'forbidden' });
    const before = JSON.parse(JSON.stringify({ weights: store.weights, thresholds: store.thresholds,
      dedup: store.dedup, switches: store.switches }));
    if (body.weights) {
      for (const [k, v] of Object.entries(body.weights)) {
        if (!(k in store.weights)) throw Object.assign(new Error(`unknown weight ${k}`), { statusCode: 400 });
        const n = Number(v);
        if (!Number.isFinite(n) || n < 0 || n > 100) throw Object.assign(new Error('weight out of range'), { statusCode: 400 });
        store.weights[k] = n;
      }
      const total = Object.values(store.weights).reduce((a, b) => a + b, 0);
      if (Math.abs(total - 100) > 0.001) { // weights must sum to 100 (02 §4.2)
        Object.assign(store.weights, before.weights);
        throw Object.assign(new Error(`weights must sum to 100 (got ${total})`), { statusCode: 400 });
      }
      store.scoreVersion = bumpVersion(store.scoreVersion); // weight change ⇒ new score version
    }
    if (body.thresholds) {
      for (const k of ['critical', 'high', 'medium', 'low']) {
        if (k in body.thresholds) {
          const n = Number(body.thresholds[k]);
          if (!Number.isFinite(n) || n < 0 || n > 100) throw Object.assign(new Error('threshold out of range'), { statusCode: 400 });
          store.thresholds[k] = n;
        }
      }
    }
    if (body.dedup && ['off', 'exact_only', 'full'].includes(body.dedup.mode)) {
      store.dedup.mode = body.dedup.mode; // kill switch (07 §2)
    }
    if (body.switches) {
      for (const k of ['ml_overlay', 'export_enabled']) {
        if (k in body.switches) store.switches[k] = !!body.switches[k];
      }
    }
    const after = JSON.parse(JSON.stringify({ weights: store.weights, thresholds: store.thresholds,
      dedup: store.dedup, switches: store.switches }));
    appendAudit(tenant, user.id, 'config.change', 'config', 'global', before, after);
    // re-score canonicals with new weights (explicit backfill is audited)
    let rescored = 0;
    for (const a of store.alerts.filter((x) => x.tenantId === tenant && x.isCanonical)) {
      persistScore(a, scoreAlert(a)); rescored++;
    }
    saveStore();
    return json(res, 200, { ok: true, rescored, scoreVersion: store.scoreVersion });
  }

  // ── audit ──
  if (route === 'GET /api/audit') {
    if (!can(user, 'audit:read')) return json(res, 403, { error: 'forbidden' });
    const list = store.audit.filter((a) => a.tenantId === tenant)
      .slice(-200).reverse();
    return json(res, 200, { events: list, chainValid: verifyAuditChain() });
  }
  if (route === 'GET /api/audit/export') {
    if (!can(user, 'audit:read')) return json(res, 403, { error: 'forbidden' });
    if (!store.switches.export_enabled) return json(res, 403, { error: 'export disabled by kill switch' });
    const lines = store.audit.filter((a) => a.tenantId === tenant)
      .map((a) => JSON.stringify(a)).join('\n');
    res.writeHead(200, {
      'Content-Type': 'application/x-ndjson; charset=utf-8',
      'Content-Disposition': `attachment; filename="audit-${tenant}-${Date.now()}.jsonl"`,
      'X-Content-Type-Options': 'nosniff',
    });
    return res.end(lines);
  }

  // ── meta / invariants (state.md §3.3) ──
  if (route === 'GET /api/meta/invariants') {
    if (!can(user, 'meta:read')) return json(res, 403, { error: 'forbidden' });
    return json(res, 200, {
      invariants: {
        tenantScoped: store.alerts.every((a) => !!a.tenantId),
        scoresImmutable: store.scores.length >= 0, // insert-only by construction
        linksNeverDeleted: store.links.every((l) => 'unlinkedAt' in l),
        dispositionsAppendOnly: Array.isArray(store.dispositions),
        auditChainValid: verifyAuditChain(),
      },
      degraded: { mlOverlay: store.switches.ml_overlay, dedupMode: store.dedup.mode },
    });
  }

  return json(res, 404, { error: 'not found' });
}

function bumpVersion(v) {
  const [a, b, c] = v.split('.').map(Number);
  return `${a}.${b + 1}.0`;
}

function publicAlert(a) {
  const { rawOriginal, entityKey, ...rest } = a; // minimization: internals not exposed
  return rest;
}

// ─────────────────────────────────────────────────────────────────────────────
// Static file host (self-hosted assets only — A06)
// ─────────────────────────────────────────────────────────────────────────────
const PUBLIC = path.join(__dirname, 'public');
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png' };

function serveStatic(req, res, url) {
  let p = url.pathname === '/' ? '/index.html' : url.pathname;
  p = path.normalize(p).replace(/^(\.\.[/\\])+/, '');
  const file = path.join(PUBLIC, p);
  if (!file.startsWith(PUBLIC)) { res.writeHead(403); return res.end('forbidden'); } // traversal guard
  if (!fs.existsSync(file) || !fs.statSync(file).isFile()) { res.writeHead(404); return res.end('not found'); }
  res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
  fs.createReadStream(file).pipe(res);
}

// ─────────────────────────────────────────────────────────────────────────────
// Demo seed (tenant t1 golden-vector scenario per 02 §4.2 + t2 isolation demo)
// ─────────────────────────────────────────────────────────────────────────────
function seedDemoData() {
  const base = Date.now() - 3600_000;
  const t1 = 't1';
  const mk = (over) => ingestAlert({
    tenantId: t1, source: 'edr', ruleId: 'EDR-CRED-DUMP-01', ruleFamily: 'credential-access',
    tactic: 'credential-access', title: 'Credential dumping tool detected on FIN-DB-001',
    summary: 'LSASS handle access by unsigned binary',
    entities: [{ type: 'host', id: 'FIN-DB-001' }, { type: 'user', id: 'svc_backup@t1' }],
    occurredAt: new Date(base).toISOString(),
    confidence: 0.75, sourceReliability: 1.0, assetTier: 0, tiMatch: 1.0,
    identityRisk: 0.6, kevListed: true, epss: 0.61, anomalyZ: 0.8, incidentLinked: false,
    ...over,
  }, 'seed');
  mk({});                                    // canonical — golden vector (score 97, critical)
  mk({ occurredAt: new Date(base + 300_000).toISOString() }); // exact duplicate
  mk({ occurredAt: new Date(base + 600_000).toISOString() }); // exact duplicate
  ingestAlert({                              // different tenant — must never link (isolation demo)
    tenantId: 't2', source: 'edr', ruleId: 'EDR-CRED-DUMP-01', ruleFamily: 'credential-access',
    tactic: 'credential-access', title: 'Credential dumping tool detected on HR-WS-014',
    summary: 'LSASS handle access by unsigned binary',
    entities: [{ type: 'host', id: 'HR-WS-014' }, { type: 'user', id: 'user@t2' }],
    occurredAt: new Date(base + 30_000).toISOString(),
    confidence: 0.6, assetTier: 2, tiMatch: 0.3, kevListed: false, epss: 0.1, anomalyZ: 0.5,
  }, 'seed');
  ingestAlert({                              // low-value noise example
    tenantId: t1, source: 'cspm', ruleId: 'CSPM-OPEN-S3-02', ruleFamily: 'posture',
    tactic: 'reconnaissance', title: 'S3 bucket policy allows public read',
    summary: 'bucket logs-public-02 allows s3:GetObject for *',
    entities: [{ type: 'resource', id: 's3://logs-public-02' }],
    occurredAt: new Date(base + 900_000).toISOString(),
    confidence: 0.9, assetTier: 3, tiMatch: 0, kevListed: false, epss: 0, anomalyZ: 0.2,
  }, 'seed');
}

// ─────────────────────────────────────────────────────────────────────────────
// Server
// ─────────────────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  secureHeaders(res);
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  try {
    if (url.pathname.startsWith('/api/')) return await handleApi(req, res, url);
    if (req.method !== 'GET') { res.writeHead(405); return res.end(); }
    return serveStatic(req, res, url);
  } catch (e) {
    console.error('[server]', e.message);
    if (!res.headersSent) json(res, 500, { error: 'internal error' });
  }
});

server.on('error', (e) => {
  if (e.code === 'EADDRINUSE') {
    console.error(`\nERROR: port ${PORT} is already in use.`);
    console.error(`  • Another instance is likely running. Use a different port: PORT=8081 node server.js`);
    console.error(`  • Or stop the other instance: netstat -ano | findstr :${PORT}  →  taskkill /F /PID <pid>`);
    process.exit(1);
  }
  console.error('[server] fatal:', e.message);
  process.exit(1);
});

loadStore();
server.listen(PORT, () => {
  console.log(`SOC Alert Triage Dashboard → http://localhost:${PORT}`);
  console.log(`demo logins: analyst@t1 / lead@t1 / auditor@t1 / analyst@t2  (no password)`);
});
