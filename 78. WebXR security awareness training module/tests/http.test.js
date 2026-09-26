'use strict';
/**
 * http.test.js — Integration tests against the real HTTP server.
 * Covers: security headers, rate limiting (429), auth gating (401/403),
 * full training flow (login → start → complete → stats), audit verification.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'xrsec-http-'));
process.env.DATA_DIR = tmp;
process.env.NODE_ENV = 'local';
process.env.ADMIN_SEED_PASSWORD = 'Test#Passw0rd!';
process.env.PORT = '0'; // ephemeral

const { server } = require('../server/src/index');

// Ensure the test runner exits: stop the server once the suite completes.
test.after(() => new Promise((resolve) => server.close(() => resolve())));

async function call(method, url, { body, token } = {}) {
  const port = server.address().port;
  const res = await fetch(`http://127.0.0.1:${port}${url}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  return { status: res.status, headers: res.headers, json };
}

test('health endpoint reports audit chain validity', async () => {
  const r = await call('GET', '/api/health');
  assert.equal(r.status, 200);
  assert.equal(r.json.status, 'ok');
  assert.equal(r.json.auditChainValid, true);
});

test('security headers present on API and static responses', async () => {
  const r = await call('GET', '/api/health');
  assert.match(r.headers.get('content-security-policy'), /default-src 'self'/);
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(r.headers.get('x-frame-options'), 'DENY');

  const page = await fetch(`http://127.0.0.1:${server.address().port}/`);
  assert.equal(page.headers.get('x-frame-options'), 'DENY');
  assert.match(page.headers.get('content-security-policy'), /frame-ancestors 'none'/);
});

test('static SPA served with path traversal blocked', async () => {
  const port = server.address().port;
  const ok = await fetch(`http://127.0.0.1:${port}/`);
  assert.equal(ok.status, 200);
  assert.match(await ok.text(), /Security Awareness Training/);

  const evil = await fetch(`http://127.0.0.1:${port}/..%2f..%2fserver%2fsrc%2fconfig.js`);
  assert.notEqual(evil.status, 200);
  assert.doesNotMatch(await evil.text(), /JWT_SECRET/);
});

test('auth: unauthorized requests are rejected (deny-by-default)', async () => {
  assert.equal((await call('GET', '/api/modules')).status, 401);
  assert.equal((await call('GET', '/api/admin/users')).status, 401);
  assert.equal((await call('POST', '/api/sessions/start', { body: { moduleId: 'x' } })).status, 401);
});

test('demo login issues working learner token', async () => {
  const r = await call('POST', '/api/auth/demo-login', { body: {} });
  assert.equal(r.status, 200);
  assert.ok(r.json.token);
  assert.equal(r.json.user.role, 'learner');
  const me = await call('GET', '/api/auth/me', { token: r.json.token });
  assert.equal(me.status, 200);
  assert.equal(me.json.user.role, 'learner');
});

test('full training flow: start → complete → stats (server-side scoring)', async () => {
  const login = await call('POST', '/api/auth/demo-login', { body: {} });
  const token = login.json.token;

  const catalog = await call('GET', '/api/modules', { token });
  assert.equal(catalog.status, 200);
  assert.ok(catalog.json.modules.length >= 5);

  const start = await call('POST', '/api/sessions/start', { body: { moduleId: 'phishing-triage' }, token });
  assert.equal(start.status, 201);
  assert.ok(start.json.session.id);
  assert.ok(start.json.module.integrity); // bundle hash for client-side verification

  const { nodes } = start.json.module;
  const results = nodes.map((n) => ({ nodeId: n.id, choice: n.correct })); // perfect answers
  const done = await call('POST', `/api/sessions/${start.json.session.id}/complete`, { body: { results }, token });
  assert.equal(done.status, 200);
  assert.equal(done.json.score.riskScore, 100); // server-computed
  assert.equal(done.json.session.status, 'completed');

  // Double-submit rejected (integrity of records)
  const again = await call('POST', `/api/sessions/${start.json.session.id}/complete`, { body: { results }, token });
  assert.equal(again.status, 400);

  const stats = await call('GET', '/api/stats/risk', { token });
  assert.equal(stats.status, 200);
  assert.equal(stats.json.completed, 1);
  assert.equal(stats.json.avgRiskScore, 100);
});

test('admin RBAC: learner cannot read users or audit; admin can', async () => {
  const learner = (await call('POST', '/api/auth/demo-login', { body: {} })).json.token;
  assert.equal((await call('GET', '/api/admin/users', { token: learner })).status, 403);
  assert.equal((await call('GET', '/api/admin/audit', { token: learner })).status, 403);

  const admin = await call('POST', '/api/auth/login', {
    body: { email: 'admin@corp.example', password: 'Test#Passw0rd!' },
  });
  assert.equal(admin.status, 200);
  assert.equal(admin.json.user.role, 'admin');
  assert.equal((await call('GET', '/api/admin/users', { token: admin.json.token })).status, 200);
  const av = await call('GET', '/api/admin/audit/verify', { token: admin.json.token });
  assert.equal(av.json.valid, true);
});

test('input validation rejects malformed payloads', async () => {
  const token = (await call('POST', '/api/auth/demo-login', { body: {} })).json.token;
  assert.equal((await call('POST', '/api/sessions/start', { body: { moduleId: '../../etc' }, token })).status, 400);
  assert.equal((await call('POST', '/api/sessions/start', { body: { moduleId: 'x'.repeat(500) }, token })).status, 400);
  assert.equal((await call('POST', '/api/sessions/start', { body: { wrong: 1 }, token })).status, 400);
});

test('audit entries appended for security-relevant actions', async () => {
  const admin = (await call('POST', '/api/auth/login', {
    body: { email: 'admin@corp.example', password: 'Test#Passw0rd!' },
  })).json.token;
  const r = await call('GET', '/api/admin/audit', { token: admin });
  const actions = r.json.entries.map((e) => e.action);
  assert.ok(actions.includes('auth.demo_login'));
  assert.ok(actions.includes('session.start'));
  assert.ok(actions.includes('session.complete'));
  assert.ok(actions.includes('auth.login'));
});

// NOTE: runs LAST — it deliberately exhausts the shared-IP login rate bucket.
test('login rate limiting returns 429 with Retry-After', async () => {
  // Fire attempts up to the per-window max (5)
  for (let i = 0; i < 5; i++) {
    await call('POST', '/api/auth/login', { body: { email: 'x@y.co', password: 'bad' } });
  }
  const r = await call('POST', '/api/auth/login', { body: { email: 'x@y.co', password: 'bad' } });
  assert.equal(r.status, 429);
  assert.ok(r.headers.get('retry-after'));
});
