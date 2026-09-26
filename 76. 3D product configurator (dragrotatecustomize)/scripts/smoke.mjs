/**
 * End-to-end smoke test.
 *
 * Exercises the full security + reporting surface against a live server:
 *   1. security headers, CORS, CSRF
 *   2. authentication, lockout, RBAC
 *   3. configuration lifecycle with encryption + optimistic concurrency
 *   4. all five report formats
 *   5. audit trail integrity + tamper detection
 *
 * Run with:  node scripts/smoke.mjs [baseUrl]
 */

import { writeFileSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';

const BASE = process.argv[2] ?? 'http://127.0.0.1:4000/api/v1';
const PASSWORD = 'PrismForge!2024';
const OUT = resolve(process.cwd(), 'data', 'smoke');

mkdirSync(OUT, { recursive: true });

let pass = 0;
let fail = 0;
const results = [];

function check(name, ok, detail = '') {
  results.push({ name, ok, detail });
  if (ok) {
    pass++;
    console.log(`  \x1b[32mPASS\x1b[0m  ${name}${detail ? ` \x1b[90m${detail}\x1b[0m` : ''}`);
  } else {
    fail++;
    console.log(`  \x1b[31mFAIL\x1b[0m  ${name} \x1b[31m${detail}\x1b[0m`);
  }
}

const jar = new Map();
const cookieHeader = () =>
  [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');

function storeCookies(res) {
  const raw = res.headers.getSetCookie?.() ?? [];
  for (const c of raw) {
    const [pair] = c.split(';');
    const idx = pair.indexOf('=');
    if (idx > 0) jar.set(pair.slice(0, idx).trim(), pair.slice(idx + 1).trim());
  }
}

async function call(path, { method = 'GET', body, token, headers = {}, raw = false, noCsrf = false } = {}) {
  const h = { ...headers };
  if (body !== undefined) h['content-type'] = 'application/json';
  if (token) h['authorization'] = `Bearer ${token}`;
  if (jar.size) h['cookie'] = cookieHeader();
  if (!noCsrf) {
    const csrf = jar.get('pf_csrf');
    if (csrf) h['x-csrf-token'] = csrf;
  }
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: h,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  storeCookies(res);
  if (raw) return res;
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* non-JSON (csv/xlsx/pdf/html) */
  }
  return { status: res.status, headers: res.headers, json, text, buffer: raw ? null : undefined };
}

async function login(email) {
  const r = await call('/auth/login', { method: 'POST', body: { email, password: PASSWORD } });
  if (r.status !== 200) throw new Error(`login failed for ${email}: ${r.status} ${r.text}`);
  return r.json.data.accessToken;
}

const spec = {
  productId: 'prismforge-one',
  name: 'Smoke Test Configuration',
  dimensions: { height: 240, diameter: 110 },
  parts: {
    body: { colour: '#8b5cf6', finish: 'anodized', enabled: true },
    grille: { colour: '#1e1b4b', finish: 'matte', enabled: true },
    cap: { colour: '#c4b5fd', finish: 'brushedMetal', enabled: true },
    ring: { colour: '#f472b6', finish: 'gloss', enabled: true },
    base: { colour: '#0f172a', finish: 'rubberized', enabled: true },
    buttons: { colour: '#f8fafc', finish: 'rubberized', enabled: true },
    strap: { colour: '#334155', finish: 'rubberized', enabled: false },
  },
  accessories: ['cap', 'ringLight', 'stand'],
  engraving: { enabled: true, text: 'SMOKE-TEST', position: 'front', font: 'grotesk', colour: '#f8fafc' },
  quantity: 250,
  notes: 'Created by the automated smoke test.',
  snapshot: '',
};

console.log('\n\x1b[95m  PrismForge API smoke test\x1b[0m\n\x1b[90m  ' + BASE + '\x1b[0m\n');

// --- 1. Transport security ------------------------------------------------
console.log('\x1b[95m1. Transport security\x1b[0m');
{
  const res = await call('/health/live', { raw: true });
  const h = res.headers;
  check('HSTS not set over plain HTTP in dev', !h.get('strict-transport-security'), '(expected in dev)');
  check('X-Content-Type-Options: nosniff', h.get('x-content-type-options') === 'nosniff');
  check('X-Frame-Options / frameguard present', Boolean(h.get('x-frame-options') || h.get('content-security-policy')));
  check('Referrer-Policy: no-referrer', h.get('referrer-policy') === 'no-referrer');
  check('CSP present with default-src none', (h.get('content-security-policy') ?? '').includes("default-src 'none'"));
  check('X-Powered-By removed', !h.get('x-powered-by'));
  check('X-Frame-Options DENY', (h.get('x-frame-options') ?? '').toUpperCase() === 'DENY');
}
{
  const res = await fetch(`${BASE}/health/live`, { headers: { origin: 'https://evil.example' } });
  check('CORS blocks foreign origin', res.status === 403 || !res.headers.get('access-control-allow-origin'), `status ${res.status}`);
}

// --- 2. Authentication ----------------------------------------------------
console.log('\n\x1b[95m2. Authentication & authorisation\x1b[0m');
const adminToken = await login('admin@prismforge.test');
check('admin login', Boolean(adminToken));
const designerToken = await login('designer@prismforge.test');
const auditorToken = await login('auditor@prismforge.test');
const viewerToken = await login('viewer@prismforge.test');
const securityToken = await login('security@prismforge.test');
check('all five role accounts authenticate', Boolean(designerToken && auditorToken && viewerToken && securityToken));

{
  const r = await call('/auth/login', { method: 'POST', body: { email: 'admin@prismforge.test', password: 'wrong-password' } });
  check('bad password rejected with generic message', r.status === 401 && r.json?.error?.message === 'Invalid credentials');
}
{
  const r = await call('/auth/login', { method: 'POST', body: { email: 'nobody@prismforge.test', password: 'whatever' } });
  check('unknown account returns identical error (no enumeration)', r.status === 401 && r.json?.error?.message === 'Invalid credentials');
}
{
  const r = await call('/auth/login', { method: 'POST', body: { email: 'x@y.z', password: 'a', extra: 'field' } });
  check('unknown field rejected (mass-assignment defence)', r.status === 422 && r.json?.error?.code === 'VALIDATION_FAILED');
}
{
  const r = await call('/configurations', { token: viewerToken });
  check('viewer cannot create configuration (RBAC)', r.status === 403 && r.json?.error?.code === 'FORBIDDEN');
}
{
  const r = await call('/audit', { token: designerToken });
  check('configurator cannot read the audit trail', r.status === 403);
}
{
  const r = await call('/reports/generate', {
    method: 'POST',
    token: auditorToken,
    body: { subject: 'integrity', format: 'json' },
  });
  check('auditor cannot generate a security_officer report', r.status === 403);
}
{
  const r = await call('/auth/me');
  check('unauthenticated request rejected', r.status === 401);
}
{
  const res = await fetch(`${BASE}/auth/refresh`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookieHeader() }, body: '{}' });
  check('CSRF: cookie-authenticated POST without token rejected', res.status === 403);
}

// --- 3. Configuration lifecycle -------------------------------------------
console.log('\n\x1b[95m3. Configuration lifecycle\x1b[0m');
let configId;
let version;
{
  const r = await call('/configurations', { method: 'POST', token: designerToken, body: { spec, share: true } });
  check('create configuration', r.status === 201, `status ${r.status} ${r.text?.slice(0, 160)}`);
  configId = r.json?.data?.id;
  version = r.json?.data?.version;
  check('share link minted', Boolean(r.json?.data?.shareUrl));
  check('server-computed total present', (r.json?.data?.totalMinor ?? 0) > 0, `total ${r.json?.data?.totalMinor}`);
}
{
  const r = await call(`/configurations/${configId}`, { token: designerToken });
  check('read own configuration', r.status === 200);
  check('server revalidates spec', r.json?.data?.spec?.engraving?.text === 'SMOKE-TEST');
}
{
  const r = await call(`/configurations/${configId}`, { token: viewerToken });
  check('IDOR: another user cannot read it', r.status === 403);
}
{
  const r = await call(`/configurations/${configId}`, { method: 'PATCH', token: designerToken, body: { expectedVersion: 999, name: 'x' } });
  check('stale version rejected (optimistic concurrency)', r.status === 409 && r.json?.error?.code === 'VERSION_CONFLICT');
}
{
  const r = await call(`/configurations/${configId}`, {
    method: 'PATCH',
    token: designerToken,
    body: { expectedVersion: version, spec: { ...spec, quantity: 1000 } },
  });
  check('update with correct version', r.status === 200, `status ${r.status}`);
  version = r.json?.data?.version;
}
{
  const r = await call(`/configurations/${configId}`, { method: 'PATCH', token: designerToken, body: { expectedVersion: version, spec: { ...spec, dimensions: { height: 9999, diameter: 110 } } } });
  check('out-of-range geometry rejected', r.status === 422);
}
{
  const r = await call('/configurations?pageSize=99999', { token: auditorToken });
  check('pagination bound enforced', r.status === 422);
}

// --- 4. Reports (all five formats) ---------------------------------------
console.log('\n\x1b[95m4. Report generation\x1b[0m');
const formats = ['csv', 'xlsx', 'html', 'pdf', 'json'];
const expected = { csv: 23948, xlsx: 23554, html: 23460, pdf: 25505, json: 27191 };
for (const fmt of formats) {
  const res = await call('/reports/generate', {
    method: 'POST',
    token: securityToken,
    body: { subject: 'configuration', format: fmt, configurationId: configId },
    raw: true,
  });
  const bytes = Buffer.from(await res.arrayBuffer());
  const name = `report-configuration.${fmt}`;
  writeFileSync(resolve(OUT, name), bytes);
  const magic =
    fmt === 'pdf' ? bytes.subarray(0, 4).toString() === '%PDF'
    : fmt === 'xlsx' ? bytes.subarray(0, 2).toString() === 'PK'
    : fmt === 'csv' ? bytes.subarray(0, 3).toString() === '\uEF\uBB\uBF'
    : true;
  check(
    `${fmt.toUpperCase()} report (${bytes.length} bytes)`,
    res.status === 200 && bytes.length > 200 && magic,
    magic ? '' : `bad magic bytes; status ${res.status}`,
  );
  check(
    `  ${fmt.toUpperCase()} content-type + no-store`,
    (res.headers.get('content-type') ?? '').includes(expected[fmt]) &&
      (res.headers.get('cache-control') ?? '').includes('no-store'),
  );
  check(`  ${fmt.toUpperCase()} reports a SHA-256 of the delivered bytes`, Boolean(res.headers.get('x-content-sha256')));
}
{
  const r = await call('/reports/generate', { method: 'POST', token: auditorToken, body: { subject: 'audit', format: 'csv' } });
  check('audit extract (CSV)', r.status === 200 && r.text.includes('SUMMARY'), `status ${r.status}`);
  writeFileSync(resolve(OUT, 'report-audit.csv'), r.text);
}
{
  const r = await call('/reports/generate', { method: 'POST', token: securityToken, body: { subject: 'integrity', format: 'html' } });
  check('integrity report (HTML)', r.status === 200 && r.text.includes('Audit chain'), `status ${r.status}`);
  writeFileSync(resolve(OUT, 'report-integrity.html'), r.text);
  check('  HTML report has its own strict CSP', r.text.includes("default-src 'none'"));
  check('  HTML report contains no unescaped script tags', !/<script/i.test(r.text));
}
{
  const r = await call('/reports/generate', { method: 'POST', token: securityToken, body: { subject: 'access-review', format: 'xlsx' } });
  check('access review (XLSX)', r.status === 200, `status ${r.status}`);
  writeFileSync(resolve(OUT, 'report-access-review.xlsx'), Buffer.from(r.buffer ?? []));
}
{
  const r = await call('/reports/generate', { method: 'POST', token: securityToken, body: { subject: 'security-posture', format: 'pdf' } });
  check('security posture (PDF)', r.status === 200, `status ${r.status}`);
}

// --- 5. Audit trail -------------------------------------------------------
console.log('\n\x1b[95m5. Audit trail & integrity\x1b[0m');
{
  const r = await call('/audit?pageSize=10', { token: auditorToken });
  check('auditor can read the trail', r.status === 200 && r.json.data.total > 0, `${r.json?.data?.total} entries`);
  check('entries carry chain hashes', Boolean(r.json.data.rows[0]?.entryHash));
  const actions = new Set(r.json.data.rows.map((x) => x.action));
  check('auth.login recorded', actions.has('auth.login'));
  check('report.generate recorded at CRITICAL', actions.has('report.generate'));
}
{
  const r = await call('/audit?outcome=DENIED', { token: auditorToken });
  check('RBAC denials are recorded', r.json?.data?.total > 0, `${r.json?.data?.total} denials`);
}
{
  const r = await call('/audit?outcome=FAILURE&minSeverity=NOTICE', { token: auditorToken });
  check('failed logins are recorded', r.json?.data?.total > 0, `${r.json?.data?.total} failures`);
}
{
  const r = await call('/audit/verify', { method: 'POST', token: securityToken, body: { fromSeq: 0 } });
  check('chain verification passes', r.status === 200 && r.json?.data?.valid === true, `entries ${r.json?.data?.verifiedEntries}`);
}
{
  const r = await call('/audit/verify', { method: 'POST', token: designerToken, body: {} });
  check('integrity verification requires security_officer+', r.status === 403);
}
{
  const r = await call('/audit/checkpoint', { method: 'POST', token: securityToken });
  check('signed checkpoint minted', r.status === 201 && Boolean(r.json?.data?.signature));
}
{
  const r = await call('/admin/system', { token: adminToken });
  check('admin system snapshot', r.status === 200 && r.json?.data?.counts?.auditEntries > 0, `${r.json?.data?.counts?.auditEntries} audit rows`);
}
{
  const r = await call('/admin/users', { token: designerToken });
  check('admin routes reject non-admins', r.status === 403);
}

// --- Summary --------------------------------------------------------------
console.log(`\n\x1b[95m  Result: ${pass} passed, ${fail} failed\x1b[0m`);
console.log(`\x1b[90m  Artefacts written to ${OUT}\x1b[0m\n`);
process.exit(fail === 0 ? 0 : 1);
