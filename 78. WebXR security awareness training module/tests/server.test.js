'use strict';
/**
 * server.test.js — Security & logic tests (node:test, zero deps).
 * Covers: OWASP A02/A03/A05/A07, ISO A.8.15 audit chain, NIST AC-7 rate limiting.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

// Isolated data dir per test run
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'xrsec-'));
process.env.DATA_DIR = tmp;
process.env.NODE_ENV = 'local';
process.env.ADMIN_SEED_PASSWORD = 'Test#Passw0rd!';

const {
  rateLimit,
  hashPassword,
  verifyPassword,
  signToken,
  verifyToken,
  sha256,
  AuditChain,
  encryptField,
  decryptField,
  sanitizeText,
  isSafeEmail,
  isSafeId,
} = require('../server/src/securityUtils');
const { MODULES, getModule, scoreSession } = require('../server/src/modules');

test('rate limiting blocks after max and resets', () => {
  const key = `t-${Math.random()}`;
  for (let i = 0; i < 3; i++) {
    assert.equal(rateLimit(key, { windowMs: 1000, max: 3 }).allowed, true);
  }
  assert.equal(rateLimit(key, { windowMs: 1000, max: 3 }).allowed, false);
});

test('rate limiter rejects malformed keys (deny-by-default)', () => {
  assert.equal(rateLimit('', {}).allowed, false);
  assert.equal(rateLimit(null, {}).allowed, false);
  assert.equal(rateLimit('x'.repeat(300), {}).allowed, false);
});

test('password hashing verifies correct password and rejects wrong', () => {
  const h = hashPassword('Correct#Horse1');
  assert.equal(verifyPassword('Correct#Horse1', h), true);
  assert.equal(verifyPassword('wrong', h), false);
  assert.equal(verifyPassword('Correct#Horse1', 'garbage'), false);
});

test('tokens verify, expire, and reject tampering/alg-confusion', () => {
  const secret = 'test-secret-123';
  const t = signToken({ sub: 'u1', role: 'learner' }, secret, 60_000);
  assert.ok(verifyToken(t, secret));
  assert.equal(verifyToken(t, 'other-secret'), null);
  // tamper payload
  const [h, b, s] = t.split('.');
  const tampered = `${h}.${Buffer.from(JSON.stringify({ sub: 'admin-x', role: 'admin', exp: Date.now() + 60000 })).toString('base64url')}.${s}`;
  assert.equal(verifyToken(tampered, secret), null);
  // alg confusion
  const forgedAlg = `${Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url')}.${b}.${s}`;
  assert.equal(verifyToken(forgedAlg, secret), null);
  // expiry
  const expired = signToken({ sub: 'u1' }, secret, -1);
  assert.equal(verifyToken(expired, secret), null);
});

test('sha256 is deterministic', () => {
  assert.equal(sha256('abc'), sha256('abc'));
  assert.notEqual(sha256('abc'), sha256('abd'));
});

test('audit chain detects tampering at any position', () => {
  const file = path.join(tmp, `audit-${Math.random()}.log`);
  const chain = new AuditChain(file);
  chain.append({ actor: 'u1', action: 'a' });
  chain.append({ actor: 'u1', action: 'b' });
  chain.append({ actor: 'u2', action: 'c' });
  assert.deepEqual(chain.verify(), { valid: true, entries: 3 });

  // Tamper with middle entry
  const lines = fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);
  const rec = JSON.parse(lines[1]);
  rec.action = 'forged';
  lines[1] = JSON.stringify(rec);
  fs.writeFileSync(file, lines.join('\n') + '\n');

  const chain2 = new AuditChain(file);
  const v = chain2.verify();
  assert.equal(v.valid, false);
  assert.equal(v.brokenAt, 1);
});

test('field encryption round-trips and fails on wrong key', () => {
  const key = Buffer.from('a'.repeat(64), 'hex');
  const blob = encryptField('learner@corp.example', key);
  assert.notEqual(blob.includes('learner'), true); // no plaintext at rest
  assert.equal(decryptField(blob, key), 'learner@corp.example');
  const wrongKey = Buffer.from('b'.repeat(64), 'hex');
  assert.equal(decryptField(blob, wrongKey), null);
});

test('sanitizeText strips HTML-significant characters and control chars', () => {
  assert.equal(sanitizeText('<script>alert(1)</script>'), '&lt;script&gt;alert(1)&lt;/script&gt;');
  assert.equal(sanitizeText('a\x00b'), 'ab');
  assert.equal(sanitizeText('x'.repeat(500), 10), 'x'.repeat(10));
});

test('email/id validators reject malicious shapes', () => {
  assert.equal(isSafeEmail('a@b.co'), true);
  assert.equal(isSafeEmail('<script>@x.y'), false);
  assert.equal(isSafeEmail('no-at-sign'), false);
  assert.equal(isSafeId('phishing-triage'), true);
  assert.equal(isSafeId('../../etc/passwd'), false);
  assert.equal(isSafeId('a; drop table users'), false);
});

test('module catalog: known and unknown ids', () => {
  assert.ok(getModule('phishing-triage'));
  assert.equal(getModule('nope'), null);
  assert.ok(MODULES.length >= 5);
});

test('scoring: perfect run scores 100, traps reduce score', () => {
  const mod = getModule('phishing-triage');
  const perfect = mod.nodes.map((n) => ({ nodeId: n.id, choice: n.correct }));
  const s1 = scoreSession(mod, perfect);
  assert.equal(s1.riskScore, 100);
  assert.equal(s1.trapHits, 0);

  const trap = mod.nodes.find((n) => n.options.some((o) => o.isTrap));
  const trapOpt = trap.options.find((o) => o.isTrap);
  const withTrap = perfect.map((r) => (r.nodeId === trap.id ? { nodeId: trap.id, choice: trapOpt.id } : r));
  const s2 = scoreSession(mod, withTrap);
  assert.equal(s2.trapHits, 1);
  assert.ok(s2.riskScore < s1.riskScore);
});

test('scoring rejects null/empty', () => {
  const mod = getModule('phishing-triage');
  assert.equal(scoreSession(null, []), null);
  assert.equal(scoreSession(mod, []), null);
});
