// Requires: npm run build (compiles workspace packages to dist/) before running.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { auditHash, sha256Hex, canonicalize, computeEventHash } from '@pathsphere/security-utils';

test('sha256Hex is deterministic', () => {
  assert.equal(sha256Hex('attack'), sha256Hex('attack'));
  assert.notEqual(sha256Hex('attack'), sha256Hex('defense'));
});

test('auditHash chains deterministically and is tamper-sensitive', () => {
  const h1 = auditHash('a'.repeat(64), 'payload-a');
  const h2 = auditHash(h1, 'payload-b');
  assert.equal(h1.length, 64);
  assert.equal(typeof h2, 'string');
  // Change payload => different hash
  assert.notEqual(auditHash('a'.repeat(64), 'payload-b'), h1);
});

test('canonicalize is key-order independent', () => {
  const a = canonicalize({ b: 2, a: 1, c: { y: true, x: 'v' } });
  const b = canonicalize({ c: { x: 'v', y: true }, a: 1, b: 2 });
  assert.equal(a, b);
});

test('computeEventHash produces chain-consistent event hash', () => {
  const event = {
    eventId: 'evt_x',
    ts: '2026-09-23T00:00:00.000Z',
    actor: 'analyst.demo',
    role: 'Analyst',
    action: 'graph.read',
    objectType: 'node',
    objectId: 'node-1000',
    tenantId: 'T-001',
    ip: '127.0.0.1',
    userAgent: 'test',
    mfa: true,
    meta: { q: 1 },
  };
  const prev = '0'.repeat(64);
  const hash = computeEventHash(prev, event);
  // recompute over the event (including its own hash/prevHash fields removed) must match
  const again = computeEventHash('0'.repeat(64), {
    ...event,
    hash: '',
    prevHash: prev,
  });
  assert.equal(hash, again);
});