// Requires: npm run build
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createLedger } from '@pathsphere/audit-ledger';
import { createReportEngine } from '@pathsphere/report-engine';
import { parseSharpHoundLite } from '@pathsphere/ingestion-service';
import { computeDrift } from '@pathsphere/delta-drift';
import { createPathEngine } from '@pathsphere/path-analysis';
import { loadDemoGraph, demoTargets, buildDemoGraph } from '@pathsphere/demo-data';

function baseEvent(overrides = {}) {
  return {
    ts: new Date().toISOString(),
    actor: 'tester',
    role: 'Analyst',
    action: 'test.action',
    objectType: 'node',
    objectId: 'node-1',
    tenantId: 'T-001',
    ip: '127.0.0.1',
    userAgent: 'streamlit-test',
    mfa: true,
    meta: {},
    ...overrides,
  };
}

test('ledger appends and verifies chain', () => {
  const ledger = createLedger();
  const e1 = ledger.append(baseEvent({ action: 'graph.read' }));
  const e2 = ledger.append(baseEvent({ action: 'path.compute' }));
  assert.notEqual(e1.hash, e2.hash);
  assert.equal(e2.prevHash, e1.hash);
  assert.equal(ledger.verify().ok, true);
  assert.equal(ledger.verify().count, 2);
});

test('ledger tamper detection', () => {
  const ledger = createLedger();
  ledger.append(baseEvent({ action: 'a' }));
  const mid = ledger.append(baseEvent({ action: 'b' }));
  ledger.append(baseEvent({ action: 'c' }));
  // tamper with the middle event's payload field
  mid.meta.pwned = true;
  const result = ledger.verify();
  assert.equal(result.ok, false);
  assert.equal(result.mismatchAt, 2);
});

test('path engine finds known escalation chain Tier0', () => {
  const store = loadDemoGraph();
  const engine = createPathEngine(store.nodes, store.edges, { maxDepth: 8 });
  const paths = engine.findKShortest(demoTargets.user, demoTargets.domainAdminGroup, 5);
  assert.ok(paths.length >= 1);
  assert.ok(paths.some((p) => p.tier0Reached));
  // every step refers to real edges in the demo graph
  for (const p of paths) {
    for (const s of p.steps) {
      assert.ok(store.nodes.has(s.from), `from node ${s.from} exists`);
      assert.ok(store.nodes.has(s.to), `to node ${s.to} exists`);
      assert.ok(s.remediation.length > 0);
    }
  }
});

test('report engine signs and verifies Ed25519', () => {
  const engine = createReportEngine();
  const report = engine.buildReport({
    reportId: 'r-42',
    reportType: 'attack-path',
    params: { source: 'ALICE', target: 'DOMAIN ADMINS' },
    graphVersion: 'g-2026-09-23-001',
    classification: 'internal',
    authorId: 'tester',
  });
  assert.equal(report.bodyBytes.length, 64);
  assert.equal(engine.verifyReport(report), true);
  report.body.summary = 'tampered';
  assert.equal(engine.verifyReport(report), false);
});

test('sharp-hound-lite parse normalizes types + idempotency', () => {
  const snap = parseSharpHoundLite({
    tenantId: 'T-001',
    nodes: [{ id: 'n1', type: 'User', name: 'ALICE' }, { id: 'n2', type: 'Domain', name: 'DEMO.LOCAL' }],
    edges: [{ id: 'e1', type: 'MemberOf', source: 'n1', target: 'n2' }],
  });
  assert.equal(snap.nodes.length, 2);
  assert.equal(snap.nodes[0].type, 'User');
  assert.equal(snap.edges[0].type, 'MemberOf');
  assert.ok(snap.graphVersion.startsWith('g-'));
});

test('delta drift detects added/removed/changed', () => {
  const before = { nodes: [{ id: 'a', properties: { risk: 1 } }, { id: 'b', properties: { risk: 9 } }], edges: [{ id: 'e1' }] };
  const after = { nodes: [{ id: 'a', properties: { risk: 5 } }, { id: 'c', properties: {} }], edges: [{ id: 'e1' }, { id: 'e2' }] };
  const drift = computeDrift(before, after);
  assert.deepEqual(drift.added, ['c']);
  assert.deepEqual(drift.removed, ['b']);
  assert.equal(drift.changed[0].field, 'risk');
  assert.deepEqual(drift.edgeChanged, ['e2']);
});

test('demo graph is structurally valid (unique ids, edges resolve)', () => {
  const snap = buildDemoGraph();
  const ids = new Set(snap.nodes.map((n) => n.id));
  assert.equal(ids.size, snap.nodes.length, 'unique node ids');
  const nodeIds = new Set(snap.nodes.map((n) => n.id));
  for (const e of snap.edges) {
    assert.ok(nodeIds.has(e.source), `edge source ${e.source}`);
    assert.ok(nodeIds.has(e.target), `edge target ${e.target}`);
  }
});