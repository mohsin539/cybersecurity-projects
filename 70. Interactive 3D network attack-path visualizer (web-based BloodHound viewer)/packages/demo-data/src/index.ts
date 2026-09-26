import type { GraphNode, GraphEdge, GraphSnapshot, NodeType } from '@pathsphere/shared-types';

/** Realistic-ish BloodHound-flavored demo graph (small, deterministic).
 *  Represents a single tenant with a tier-0 domain + helpdesk escalation chain. */

const T = 'T-001';

function n(id: string, type: NodeType, name: string, extra: Partial<GraphNode> = {}): GraphNode {
  return { id, type, name, tenantId: T, riskScore: 0, tier: 1, properties: {}, ...extra };
}

function e(id: string, type: GraphEdge['type'], source: string, target: string, extra: Partial<GraphEdge> = {}): GraphEdge {
  return { id, type, source, target, tenantId: T, weight: 1, techniqueIds: [], properties: {}, ...extra };
}

export function buildDemoGraph(): GraphSnapshot {
  const nodes: GraphNode[] = [
    n('node-1000', 'Domain', 'DEMO.LOCAL', { tier0: true, tier: 0, riskScore: 10 }),
    n('node-1001', 'Domain', 'MEGA.LOCAL', { tier0: true, tier: 0, riskScore: 10 }),
    n('node-2000', 'Group', 'DOMAIN ADMINS', { tier0: true, tier: 0, riskScore: 9 }),
    n('node-2001', 'Group', 'ENTERPRISE ADMINS', { tier0: false, tier: 1, riskScore: 6 }),
    n('node-2002', 'Group', 'HELPDESK', { tier0: false, tier: 1, riskScore: 7 }),
    n('node-2003', 'Group', 'SERVER OPS', { tier0: false, tier: 1, riskScore: 5 }),
    n('node-3000', 'Computer', 'DC01.DEMO.LOCAL', { tier0: true, tier: 0, riskScore: 9, enabled: true }),
    n('node-3001', 'Computer', 'DC02.DEMO.LOCAL', { tier0: true, tier: 0, riskScore: 9, enabled: true }),
    n('node-3002', 'Computer', 'WS-APP01.DEMO.LOCAL', { tier0: false, tier: 1, riskScore: 5, enabled: true }),
    n('node-3003', 'Computer', 'WS-FILE01.DEMO.LOCAL', { tier0: false, tier: 1, riskScore: 4, enabled: true }),
    n('node-3004', 'Computer', 'SRV-DB01.DEMO.LOCAL', { tier0: false, tier: 1, riskScore: 6, enabled: true }),
    n('node-3005', 'Computer', 'SRV-WEB01.DEMO.LOCAL', { tier0: false, tier: 1, riskScore: 5, enabled: true }),
    n('node-3006', 'Computer', 'EXCH01.DEMO.LOCAL', { tier0: false, tier: 1, riskScore: 6, enabled: true }),
    n('node-4000', 'User', 'ALICE', { tier0: false, tier: 1, riskScore: 3, enabled: true }),
    n('node-4001', 'User', 'BOB', { tier0: false, tier: 1, riskScore: 4, enabled: true }),
    n('node-4002', 'User', 'CAROL', { tier0: false, tier: 1, riskScore: 5, enabled: true }),
    n('node-4003', 'User', 'DAVE', { tier0: false, tier: 1, riskScore: 4, enabled: true }),
    n('node-4004', 'User', 'EVIL-COMPROMISED', { tier0: false, tier: 1, riskScore: 8, enabled: true }),
  ];

  const edges: GraphEdge[] = [
    // Domain -> admins group -> domain controllers
    e('edge-0001', 'Contains', 'node-1000', 'node-2000'),
    e('edge-0002', 'MemberOf', 'node-2000', 'node-2001'),
    e('edge-0003', 'MemberOf', 'node-2000', 'node-3000', { weight: 9 }),
    e('edge-0004', 'MemberOf', 'node-2000', 'node-3001', { weight: 9 }),
    e('edge-0005', 'Contains', 'node-1000', 'node-2002'),
    e('edge-0006', 'Contains', 'node-1000', 'node-2003'),
    e('edge-0007', 'MemberOf', 'node-2002', 'node-2003'),
    e('edge-0008', 'MemberOf', 'node-3002', 'node-2003', { weight: 3 }),
    e('edge-0009', 'MemberOf', 'node-3003', 'node-2003', { weight: 3 }),
    e('edge-0010', 'Contains', 'node-1000', 'node-3002'),
    e('edge-0011', 'Contains', 'node-1000', 'node-3003'),
    e('edge-0012', 'Contains', 'node-1000', 'node-3004'),
    e('edge-0013', 'Contains', 'node-1000', 'node-3005'),
    e('edge-0014', 'Contains', 'node-1000', 'node-3006'),

    // Users
    e('edge-0015', 'MemberOf', 'node-4000', 'node-2002', { weight: 2 }),
    e('edge-0016', 'MemberOf', 'node-4001', 'node-2002', { weight: 2 }),
    e('edge-0017', 'MemberOf', 'node-4002', 'node-2002', { weight: 2 }),
    e('edge-0018', 'MemberOf', 'node-4003', 'node-2003', { weight: 2 }),
    e('edge-0019', 'MemberOf', 'node-4004', 'node-2002', { weight: 2 }),
    e('edge-0020', 'HasSession', 'node-4004', 'node-3002', { weight: 3 }),
    e('edge-0021', 'HasSession', 'node-4003', 'node-3003', { weight: 3 }),

    // Privileged escalation chain (the juicy path)
    e('edge-0022', 'CanRDP', 'node-2002', 'node-3002', { weight: 4 }),
    e('edge-0023', 'GenericAll', 'node-3002', 'node-3004', { weight: 5 }),
    e('edge-0024', 'AdminTo', 'node-3004', 'node-3005', { weight: 4 }),
    e('edge-0025', 'AdminTo', 'node-3005', 'node-3006', { weight: 4 }),
    e('edge-0026', 'ForceChangePassword', 'node-3006', 'node-4004', { weight: 2 }),
    e('edge-0027', 'WriteDacl', 'node-3004', 'node-2000', { weight: 8 }),

    // Cross-domain / foreign trust
    e('edge-0028', 'MemberOf', 'node-2001', 'node-1001', { weight: 6 }),
    e('edge-0029', 'GPLink', 'node-1000', 'node-1001', { weight: 5 }),
    e('edge-0030', 'HasSession', 'node-4000', 'node-3002', { weight: 3 }),
  ];

  return {
    graphVersion: 'g-2026-09-23-001',
    collectedAt: new Date().toISOString(),
    sourceSystem: 'sharp-hound',
    tenantId: T,
    nodes,
    edges,
  };
}

/** Return a target for tests/demos: commonly queried identities. */
export const demoTargets = {
  user: 'node-4000', // ALICE
  domain: 'node-1000',
  dc: 'node-3000',
  domainAdminGroup: 'node-2000',
  tier0Compromise: 'node-4004', // EVIL-COMPROMISED
  guestSession: 'node-3003',
} as const;

export function loadDemoGraph(): { nodes: Map<string, GraphNode>; edges: GraphEdge[]; graphVersion: string } {
  const snap = buildDemoGraph();
  return { nodes: new Map(snap.nodes.map((x) => [x.id, x])), edges: snap.edges, graphVersion: snap.graphVersion };
}