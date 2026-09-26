import type { BHEdge, BHNode, EdgeType, GraphModel } from '../types';

/**
 * BloodHound-style adjacency.
 * - HasSession: navigable in BOTH directions (user -> machine via credentials,
 *   machine -> user via credential theft on that host). Locks real lateral movement.
 * - All other edges: navigable SOURCE -> TARGET only (privilege granted toward target).
 */
export function buildAdjacency(edges: BHEdge[]): Map<string, { to: string; edge: BHEdge }[]> {
  const adj = new Map<string, { to: string; edge: BHEdge }[]>();
  const push = (from: string, to: string, edge: BHEdge) => {
    const list = adj.get(from) ?? [];
    list.push({ to, edge });
    adj.set(from, list);
  };
  for (const e of edges) {
    push(e.source, e.target, e);
    if (e.type === 'HasSession') push(e.target, e.source, e);
  }
  return adj;
}

export interface ShortestPathResult {
  found: boolean;
  hops: { edge: BHEdge; fromDir: 'source' | 'target' }[];
  nodesOnPath: string[];
}

/** BFS shortest path from `startId` to `targetId`. */
export function shortestPath(
  adj: Map<string, { to: string; edge: BHEdge }[]>,
  startId: string,
  targetId: string,
): ShortestPathResult {
  const visited = new Set<string>([startId]);
  const prev = new Map<string, { from: string; edge: BHEdge; fromDir: 'source' | 'target' }>();
  const queue: string[] = [startId];

  while (queue.length > 0) {
    const cur = queue.shift()!;
    if (cur === targetId) break;
    const list = adj.get(cur) ?? [];
    for (const { to, edge } of list) {
      if (visited.has(to)) continue;
      visited.add(to);
      prev.set(to, { from: cur, edge, fromDir: edge.source === cur ? 'source' : 'target' });
      queue.push(to);
      if (to === targetId) break;
    }
  }

  if (!prev.has(targetId)) return { found: false, hops: [], nodesOnPath: [] };

  const hops: ShortestPathResult['hops'] = [];
  const nodesOnPath: string[] = [targetId];
  let cur = targetId;
  while (cur !== startId) {
    const p = prev.get(cur)!;
    hops.unshift({ edge: p.edge, fromDir: p.fromDir });
    nodesOnPath.unshift(p.from);
    cur = p.from;
  }
  return { found: true, hops, nodesOnPath };
}

export interface ReachabilityReport {
  /** nodes reachable by any owned node */
  exposedNodeIds: Set<string>;
  /** nodes from which the high-value target is reachable */
  canReachTarget: Set<string>;
  ownedNodes: BHNode[];
}

/** Full BloodHound-style reachability analysis over the graph. */
export function reachabilityAnalysis(
  model: GraphModel,
  adj: Map<string, { to: string; edge: BHEdge }[]>,
  targetId: string,
): ReachabilityReport {
  const owned = model.nodes.filter((n) => n.owned);
  const ownedIds = new Set(owned.map((n) => n.id));
  const exposed = new Set<string>(ownedIds);
  const queue = [...ownedIds];

  // forward BFS from owned seeds
  while (queue.length) {
    const cur = queue.shift()!;
    for (const { to } of adj.get(cur) ?? []) {
      if (!exposed.has(to)) {
        exposed.add(to);
        queue.push(to);
      }
    }
  }

  // reverse reachability: which nodes can reach target?  (do reverse BFS from target on reversed adjacency)
  const revAdj = new Map<string, { from: string; edge: BHEdge }[]>();
  for (const e of model.edges) {
    const push = (frm: string, to: string, edge: BHEdge) => {
      const list = revAdj.get(to) ?? [];
      list.push({ from: frm, edge });
      revAdj.set(to, list);
    };
    push(e.source, e.target, e);
    if (e.type === 'HasSession') push(e.target, e.source, e);
  }

  const canReach = new Set<string>();
  const rq = [targetId];
  canReach.add(targetId);
  while (rq.length) {
    const cur = rq.shift()!;
    for (const { from } of revAdj.get(cur) ?? []) {
      if (!canReach.has(from)) {
        canReach.add(from);
        rq.push(from);
      }
    }
  }

  return { exposedNodeIds: exposed, canReachTarget: canReach, ownedNodes: owned };
}

export const EDGE_TECHNIQUES: Record<
  EdgeType,
  { label: string; technique: string; color: string; usedOn: string }
> = {
  Owns: {
    label: 'Owned / control',
    technique: 'T1078 · Valid Accounts',
    color: '#ff5470',
    usedOn: 'Full control over this object — a foothold seed.',
  },
  MemberOf: {
    label: 'Member of',
    technique: 'T1078 · Valid Accounts',
    color: '#8a6dff',
    usedOn: 'Attacker inherits group privileges through membership.',
  },
  HasSession: {
    label: 'Has session',
    technique: 'T1003 · OS Credential Dumping',
    color: '#2ee6a8',
    usedOn: 'A principal has an interactive/service session here — steal credentials (LSASS, Kerberos tickets).',
  },
  AdminTo: {
    label: 'Local admin',
    technique: 'T1546 · Hijack Execution Flow / lateral',
    color: '#ffb020',
    usedOn: 'Attacker is local administrator on target — can run code, harvest credentials, plant persistence.',
  },
  GenericAll: {
    label: 'GenericAll',
    technique: 'T1098 · Account Manipulation',
    color: '#ff5470',
    usedOn: 'Full object control — reset passwords, add self to group, modify attributes (bloodyAD / dacledit).',
  },
  GenericWrite: {
    label: 'GenericWrite',
    technique: 'T1098 · Account Manipulation',
    color: '#ff5470',
    usedOn: 'Write access — set SPN to Kerberoast, add self to a group, shadow credentials.',
  },
  WriteDacl: {
    label: 'WriteDacl',
    technique: 'T1222 · DACL modification',
    color: '#ff5470',
    usedOn: 'Modify the target DACL to grant DCSync / full control to yourself.',
  },
  AllExtendedRights: {
    label: 'All extended rights',
    technique: 'T1098 · Account Manipulation',
    color: '#ff5470',
    usedOn: 'Reset password / UAC / user-account-control rights on the object.',
  },
  ForceChangePassword: {
    label: 'Force password reset',
    technique: 'T1098 · Account Manipulation',
    color: '#ff5470',
    usedOn: 'Reset target password without current credentials — seize a service account.',
  },
  AddMember: {
    label: 'Add member',
    technique: 'T1098 · Add to group',
    color: '#ff5470',
    usedOn: 'Add a controlled principal to this group (e.g., DOMAIN ADMINS).',
  },
  CanRDP: {
    label: 'Remote desktop',
    technique: 'T1021.001 · Remote Desktop',
    color: '#5c7cfa',
    usedOn: 'Interactive RDP capability onto the target host.',
  },
};

export const EDGE_NAMES: Record<EdgeType, string> = {
  Owns: 'Owns',
  MemberOf: 'MemberOf',
  HasSession: 'HasSession',
  AdminTo: 'AdminTo',
  GenericAll: 'GenericAll',
  GenericWrite: 'GenericWrite',
  WriteDacl: 'WriteDacl',
  AllExtendedRights: 'AllExtendedRights',
  ForceChangePassword: 'ForceChangePassword',
  AddMember: 'AddMember',
  CanRDP: 'CanRDP',
};

export function hopNarrative(edge: BHEdge, from: BHNode, to: BHNode): string {
  const t = EDGE_TECHNIQUES[edge.type];
  const dirArrow = edge.type === 'HasSession' ? '⇄' : '→';
  const base = `${from.name} ${dirArrow} ${to.name}`;
  const flavor =
    edge.type === 'MemberOf'
      ? `${from.name} is a member of ${to.name}; attacker inherits its collective privileges.`
      : edge.type === 'HasSession'
        ? `A session belonging to ${from.name} is active on ${to.name}; attacker extracts credentials on this host and pivots.`
        : edge.type === 'AdminTo'
          ? `Ownership of ${from.name} grants local administrator on ${to.name}.`
          : t.usedOn;
  return `${base}. ${flavor}`;
}