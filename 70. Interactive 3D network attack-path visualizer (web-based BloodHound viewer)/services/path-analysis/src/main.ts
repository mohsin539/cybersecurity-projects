import { jsonServer, health, isMain } from '@pathsphere/server-kit';
import { loadDemoGraph } from '@pathsphere/demo-data';
import type { GraphEdge, GraphNode, AttackPath, PathStep, EdgeType } from '@pathsphere/shared-types';

export interface PathEngine {
  findShortest(source: string, target: string): AttackPath | null;
  findKShortest(source: string, target: string, k: number, maxDepth?: number): AttackPath[];
}

/** Yen's algorithm over weighted directed edges. Deterministic, no external deps. */
export function createPathEngine(
  nodes: Map<string, GraphNode>,
  edges: GraphEdge[],
  opts?: { maxDepth?: number },
): PathEngine {
  const adj = new Map<string, GraphEdge[]>();
  for (const edge of edges) {
    const list = adj.get(edge.source) ?? [];
    list.push(edge);
    adj.set(edge.source, list);
  }

  function toPath(path: string[]): AttackPath {
    const steps: PathStep[] = [];
    let totalWeight = 0;
    for (let i = 0; i < path.length - 1; i++) {
      const from = path[i]!;
      const to = path[i + 1]!;
      const edge = adj.get(from)?.find((e) => e.target === to);
      const weight = edge?.weight ?? 1;
      totalWeight += weight;
      steps.push({
        edgeId: edge?.id ?? '',
        from,
        to,
        edgeType: (edge?.type ?? 'GenericAll') as EdgeType,
        weight,
        techniqueIds: edge?.techniqueIds ?? [],
        remediation: edge ? remediationFor(edge.type) : 'Break the relationship',
        explainable: `${nodes.get(from)?.name ?? from} ->${edge ? `[${edge.type}]` : ''}-> ${nodes.get(to)?.name ?? to}`,
      });
    }
    const targetNode = nodes.get(path[path.length - 1]!);
    return {
      pathId: `path-${steps.reduce((acc, s) => acc + s.edgeId, '').slice(0, 24)}`,
      steps,
      totalWeight,
      length: steps.length,
      tier0Reached: targetNode?.tier0 === true,
    };
  }

  function shortestFromBanned(source: string, target: string, bannedVertices: Set<string>, bannedEdges: Set<string>): string[] | null {
    const dist = new Map<string, number>();
    const prev = new Map<string, string>();
    const visited = new Set<string>();
    const pq: Array<{ node: string; d: number }> = [{ node: source, d: 0 }];
    dist.set(source, 0);
    while (pq.length) {
      pq.sort((a, b) => a.d - b.d);
      const cur = pq.shift()!;
      if (visited.has(cur.node)) continue;
      visited.add(cur.node);
      if (cur.node === target) break;
      for (const edge of adj.get(cur.node) ?? []) {
        const key = `${edge.source}\u0000${edge.target}\u0000${edge.id}`;
        if (bannedEdges.has(key)) continue;
        if (bannedVertices.has(edge.target)) continue;
        const nd = cur.d + (edge.weight ?? 1);
        if (dist.get(edge.target) === undefined || nd < dist.get(edge.target)!) {
          dist.set(edge.target, nd);
          prev.set(edge.target, cur.node);
          pq.push({ node: edge.target, d: nd });
        }
      }
    }
    if (dist.get(target) === undefined) return null;
    const path: string[] = [];
    let cur: string | undefined = target;
    while (cur !== undefined) {
      path.unshift(cur);
      cur = prev.get(cur);
    }
    return path;
  }

  function kShortest(source: string, target: string, k: number, maxDepth?: number): string[][] {
    const A: string[][] = [];
    const B: string[][] = [];
    const first = shortestFromBanned(source, target, new Set(), new Set());
    if (!first) return A;
    A.push(first);

    for (let ki = 1; ki < k; ki++) {
      const prevPath = A[ki - 1]!;
      for (let i = 0; i < prevPath.length - 1; i++) {
        const spurNode = prevPath[i]!;
        const rootPath = prevPath.slice(0, i + 1);
        const bannedVertices = new Set(rootPath.slice(0, -1));
        const bannedEdges = new Set<string>();
        for (const p of A) {
          if (p.length >= i + 1 && p.slice(0, i + 1).join('/') === rootPath.join('/')) {
            const from = p[i];
            const to = p[i + 1];
            if (!from || !to) continue;
            bannedEdges.add(`${from}\u0000${to}\u0000${(adj.get(from) ?? []).find((e) => e.target === to)?.id ?? ''}`);
          }
        }
        const spur = shortestFromBanned(spurNode, target, bannedVertices, bannedEdges);
        if (!spur) continue;
        const total = [...rootPath.slice(0, -1), ...spur];
        if (maxDepth && total.length > maxDepth + 1) continue;
        if (!B.some((p) => p.join('/') === total.join('/'))) B.push(total);
      }
      if (!B.length) break;
      B.sort((a, b) => {
        const wa = weightOf(a);
        const wb = weightOf(b);
        return wa - wb || a.length - b.length;
      });
      const best = B.shift()!;
      A.push(best);
    }
    return A;
  }

  function weightOf(path: string[]): number {
    let w = 0;
    for (let i = 0; i < path.length - 1; i++) {
      const edge = adj.get(path[i]!)?.find((e) => e.target === path[i + 1]);
      w += edge?.weight ?? 1;
    }
    return w;
  }

  return {
    findShortest(source, target) {
      const p = shortestFromBanned(source, target, new Set(), new Set());
      return p ? toPath(p) : null;
    },
    findKShortest(source, target, k, maxDepth = opts?.maxDepth ?? 8) {
      return kShortest(source, target, Math.max(1, Math.min(k, 8)), maxDepth).map(toPath);
    },
  };
}

function remediationFor(type: string): string {
  switch (type) {
    case 'MemberOf':
      return 'Remove the user/group membership; re-audit the group owner.';
    case 'GenericAll':
      return 'Restrict full-control ACE on the target; scope ACL to least privilege.';
    case 'GenericWrite':
      return 'Tighten ACE; enforce break-glass review of write permissions.';
    case 'WriteDacl':
      return 'Remove WriteDacl; monitor DACL changes (SIEM rule).';
    case 'ForceChangePassword':
      return 'Recycle the exposed password; remove force-password-change ACE.';
    case 'CanRDP':
      return 'Disable RDP access; move the host behind a jump host.';
    case 'AdminTo':
      return 'Deploy LAPS; rotate local admin credentials; lockdown.';
    case 'HasSession':
      return 'Disable the session/credential reuse; enforce MFA on the account.';
    case 'AddKeyCredentialLink':
      return 'Enforce hardware-bound keys; revoke leaked key credential.';
    case 'Contains':
      return 'Review container membership — reduce containment of privileged principals.';
    default:
      return 'Break the relationship; re-validate by graph re-collection.';
  }
}

export function createPathService() {
  return jsonServer([
    { method: 'GET', path: /^\/service$/, handler: health('path-analysis') },
    {
      method: 'POST',
      path: /^\/compute-path$/,
      handler: async (ctx) => {
        const { source, target, k = 5, maxDepth = 8 } = await ctx.json<{ source?: string; target?: string; k?: number; maxDepth?: number }>();
        if (!source || !target) throw new Error('bad_request');
        const engine = createPathEngine(loadDemoGraph().nodes, loadDemoGraph().edges);
        const t0 = performance.now();
        const paths = engine.findKShortest(source, target, k, maxDepth);
        const ms = Math.round(performance.now() - t0);
        return ctx.jsonOk({
          jobId: `job-${Date.now().toString(36)}`,
          status: 'complete',
          source,
          target,
          paths,
          computedAt: new Date().toISOString(),
          graphVersion: loadDemoGraph().graphVersion,
          executionMs: ms,
        });
      },
    },
  ]);
}

export async function main(): Promise<void> {
  const port = Number(process.env.PATH_ANALYSIS_PORT) || 8082;
  const server = createPathService();
  server.listen(port, '0.0.0.0', () => console.log(`[path-analysis] listening on :${port}`));
}

if (isMain(import.meta.url)) {
  void main();
}