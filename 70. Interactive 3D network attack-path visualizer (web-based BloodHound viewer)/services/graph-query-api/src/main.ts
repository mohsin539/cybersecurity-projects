import { jsonServer, bearer, health, isMain } from '@pathsphere/server-kit';
import type { GraphNode, GraphEdge, AuthContext } from '@pathsphere/shared-types';
import { pathCacheKey } from '@pathsphere/security-utils';

/** Persisted Query Registry — GraphQL allow-list (OWASP A03 / design principle P-02).
 *  Only these operations may be served; arbitrary client-side Cypher is never accepted. */
export interface PersistedQuery {
  name: string;
  allowRoles: AuthContext['role'][];
  maxRows: number;
  maxDepth: number;
  /** ABAC policy decision stub - in prod this is a Rego decision via OPA. */
  abacCheck: (ctx: AuthContext) => boolean | Promise<boolean>;
}

const PERSISTED_QUERIES: PersistedQuery[] = [
  {
    name: 'GetNodeById',
    allowRoles: ['Viewer', 'Analyst', 'Auditor', 'Admin'],
    maxRows: 1,
    maxDepth: 0,
    abacCheck: (ctx) => ctx.sensitivity !== 'restricted' || ctx.role === 'Auditor' || ctx.role === 'Admin',
  },
  {
    name: 'GetSubgraph',
    allowRoles: ['Analyst', 'Auditor', 'Admin'],
    maxRows: 5000,
    maxDepth: 5,
    abacCheck: (ctx) => ['Analyst', 'Auditor', 'Admin'].includes(ctx.role),
  },
  {
    name: 'GetTier0Reachable',
    allowRoles: ['Admin'],
    maxRows: 1000,
    maxDepth: 10,
    abacCheck: (ctx) => ctx.role === 'Admin',
  },
];

/** In-memory graph injected by bootstrap (replaces Neo4j of record for the demo). */
export interface GraphStore {
  nodes: Map<string, GraphNode>;
  edges: GraphEdge[];
  graphVersion: string;
}

export function createGraphApi(store: GraphStore) {
  const server = jsonServer([
    { method: 'GET', path: /^\/service$/, handler: health('graph-query-api') },
    {
      method: 'GET',
      path: /^\/persisted-queries$/,
      handler: (ctx) =>
        ctx.jsonOk(
          PERSISTED_QUERIES.map(({ name, allowRoles, maxRows, maxDepth }) => ({ name, allowRoles, maxRows, maxDepth })),
        ),
    },
    {
      method: 'POST',
      path: /^\/graphql$/,
      handler: async (ctx) => {
        const token = bearer(ctx.req);
        if (!token) throw new Error('unauthorized');
        /** Demo auth context — production resolves from auth-service introspect. */
        const user = await introspect(token);
        const { operation, variables } = await ctx.json<{ operation?: string; variables?: Record<string, unknown> }>();
        const query = PERSISTED_QUERIES.find((q) => q.name === operation);
        if (!query) {
          await emitAudit(user, 'graphql.denied_operation', { operation });
          return ctx.send(403, { errors: [{ message: 'operation_not_in_allowlist' }] });
        }
        if (!query.allowRoles.includes(user.role)) {
          await emitAudit(user, 'graphql.role_denied', { operation });
          return ctx.send(403, { errors: [{ message: 'role_not_allowed' }] });
        }
        const allowed = await query.abacCheck(user);
        if (!allowed) {
          await emitAudit(user, 'graphql.abac_denied', { operation });
          return ctx.send(403, { errors: [{ message: 'abac_denied' }] });
        }

        const result = execute(query.name, variables ?? {}, store);
        await emitAudit(user, 'graphql.executed', { operation, rows: result.rows, cacheKey: result.cacheKey });
        return ctx.jsonOk({ data: result.data, meta: { cacheKey: result.cacheKey, rows: result.rows } });
      },
    },
    {
      method: 'GET',
      path: /^\/nodes\/(.+)$/,
      handler: (ctx) => {
        const id = decodeURIComponent(ctx.seg[1] ?? '');
        const node = store.nodes.get(id);
        if (!node) return ctx.send(404, { error: 'node_not_found' });
        return ctx.jsonOk({ node });
      },
    },
    {
      method: 'GET',
      path: /^\/graph-version$/,
      handler: (ctx) => ctx.jsonOk({ graphVersion: store.graphVersion, nodeCount: store.nodes.size, edgeCount: store.edges.length }),
    },
  ]);

  return server;
}

function execute(name: string, variables: Record<string, unknown>, store: GraphStore): {
  data: unknown;
  rows: number;
  cacheKey: string;
} {
  const digest = pathCacheKey('T-001', store.graphVersion, JSON.stringify({ name, variables }));
  switch (name) {
    case 'GetNodeById': {
      const node = store.nodes.get(String(variables.id ?? ''));
      return { data: node ? { node } : { node: null }, rows: node ? 1 : 0, cacheKey: digest };
    }
    case 'GetSubgraph': {
      const seedId = String(variables.seed ?? '');
      const maxDepth = Number(variables.maxDepth ?? 3);
      const visited = new Set<string>();
      const nodes: GraphNode[] = [];
      const edgesOut: GraphEdge[] = [];
      const edgeMap = new Map<string, GraphEdge[]>();
      for (const e of store.edges) {
        const list = edgeMap.get(e.source) ?? [];
        list.push(e);
        edgeMap.set(e.source, list);
      }
      const frontier = [seedId];
      let depth = 0;
      while (frontier.length && depth <= maxDepth) {
        const next: string[] = [];
        for (const id of frontier) {
          if (visited.has(id)) continue;
          visited.add(id);
          const n = store.nodes.get(id);
          if (n) nodes.push(n);
          for (const e of edgeMap.get(id) ?? []) {
            edgesOut.push(e);
            next.push(e.target);
          }
        }
        frontier.splice(0, frontier.length, ...next);
        depth++;
      }
      return { data: { nodes, edges: edgesOut }, rows: nodes.length, cacheKey: digest };
    }
    case 'GetTier0Reachable': {
      return { data: { nodes: [...store.nodes.values()].filter((n) => n.tier === 0) }, rows: store.nodes.size, cacheKey: digest };
    }
    default:
      return { data: null, rows: 0, cacheKey: digest };
  }
}

/** Demo introspect — replace with real auth-service /introspect call. */
async function introspect(token: string): Promise<AuthContext> {
  if (!token.startsWith('demo-')) {
    // Accept any HS256 token from auth-service in dev; role extracted from payload base64
    try {
      const payload = JSON.parse(Buffer.from(token.split('.')[1] ?? '', 'base64url').toString('utf8')) as Partial<AuthContext>;
      return {
        subject: String(payload.subject ?? 'unknown'),
        role: payload.role ?? 'Viewer',
        tenantIds: payload.tenantIds ?? ['T-001'],
        ous: payload.ous ?? [],
        sensitivity: payload.sensitivity ?? 'internal',
      };
    } catch {
      /* fallthrough */
    }
  }
  return { subject: 'demo-analyst', role: 'Analyst', tenantIds: ['T-001'], ous: ['OU=Corp,DC=demo,DC=local'], sensitivity: 'confidential' };
}

async function emitAudit(_user: AuthContext, action: string, meta: Record<string, unknown>): Promise<void> {
  // Production: POST to audit-ledger service. Demo: log line only.
  console.log(JSON.stringify({ service: 'graph-query-api', action, meta, ts: new Date().toISOString() }));
}

export async function main(): Promise<void> {
  const { loadDemoGraph } = await import('@pathsphere/demo-data');
  const store = loadDemoGraph();
  const port = Number(process.env.GRAPH_API_PORT) || 8081;
  const server = createGraphApi(store);
  server.listen(port, '0.0.0.0', () => console.log(`[graph-query-api] listening on :${port} (graphVersion=${store.graphVersion}, nodes=${store.nodes.size}, edges=${store.edges.length})`));
}

if (isMain(import.meta.url)) {
  void main();
}