import { jsonServer, health, isMain } from '@pathsphere/server-kit';
import { sha256Hex } from '@pathsphere/security-utils';
import type { GraphNode, GraphEdge, GraphSnapshot, EdgeType, NodeType } from '@pathsphere/shared-types';

/** SharpHound-lite ingestion.
 *  External tools (SharpHound/AzureHound) emit {nodes:[],edges:[]}. We:
 *  1. normalize casing               -> canonical GraphSnapshot
 *  2. compute idempotency fingerprint-> collision-guarded commit
 *  3. emit audit events to ledger
 * In production this writes to Neo4j (parameterized MERGE) after OPA validation. */

export interface SharpHoundLitePayload {
  dataVersion?: string;
  collectedAt?: string;
  tenantId: string;
  nodes: Array<{ id: string; type: string; name: string; enabled?: boolean; tier0?: boolean; properties?: Record<string, unknown> }>;
  edges: Array<{ id: string; type: string; source: string; target: string; weight?: number; techniqueIds?: string[]; properties?: Record<string, unknown> }>;
}

const NODE_TYPE_MAP: Record<string, NodeType> = {
  User: 'User', Group: 'Group', Computer: 'Computer', Domain: 'Domain', OU: 'OU',
  Container: 'Container', GPO: 'GPO', AzureUser: 'AzureUser', AzureGroup: 'AzureGroup',
  AzureDevice: 'AzureDevice', ServicePrincipal: 'ServicePrincipal', ForeignPrincipal: 'ForeignPrincipal',
};

const EDGE_TYPE_MAP: Record<string, EdgeType> = {
  MemberOf: 'MemberOf', HasSession: 'HasSession', AdminTo: 'AdminTo', GenericAll: 'GenericAll',
  GenericWrite: 'GenericWrite', WriteDacl: 'WriteDacl', WriteOwner: 'WriteOwner',
  ForceChangePassword: 'ForceChangePassword', AddMember: 'AddMember', AddSelf: 'AddSelf',
  CanRDP: 'CanRDP', CanPSRemote: 'CanPSRemote', AllowedToDelegate: 'AllowedToDelegate',
  Owns: 'Owns', GPLink: 'GPLink', AddKeyCredentialLink: 'AddKeyCredentialLink', Contains: 'Contains',
};

export function parseSharpHoundLite(input: unknown): GraphSnapshot {
  const data = input as SharpHoundLitePayload;
  if (!data || !Array.isArray(data.nodes) || !Array.isArray(data.edges)) {
    throw new Error('invalid-sharphound-payload');
  }
  const nodes: GraphNode[] = data.nodes.map((r) => ({
    id: String(r.id ?? ''),
    type: NODE_TYPE_MAP[r.type] ?? 'Container',
    name: String(r.name ?? r.id ?? ''),
    tenantId: data.tenantId,
    enabled: r.enabled,
    tier0: r.tier0,
    riskScore: 0,
    properties: r.properties ?? {},
  }));
  const edges: GraphEdge[] = data.edges.map((r) => ({
    id: String(r.id ?? `${r.source}__${r.target}__${r.type}`),
    type: EDGE_TYPE_MAP[r.type] ?? 'Contains',
    source: String(r.source ?? ''),
    target: String(r.target ?? ''),
    tenantId: data.tenantId,
    weight: r.weight ?? 1,
    techniqueIds: r.techniqueIds ?? [],
    properties: r.properties ?? {},
  }));
  const graphVersion = `g-${data.dataVersion ?? 'ingested'}-${sha256Hex(JSON.stringify({ nodes, edges })).slice(0, 12)}`;
  return {
    graphVersion,
    collectedAt: data.collectedAt ?? new Date().toISOString(),
    sourceSystem: 'api',
    tenantId: data.tenantId,
    nodes,
    edges,
  };
}

/** Deterministic idempotency key — identical payload => key collision => request already applied. */
export function idempotencyKey(payload: unknown): string {
  return sha256Hex(JSON.stringify(payload));
}

export function createIngestionService() {
  const appliedHashes = new Set<string>();
  return jsonServer([
    { method: 'GET', path: /^\/service$/, handler: health('ingestion-service') },
    {
      method: 'POST',
      path: /^\/ingest$/,
      handler: async (ctx) => {
        const body = await ctx.json();
        const key = idempotencyKey(body);
        if (appliedHashes.has(key)) {
          return ctx.jsonOk({ status: 'duplicate', idempotencyKey: key });
        }
        const snapshot = parseSharpHoundLite(body);
        appliedHashes.add(key);
        console.log(JSON.stringify({
          service: 'ingestion-service', action: 'graph.ingested', graphVersion: snapshot.graphVersion,
          nodes: snapshot.nodes.length, edges: snapshot.edges.length, idempotencyKey: key, ts: new Date().toISOString(),
        }));
        return ctx.jsonOk({ status: 'ingested', graphVersion: snapshot.graphVersion, idempotencyKey: key });
      },
    },
    {
      // Demo: load the bundled demo graph as if ingested by an external collector.
      method: 'GET',
      path: /^\/ingest$/,
      handler: async (ctx) => {
        const { buildDemoGraph } = await import('@pathsphere/demo-data');
        const snap = buildDemoGraph();
        const key = idempotencyKey(snap.graphVersion);
        if (appliedHashes.has(key)) {
          return ctx.jsonOk({ status: 'duplicate', idempotencyKey: key });
        }
        appliedHashes.add(key);
        console.log(JSON.stringify({
          service: 'ingestion-service', action: 'graph.ingested_demo', graphVersion: snap.graphVersion,
          nodes: snap.nodes.length, edges: snap.edges.length, idempotencyKey: key, ts: new Date().toISOString(),
        }));
        return ctx.jsonOk({ status: 'ingested', graphVersion: snap.graphVersion, idempotencyKey: key });
      },
    },
  ]);
}

export async function main(): Promise<void> {
  const port = Number(process.env.INGEST_PORT) || 8084;
  const server = createIngestionService();
  server.listen(port, '0.0.0.0', () => console.log(`[ingestion-service] listening on :${port}`));
}

if (isMain(import.meta.url)) {
  void main();
}