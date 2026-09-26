import { jsonServer, health, isMain } from '@pathsphere/server-kit';

/** Detects drift between two graph snapshots (e.g., pre-/post-remediation). */
export interface DriftReport {
  added: string[];
  removed: string[];
  changed: Array<{ id: string; field: string; before: unknown; after: unknown }>;
  edgeChanged: string[];
}

export function computeDrift(before: { nodes: Array<{ id: string; properties: Record<string, unknown> }>; edges: Array<{ id: string }> }, after: { nodes: Array<{ id: string; properties: Record<string, unknown> }>; edges: Array<{ id: string }> }): DriftReport {
  const bMap = new Map(before.nodes.map((n) => [n.id, n]));
  const aMap = new Map(after.nodes.map((n) => [n.id, n]));
  const added: string[] = [];
  const removed: string[] = [];
  const changed: DriftReport['changed'] = [];
  for (const a of after.nodes) if (!bMap.has(a.id)) added.push(a.id);
  for (const b of before.nodes) if (!aMap.has(b.id)) removed.push(b.id);
  for (const [id, b] of bMap) {
    const a = aMap.get(id);
    if (!a) continue;
    for (const key of new Set([...Object.keys(b.properties), ...Object.keys(a.properties)])) {
      if (JSON.stringify(b.properties[key]) !== JSON.stringify(a.properties[key])) {
        changed.push({ id, field: key, before: b.properties[key], after: a.properties[key] });
      }
    }
  }
  const bE = new Set(before.edges.map((e) => e.id));
  const aE = new Set(after.edges.map((e) => e.id));
  const edgeChanged = [...new Set([...bE, ...aE])].filter((id) => bE.has(id) !== aE.has(id));
  return { added, removed, changed, edgeChanged };
}

export function createDriftService() {
  return jsonServer([
    { method: 'GET', path: /^\/service$/, handler: health('delta-drift') },
    {
      method: 'POST',
      path: /^\/drift$/,
      handler: async (ctx) => {
        const body = await ctx.json<{ before: Parameters<typeof computeDrift>[0]; after: Parameters<typeof computeDrift>[1] }>();
        if (!body?.before || !body?.after) throw new Error('bad_request');
        return ctx.jsonOk({ drift: computeDrift(body.before, body.after), ts: new Date().toISOString() });
      },
    },
  ]);
}

export async function main(): Promise<void> {
  const port = Number(process.env.DRIFT_PORT) || 8089;
  createDriftService().listen(port, '0.0.0.0', () => console.log(`[delta-drift] listening on :${port}`));
}

if (isMain(import.meta.url)) {
  void main();
}