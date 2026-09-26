import { jsonServer, health, isMain } from '@pathsphere/server-kit';
import { loadDemoGraph } from '@pathsphere/demo-data';

const RISK_WEIGHTS: Record<string, number> = { User: 1, Group: 2, Computer: 3, Domain: 8, GPO: 4, OU: 2 };

export function createRiskScoringService() {
  return jsonServer([
    { method: 'GET', path: /^\/service$/, handler: health('risk-scoring') },
    {
      method: 'GET',
      path: /^\/score$/,
      handler: (ctx) => {
        const { nodes } = loadDemoGraph();
        const scores = [...nodes.values()].map((n) => ({
          id: n.id,
          name: n.name,
          type: n.type,
          tier0: n.tier0 === true,
          riskScore: (n.riskScore ?? 0) + (RISK_WEIGHTS[n.type] ?? 1),
        }));
        return ctx.jsonOk({ modelVersion: 'v1', computedAt: new Date().toISOString(), scores: scores.sort((a, b) => b.riskScore - a.riskScore).slice(0, 20) });
      },
    },
  ]);
}

export async function main(): Promise<void> {
  const port = Number(process.env.RISK_PORT) || 8087;
  createRiskScoringService().listen(port, '0.0.0.0', () => console.log(`[risk-scoring] listening on :${port}`));
}

if (isMain(import.meta.url)) {
  void main();
}