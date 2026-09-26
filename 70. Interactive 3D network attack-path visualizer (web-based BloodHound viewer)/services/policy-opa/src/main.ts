import { jsonServer, health, isMain } from '@pathsphere/server-kit';
import type { AbacDecision } from '@pathsphere/shared-types';

/** Policy decision endpoint.
 *  In production: OPA sidecar container evaluates the Rego bundle in
 *  services/policy-opa/policies/. This demo mirrors the same decision logic
 *  so the API contract is unchanged when OPA is swapped in. */

const ROLE_CAPABILITIES: Record<string, string[]> = {
  Admin: ['graph.read', 'graph.write', 'report.create', 'report.sign', 'ledger.read', 'ingest'],
  Analyst: ['graph.read', 'path.compute', 'report.create', 'report.sign', 'ingest'],
  Auditor: ['graph.read', 'ledger.read', 'report.view'],
  Viewer: ['graph.read'],
};

const SENSITIVITY_LIMIT: Record<string, string[]> = {
  public: ['Admin', 'Analyst', 'Auditor', 'Viewer'],
  internal: ['Admin', 'Analyst', 'Auditor'],
  confidential: ['Admin'],
  restricted: ['Admin'],
};

export function createPolicyService() {
  const decisions: Array<{ req: unknown; decision: AbacDecision; ts: string }> = [];
  return jsonServer([
    { method: 'GET', path: /^\/service$/, handler: health('policy-opa') },
    {
      method: 'POST',
      path: /^\/decision$/,
      handler: async (ctx) => {
        const req = await ctx.json<{
          subject: string;
          role: string;
          action: string;
          resource: string;
          resourceType: string;
          tenantId: string;
          tenantIds?: string[];
          sensitivity: string;
          ous?: string[];
          objectOu?: string;
          approverRequired?: boolean;
        }>();
        if (!req || typeof req.action !== 'string' || typeof req.role !== 'string') throw new Error('bad_request');

        const tenantMatch = (req.tenantIds ?? [req.tenantId]).includes(req.tenantId);
        const capability = ROLE_CAPABILITIES[req.role]?.includes(req.action) ?? false;
        const sensitivity = SENSITIVITY_LIMIT[req.sensitivity]?.includes(req.role) ?? false;
        const objectScope = (req.ous?.length ?? 0) === 0 || (req.objectOu ?? '') in (req.ous ?? []);
        const allowed = tenantMatch && capability && sensitivity && objectScope;

        decisions.push({ req, decision: { allowed, reason: allowed ? 'policy.allowed' : 'policy.denied' }, ts: new Date().toISOString() });
        return ctx.send(200, { result: { allowed, reason: allowed ? 'policy.allowed' : 'policy.denied' } });
      },
    },
    {
      method: 'GET',
      path: /^\/decisions$/,
      handler: (ctx) => ctx.jsonOk({ decisions: decisions.slice(-50) }),
    },
  ]);
}

export async function main(): Promise<void> {
  const port = Number(process.env.OPA_PORT) || 8181;
  const server = createPolicyService();
  server.listen(port, '0.0.0.0', () => console.log(`[policy-opa] listening on :${port}`));
}

if (isMain(import.meta.url)) {
  void main();
}