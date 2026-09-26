import { jsonServer, health, isMain } from '@pathsphere/server-kit';

const MITRE_MAP: Record<string, string[]> = {
  MemberOf: ['T1078', 'T1098'],
  HasSession: ['T1053', 'T1550.003'],
  AdminTo: ['T1068', 'T1078'],
  GenericAll: ['T1068'],
  WriteDacl: ['T1222', 'T1548'],
  CanRDP: ['T1021.001'],
  ForceChangePassword: ['T1098'],
};

export function createMitreMapperService() {
  return jsonServer([
    { method: 'GET', path: /^\/service$/, handler: health('mitre-mapper') },
    {
      method: 'POST',
      path: /^\/map$/,
      handler: async (ctx) => {
        const body = await ctx.json<{ edgeTypes?: string[] }>();
        const types = body?.edgeTypes ?? Object.keys(MITRE_MAP);
        return ctx.jsonOk({ mapping: Object.fromEntries(types.map((t) => [t, MITRE_MAP[t] ?? []])) });
      },
    },
  ]);
}

export async function main(): Promise<void> {
  const port = Number(process.env.MITRE_PORT) || 8088;
  createMitreMapperService().listen(port, '0.0.0.0', () => console.log(`[mitre-mapper] listening on :${port}`));
}

if (isMain(import.meta.url)) {
  void main();
}