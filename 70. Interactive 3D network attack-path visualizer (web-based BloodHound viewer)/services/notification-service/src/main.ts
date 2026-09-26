import { jsonServer, health, isMain } from '@pathsphere/server-kit';

export function createNotificationService() {
  const delivered: string[] = [];
  return jsonServer([
    { method: 'GET', path: /^\/service$/, handler: health('notification-service') },
    {
      method: 'POST',
      path: /^\/notify$/,
      handler: async (ctx) => {
        const body = await ctx.json<{ channel?: string; to?: string; template?: string }>();
        if (!body?.template) throw new Error('bad_request');
        delivered.push(JSON.stringify(body));
        return ctx.send(202, { status: 'queued', event: { service: 'notification-service', action: 'notify.queued' } });
      },
    },
    { method: 'GET', path: /^\/delivered$/, handler: (ctx) => ctx.jsonOk({ count: delivered.length, delivered: delivered.slice(-20) }) },
  ]);
}

export async function main(): Promise<void> {
  const port = Number(process.env.NOTIFY_PORT) || 8086;
  createNotificationService().listen(port, '0.0.0.0', () => console.log(`[notification-service] listening on :${port}`));
}

if (isMain(import.meta.url)) {
  void main();
}