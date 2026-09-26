import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

/** Cross-platform "is this module the entrypoint?" check for ESM services. */
export function isMain(importMetaUrl: string, argv1: string | undefined = process.argv[1]): boolean {
  if (!argv1) return false;
  try {
    return resolve(fileURLToPath(importMetaUrl)) === resolve(argv1);
  } catch {
    return false;
  }
}

export type Json = Record<string, unknown> | unknown[] | string | number | boolean | null;

export interface RouteContext {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  seg: string[];
  query: URLSearchParams;
  json<T = Json>(): Promise<T>;
  send(code: number, payload: unknown): void;
  jsonOk(payload: unknown): void;
}

export type Handler = (ctx: RouteContext) => Promise<void> | void;

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req
      .on('data', (c: Buffer) => chunks.push(c))
      .on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
      .on('error', reject);
  });
}

/**
 * Minimal JSON server builder used by every PathSphere microservice.
 * - Bodiless? -> empty object
 * - Strict JSON or 400
 * - Every route is wrapped to emit 500 on unexpected error
 */
export function jsonServer(routes: Array<{ method: string; path: RegExp | null; handler: Handler }>, log = true) {
  return createServer(async (req, res) => {
    const method = (req.method ?? 'GET').toUpperCase();
    const url = new URL(req.url ?? '/', 'http://localhost');
    const seg = url.pathname.split('/').filter(Boolean);

    const send = (code: number, payload: unknown): void => {
      if (res.writableEnded) return;
      res.writeHead(code, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    };

    const ctx: RouteContext = {
      req,
      res,
      url,
      seg,
      query: url.searchParams,
      async json<T = Json>(): Promise<T> {
        const raw = await readBody(req);
        if (raw.trim().length === 0) return {} as T;
        try {
          return JSON.parse(raw) as T;
        } catch {
          throw new Error('invalid-json');
        }
      },
      send,
      jsonOk: (payload: unknown) => send(200, payload),
    };

    try {
      const route = routes.find(
        (r) => r.method === method && (r.path === null || r.path.test(url.pathname)),
      );
      if (!route) return send(404, { error: 'not_found', path: url.pathname });
      await route.handler(ctx);
    } catch (err) {
      if ((err as Error).message === 'invalid-json') return send(400, { error: 'bad_json' });
      if ((err as Error).message === 'unauthorized') return send(401, { error: 'unauthorized' });
      if ((err as Error).message === 'forbidden') return send(403, { error: 'forbidden' });
      if (log) console.error('[server]', err);
      return send(500, { error: 'internal_error' });
    }
  });
}

/** Standard health handler for all services. */
export function health(name: string): Handler {
  return (ctx) => ctx.jsonOk({ name, status: 'ok', ts: new Date().toISOString() });
}

/** Bearer token extraction with constant-time compare not needed for demo. */
export function bearer(req: IncomingMessage): string | null {
  const auth = req.headers.authorization;
  if (!auth) return null;
  const m = /^Bearer\s+(.+)$/.exec(auth);
  return m?.[1] ?? null;
}

export { ServerResponse };