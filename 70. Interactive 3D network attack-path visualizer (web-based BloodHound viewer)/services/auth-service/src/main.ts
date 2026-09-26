import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { createHash, createHmac } from 'node:crypto';
import { isMain } from '@pathsphere/server-kit';

/** OIDC-lite issuer. In production, delegate to Keycloak/Entra ID (OIDC provider). */
export interface OidcUser {
  sub: string;
  username: string;
  role: 'Viewer' | 'Analyst' | 'Auditor' | 'Admin';
  tenantIds: string[];
  ous: string[];
}

export interface DirectoryUser {
  username: string;
  passwordHash: string;
  isLocked?: boolean;
  mustMfa: boolean;
}

export interface AuthServiceOptions {
  secret: string;
  kid?: string;
  tokenTtlSec?: number;
  users?: Record<string, DirectoryUser>;
  audit?: (action: string, meta: Record<string, unknown>) => Promise<void>;
}

function base64url(input: string | Buffer): string {
  return Buffer.from(input instanceof Buffer ? input : input).toString('base64url');
}

function createJwt(header: Record<string, unknown>, payload: Record<string, unknown>, secret: string): string {
  const h = base64url(JSON.stringify(header));
  const p = base64url(JSON.stringify(payload));
  const sig = createHmac('sha256', secret).update(`${h}.${p}`).digest('base64url');
  return `${h}.${p}.${sig}`;
}

function parseJwt<T>(token: string, secret: string): T | null {
  const [h, p, sig] = token.split('.');
  if (!h || !p || !sig) return null;
  const expected = createHmac('sha256', secret).update(`${h}.${p}`).digest('base64url');
  if (!requireSafeEqual(sig, expected)) return null;
  const payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8')) as T & { exp?: number };
  if (payload.exp !== undefined && payload.exp < Math.floor(Date.now() / 1000)) return null;
  return payload;
}

function requireSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export function createAuthService(options: AuthServiceOptions) {
  const secret = options.secret;
  const kid = options.kid ?? 'ps3d-1';
  const ttl = options.tokenTtlSec ?? 900; // 15 min
  const audit = options.audit ?? (async (): Promise<void> => undefined);
  const users = new Map<string, DirectoryUser>(
    Object.entries(options.users ?? {
      'analyst.demo': { username: 'analyst.demo', passwordHash: sha256('ChangeMe!123'), mustMfa: true },
      'auditor.demo': { username: 'auditor.demo', passwordHash: sha256('ChangeMe!123'), mustMfa: true },
    }),
  );

  const roleByUsername = (u: string): OidcUser['role'] => (u.startsWith('auditor') ? 'Auditor' : 'Analyst');

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = (req.url ?? '/').split('?')[0] ?? '/';
    const seg = url.split('/').filter(Boolean);

    const send = (code: number, payload: unknown): void => {
      res.writeHead(code, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(payload));
    };

    if (req.method === 'GET' && (seg[0] === 'service' || seg[0] === 'health')) {
      return send(200, { name: 'auth-service', status: 'ok', kid });
    }
    if (req.method === 'GET' && seg[0] === 'jwks') {
      return send(200, { keys: [{ kty: 'oct', k: base64url(secret), kid, alg: 'HS256', use: 'sig' }] });
    }
    if (req.method === 'POST' && seg[0] === 'login') {
      const body = await readJson(req);
      if (!body || typeof body !== 'object') return send(400, { error: 'bad_request' });
      const { username, password } = body as { username?: string; password?: string };
      if (typeof username !== 'string' || typeof password !== 'string') return send(400, { error: 'bad_request' });
      const user = users.get(username);
      if (!user) {
        await audit('auth.login_failed', { username });
        return send(401, { error: 'invalid_credentials' });
      }
      if (user.isLocked) {
        await audit('auth.login_locked', { username });
        return send(403, { error: 'account_locked' });
      }
      if (sha256(password) !== user.passwordHash) {
        await audit('auth.login_failed', { username });
        return send(401, { error: 'invalid_credentials' });
      }
      const oidc: OidcUser = {
        sub: username,
        username,
        role: roleByUsername(username),
        tenantIds: ['T-001'],
        ous: ['OU=Corp,DC=demo,DC=local'],
      };
      const token = createJwt(
        { alg: 'HS256', typ: 'JWT', kid },
        { ...oidc, exp: Math.floor(Date.now() / 1000) + ttl },
        secret,
      );
      await audit('auth.login_success', { username, mfa: user.mustMfa });
      return send(200, { access_token: token, token_type: 'Bearer', expires_in: ttl, mfa_required: user.mustMfa });
    }
    if (req.method === 'POST' && seg[0] === 'validate') {
      const body = (await readJson(req)) as { access_token?: unknown } | null;
      const token = body?.access_token;
      if (typeof token !== 'string') return send(400, { error: 'bad_request' });
      const user = parseJwt<OidcUser>(token, secret);
      if (!user) return send(401, { error: 'invalid_token' });
      await audit('auth.validate', { username: user.username });
      return send(200, user);
    }
    return send(404, { error: 'not_found' });
  }

  return {
    handle,
    signJwt: (payload: unknown) =>
      createJwt({ alg: 'HS256', typ: 'JWT', kid }, payload as Record<string, unknown>, secret),
    verifyJwt: (token: string) => parseJwt<OidcUser>(token, secret),
  };
}

function sha256(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const raw = Buffer.concat(chunks).toString('utf8');
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/** Audit hook default — production posts to audit-ledger (hash-chained). */
const defaultAudit = async (action: string, meta: Record<string, unknown>): Promise<void> => {
  console.log(JSON.stringify({ service: 'auth-service', action, meta, ts: new Date().toISOString() }));
};

export async function main(): Promise<void> {
  const port = Number(process.env.AUTH_PORT) || 8080;
  const secret = process.env.AUTH_SIGNING_SECRET || 'dev-only-change-me';
  const userStore = process.env.AUTH_USERS ? JSON.parse(process.env.AUTH_USERS) : undefined;
  const service = createAuthService({ secret, users: userStore, audit: defaultAudit });
  const server = createServer((req, res) => void service.handle(req, res));
  server.listen(port, '0.0.0.0', () => console.log(`[auth-service] listening on :${port}`));
}

if (isMain(import.meta.url)) {
  void main();
}