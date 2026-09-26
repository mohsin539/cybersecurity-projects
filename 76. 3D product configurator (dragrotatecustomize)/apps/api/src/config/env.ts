/**
 * Environment configuration.
 *
 * Fail-fast validation (OWASP A05:2021 - Security Misconfiguration). In
 * production the process refuses to boot without explicit cryptographic
 * material; in development it derives ephemeral keys and screams about it so
 * nobody accidentally ships dev keys.
 */

import { randomBytes, scryptSync } from 'node:crypto';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';
import { z } from 'zod';

const here = fileURLToPath(new URL('.', import.meta.url));
export const API_ROOT = resolve(here, '..', '..');

const envFile = resolve(API_ROOT, '.env');
if (existsSync(envFile)) dotenv.config({ path: envFile, override: false });

const NODE_ENV = (process.env['NODE_ENV'] ?? 'development') as
  | 'development'
  | 'test'
  | 'production';

const isProd = NODE_ENV === 'production';

/**
 * Deterministic-but-unique ephemeral key. Derived from process entropy so a
 * restart invalidates old ciphertexts - acceptable in dev, never in prod.
 */
function ephemeralKey(label: string): string {
  return scryptSync(randomBytes(32), label, 32).toString('base64url');
}

function requireKey(name: string, ephemeralLabel: string): string {
  const raw = process.env[name]?.trim();
  if (raw && raw.length >= 32) return raw;
  if (isProd) {
    throw new Error(
      `[FATAL] ${name} is missing or shorter than 32 characters. ` +
        `Generate one with: npm run keygen --workspace @prismforge/api`,
    );
  }
  const generated = ephemeralKey(ephemeralLabel);
  process.emitWarning(
    `${name} is unset - generated an EPHEMERAL development key. ` +
      `Data will not decrypt across restarts and this MUST NOT happen in production.`,
    'PrismForgeConfigWarning',
  );
  return generated;
}

const bool = (def: boolean) =>
  z
    .string()
    .optional()
    .transform((v) => (v === undefined || v === '' ? def : v === 'true' || v === '1'));

const int = (def: number, min: number, max: number) =>
  z
    .string()
    .optional()
    .transform((v) => (v === undefined || v === '' ? def : Number(v)))
    .pipe(z.number().int().min(min).max(max));

const csv = z
  .string()
  .optional()
  .transform((v) =>
    (v ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
  );

const schema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: int(4000, 1, 65535),
    HOST: z.string().default('127.0.0.1'),
    SHUTDOWN_TIMEOUT_MS: int(10_000, 1_000, 120_000),
    TRUST_PROXY_HOPS: int(0, 0, 10),
    LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
    EXPOSE_STACK_TRACES: bool(false),

    ACCESS_TOKEN_TTL_SECONDS: int(900, 60, 86_400),
    REFRESH_TOKEN_TTL_SECONDS: int(28_800, 300, 2_592_000),
    REFRESH_ABSOLUTE_TTL_SECONDS: int(604_800, 900, 31_536_000),
    COOKIE_SECURE: bool(false),
    COOKIE_SAME_SITE: z.enum(['lax', 'strict', 'none']).default('lax'),

    CORS_ORIGINS: csv,

    RATE_LIMIT_WINDOW_MS: int(60_000, 1_000, 3_600_000),
    RATE_LIMIT_MAX: int(300, 1, 100_000),
    AUTH_RATE_LIMIT_MAX: int(10, 1, 1_000),
    REPORT_RATE_LIMIT_MAX: int(20, 1, 1_000),

    MAX_FAILED_LOGINS: int(5, 1, 100),
    LOCKOUT_MINUTES: int(15, 1, 10_080),

    DATABASE_PATH: z.string().default('./data/prismforge.db'),
    EXPORT_DIR: z.string().default('./data/exports'),
    EXPORT_RETENTION_DAYS: int(30, 1, 3_650),

    AUDIT_LOG_TO_STDOUT: bool(true),
  })
  .superRefine((v, ctx) => {
    if (v.COOKIE_SAME_SITE === 'none' && !v.COOKIE_SECURE) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['COOKIE_SECURE'],
        message: 'SameSite=None requires Secure=true (browsers reject it otherwise)',
      });
    }
    if (v.NODE_ENV === 'production' && v.CORS_ORIGINS.length === 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['CORS_ORIGINS'],
        message: 'CORS_ORIGINS must list explicit origins in production',
      });
    }
    if (v.REFRESH_ABSOLUTE_TTL_SECONDS < v.REFRESH_TOKEN_TTL_SECONDS) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['REFRESH_ABSOLUTE_TTL_SECONDS'],
        message: 'Absolute refresh TTL must be >= sliding refresh TTL',
      });
    }
  });

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  const detail = parsed.error.issues
    .map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`)
    .join('\n');
  throw new Error(`Invalid environment configuration:\n${detail}`);
}

const raw = parsed.data;

const corsOrigins = raw.CORS_ORIGINS.length
  ? raw.CORS_ORIGINS
  : ['http://localhost:5173', 'http://127.0.0.1:5173'];

if (isProd && !raw.COOKIE_SECURE) {
  throw new Error('[FATAL] COOKIE_SECURE must be true in production (OWASP A02:2021).');
}

export const env = {
  nodeEnv: raw.NODE_ENV,
  isProd,
  isDev: raw.NODE_ENV === 'development',
  isTest: raw.NODE_ENV === 'test',
  port: raw.PORT,
  host: raw.HOST,
  shutdownTimeoutMs: raw.SHUTDOWN_TIMEOUT_MS,
  trustProxyHops: raw.TRUST_PROXY_HOPS,
  logLevel: raw.LOG_LEVEL,
  exposeStackTraces: raw.EXPOSE_STACK_TRACES,

  configEncryptionKey: requireKey('CONFIG_ENCRYPTION_KEY', 'config-encryption-dev'),
  auditHmacKey: requireKey('AUDIT_HMAC_KEY', 'audit-hmac-dev'),
  jwtSigningKey: requireKey('JWT_SIGNING_KEY', 'jwt-signing-dev'),

  accessTokenTtlSeconds: raw.ACCESS_TOKEN_TTL_SECONDS,
  refreshTokenTtlSeconds: raw.REFRESH_TOKEN_TTL_SECONDS,
  refreshAbsoluteTtlSeconds: raw.REFRESH_ABSOLUTE_TTL_SECONDS,
  cookieSecure: raw.COOKIE_SECURE,
  cookieSameSite: raw.COOKIE_SAME_SITE,

  corsOrigins,

  rateLimitWindowMs: raw.RATE_LIMIT_WINDOW_MS,
  rateLimitMax: raw.RATE_LIMIT_MAX,
  authRateLimitMax: raw.AUTH_RATE_LIMIT_MAX,
  reportRateLimitMax: raw.REPORT_RATE_LIMIT_MAX,

  maxFailedLogins: raw.MAX_FAILED_LOGINS,
  lockoutMinutes: raw.LOCKOUT_MINUTES,

  databasePath: resolve(API_ROOT, raw.DATABASE_PATH),
  exportDir: resolve(API_ROOT, raw.EXPORT_DIR),
  exportRetentionDays: raw.EXPORT_RETENTION_DAYS,

  auditLogToStdout: raw.AUDIT_LOG_TO_STDOUT,

  /** Public origin of the SPA, used to build absolute share links. */
  publicWebOrigin: corsOrigins[0] ?? 'http://localhost:5173',
} as const;

export type Env = typeof env;
