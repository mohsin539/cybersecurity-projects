/**
 * Transport & browser-facing security controls.
 *
 * Covers:
 *   - OWASP A02:2021 Cryptographic Failures      -> HSTS, secure cookies
 *   - OWASP A05:2021 Security Misconfiguration    -> strict CSP, no sniff, no referrer leak
 *   - OWASP A07:2021 Identification & Auth Failures -> no caching of auth responses
 *   - OWASP A01:2021 Broken Access Control       -> CORS allow-list, not a wildcard
 *   - ISO/IEC 27001 A.8.20 / A.8.21 network security
 */

import { randomBytes } from 'node:crypto';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import cors, { type CorsOptions } from 'cors';
import express, { type Request, type RequestHandler, type Response } from 'express';
import helmet, { type HelmetOptions } from 'helmet';
import { env } from '../config/env.js';
import { AppError } from '../utils/errors.js';

// ---------------------------------------------------------------------------
// Security headers
// ---------------------------------------------------------------------------

/**
 * API surface CSP: this origin only ever returns JSON, so the policy is
 * maximally restrictive. `default-src 'none'` means an injected <script> or
 * <img> tag pointing at the API cannot load anything.
 */
export function apiContentSecurityPolicy(): HelmetOptions['contentSecurityPolicy'] {
  return {
    useDefaults: false,
    directives: {
      'default-src': ["'none'"],
      'base-uri': ["'none'"],
      'form-action': ["'none'"],
      'frame-ancestors': ["'none'"],
      sandbox: [],
      ...(env.isProd ? { 'upgrade-insecure-requests': [] as string[] } : {}),
    },
  };
}

export const securityHeaders = (): RequestHandler[] => [
  helmet({
    contentSecurityPolicy: apiContentSecurityPolicy(),
    crossOriginEmbedderPolicy: false, // the SPA is cross-origin by design
    crossOriginOpenerPolicy: { policy: 'same-origin' },
    crossOriginResourcePolicy: { policy: 'same-site' },
    referrerPolicy: { policy: 'no-referrer' },
    // HSTS is only meaningful over TLS; enabling it on plain HTTP in dev would
    // pin localhost to HTTPS and break the dev server.
    hsts: env.isProd
      ? { maxAge: 63_072_000, includeSubDomains: true, preload: false }
      : false,
    frameguard: { action: 'deny' },
    noSniff: true,
    xssFilter: true,
    hidePoweredBy: true,
    dnsPrefetchControl: { allow: false },
    ieNoOpen: true,
    permittedCrossDomainPolicies: { permittedPolicies: 'none' },
    originAgentCluster: true,
  }),
];

// ---------------------------------------------------------------------------
// CORS - strict allow-list, never a reflected wildcard
// ---------------------------------------------------------------------------

export const corsPolicy: CorsOptions = {
  origin(origin, callback) {
    // Same-origin / curl / server-to-server requests carry no Origin header.
    if (!origin) return callback(null, true);
    if (env.corsOrigins.includes(origin)) return callback(null, true);
    return callback(new AppError('FORBIDDEN', 'Origin is not permitted'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Correlation-Id', 'If-Match'],
  exposedHeaders: ['X-Correlation-Id', 'X-RateLimit-Remaining', 'X-RateLimit-Reset', 'Content-Disposition'],
  maxAge: 600,
  optionsSuccessStatus: 204,
};

export const corsMiddleware: RequestHandler = cors(corsPolicy);

// ---------------------------------------------------------------------------
// Body parsing with hard limits (OWASP A04:2021 - Insecure Design)
// ---------------------------------------------------------------------------

export const bodyParsers: RequestHandler[] = [
  // 1 MiB is generous for a configuration payload but caps memory per request.
  express.json({ limit: '1mb', strict: true, type: ['application/json', 'application/*+json'] }),
  express.urlencoded({ extended: false, limit: '64kb', parameterLimit: 100 }),
  cookieParser(),
  compression({
    threshold: 1024,
    filter: (req, res) => {
      const type = String(res.getHeader('Content-Type') ?? '');
      // Already-compressed payloads (PNG snapshots, xlsx, pdf) - skip.
      if (/image\//.test(type) || /zip|octet-stream|pdf|gzip/.test(type)) return false;
      return compression.filter(req, res);
    },
  }),
];

// ---------------------------------------------------------------------------
// Rate limiting (ISO/IEC 27001 A.8.6 capacity management; anti-automation)
//
// Implemented in-process rather than via a third-party middleware: the whole
// limiter is ~40 lines, which keeps the dependency surface small (OWASP A06)
// and lets the keys be composed exactly as required (IP, IP+account).
// Swap for a shared store (Redis) before running multiple replicas.
// ---------------------------------------------------------------------------

interface Bucket {
  count: number;
  resetAt: number;
}

function clientKey(req: Request): string {
  // req.ip honours the configured `trust proxy` hops, so it cannot be spoofed
  // unless the deployment misconfigures the proxy trust.
  return req.ip ?? req.socket.remoteAddress ?? 'unknown';
}

function limiter(opts: {
  windowMs: number;
  max: number;
  name: string;
  message: string;
  perAccount?: boolean;
}): RequestHandler {
  const store = new Map<string, Bucket>();
  const sweep = setInterval(() => {
    const now = Date.now();
    for (const [k, v] of store) if (v.resetAt <= now) store.delete(k);
  }, opts.windowMs);
  sweep.unref();

  return (req: Request, res: Response, next) => {
    const key = opts.perAccount
      ? `${clientKey(req)}|${req.ctx?.actor?.id ?? 'anon'}`
      : clientKey(req);
    const now = Date.now();
    const existing = store.get(key);
    const bucket: Bucket = existing && existing.resetAt > now ? existing : { count: 0, resetAt: now + opts.windowMs };
    bucket.count += 1;
    store.set(key, bucket);

    const remaining = Math.max(0, opts.max - bucket.count);
    res.setHeader('X-RateLimit-Limit', String(opts.max));
    res.setHeader('X-RateLimit-Remaining', String(remaining));
    res.setHeader('X-RateLimit-Reset', String(Math.ceil(bucket.resetAt / 1000)));

    if (bucket.count > opts.max) {
      const retryAfter = Math.ceil((bucket.resetAt - now) / 1000);
      res.setHeader('Retry-After', String(retryAfter));
      return next(
        new AppError('RATE_LIMITED', opts.message, {
          details: {
            limit: opts.max,
            windowMs: opts.windowMs,
            retryAfterSeconds: retryAfter,
            scope: opts.name,
          },
        }),
      );
    }
    return next();
  };
}

/** Broad protection for the whole surface. */
export const globalLimiter = (): RequestHandler =>
  limiter({
    windowMs: env.rateLimitWindowMs,
    max: env.rateLimitMax,
    name: 'global',
    message: 'Too many requests. Slow down.',
  });

/** Tight limiter on credential endpoints - the primary brute-force control. */
export const authLimiter = (): RequestHandler =>
  limiter({
    windowMs: 15 * 60_000,
    max: env.authRateLimitMax,
    name: 'auth-ip',
    message: 'Too many authentication attempts. Try again later.',
  });

/** Per-account limiter layered on top of the per-IP limiter. */
export const authAccountLimiter = (): RequestHandler =>
  limiter({
    windowMs: 15 * 60_000,
    max: Math.max(3, env.authRateLimitMax),
    name: 'auth-account',
    perAccount: true,
    message: 'Too many attempts for this account.',
  });

/** Reports are CPU/IO heavy; keep them bounded. */
export const reportLimiter = (): RequestHandler =>
  limiter({
    windowMs: 60_000,
    max: env.reportRateLimitMax,
    name: 'report',
    message: 'Report generation rate limit exceeded. Wait before requesting another.',
  });

// ---------------------------------------------------------------------------
// CSRF (OWASP A01:2021)
// ---------------------------------------------------------------------------
//
// Strategy: the access token lives in memory only and is sent as a Bearer
// header, which a cross-site form cannot forge. The refresh token lives in an
// httpOnly SameSite cookie, so the cookie-authenticated routes are the only
// CSRF surface. Those routes are protected by TWO independent controls:
//
//   1. Origin/Referer must be in the CORS allow-list (browsers set it always).
//   2. Double-submit token: a non-httpOnly `pf_csrf` cookie must be echoed in
//      the `X-CSRF-Token` header. A cross-origin attacker can cause the cookie
//      to be sent but cannot read it, so cannot populate the header.

export const CSRF_COOKIE = 'pf_csrf';
export const CSRF_HEADER = 'x-csrf-token';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/** Routes that are authenticated by cookie rather than by Bearer token. */
const COOKIE_AUTH_PATHS = [/^\/api\/v1\/auth\/refresh$/, /^\/api\/v1\/auth\/logout$/, /^\/api\/v1\/csrf$/];

export const issueCsrfToken: RequestHandler = (req, res, next) => {
  const existing = req.cookies?.[CSRF_COOKIE] as string | undefined;
  const token = existing && /^[A-Za-z0-9_-]{32,128}$/.test(existing) ? existing : randomBytes(32).toString('base64url');
  if (!existing) {
    res.cookie(CSRF_COOKIE, token, {
      httpOnly: false, // must be readable by the SPA to echo it back
      secure: env.cookieSecure,
      sameSite: env.cookieSameSite,
      path: '/',
      maxAge: 8 * 3600_000,
    });
  }
  res.setHeader('X-CSRF-Token', token);
  next();
};

export const csrfProtection: RequestHandler = (req, _res, next) => {
  if (SAFE_METHODS.has(req.method)) return next();

  const path = req.path;
  const cookieAuthenticated = COOKIE_AUTH_PATHS.some((re) => re.test(path));
  const hasBearer = Boolean(req.header('authorization'));

  // 1. Origin gate applies to every state-changing request.
  const origin = req.header('origin');
  if (origin && !env.corsOrigins.includes(origin)) {
    return next(new AppError('CSRF_FAILED', 'Cross-origin request rejected'));
  }
  if (!origin) {
    const referer = req.header('referer');
    if (referer) {
      try {
        if (!env.corsOrigins.includes(new URL(referer).origin)) {
          return next(new AppError('CSRF_FAILED', 'Referer origin rejected'));
        }
      } catch {
        return next(new AppError('CSRF_FAILED', 'Malformed Referer header'));
      }
    }
  }

  // 2. Double-submit token, required whenever the request rides on cookies.
  if (cookieAuthenticated || !hasBearer) {
    const cookie = req.cookies?.[CSRF_COOKIE] as string | undefined;
    const header = req.header(CSRF_HEADER);
    if (!cookie || !header || cookie.length !== header.length) {
      return next(new AppError('CSRF_FAILED', 'CSRF token missing or malformed'));
    }
    let diff = 0;
    for (let i = 0; i < cookie.length; i++) diff |= cookie.charCodeAt(i) ^ header.charCodeAt(i);
    if (diff !== 0) return next(new AppError('CSRF_FAILED', 'CSRF token mismatch'));
  }

  return next();
};
