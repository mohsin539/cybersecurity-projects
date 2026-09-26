/**
 * Express request context.
 *
 * Every request carries a correlation id which is echoed to the client, written
 * to every log line, and embedded in every audit record. That single thread is
 * what makes an incident reconstructable (ISO/IEC 27001 A.8.15, A.8.16).
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { randomUUID } from 'node:crypto';
import type { Role } from '@prismforge/shared';
import { ipFingerprint } from '../utils/crypto.js';

export interface Actor {
  id: string;
  email: string;
  role: Role;
  displayName: string;
  sessionId: string | null;
  /** True when the actor was resolved from a verified access token. */
  authenticated: boolean;
  mfaEnrolled: boolean;
}

export interface RequestContext {
  correlationId: string;
  startedAt: number;
  ip: string;
  ipFingerprint: string;
  userAgent: string | null;
  actor: Actor | null;
  /** Set by the audit middleware; the route's outcome is stamped onto it. */
  auditAction?: string;
  auditResourceType?: string;
  auditResourceId?: string;
  auditMessage?: string;
  auditSeverity?: 'INFO' | 'NOTICE' | 'WARNING' | 'CRITICAL';
  auditDetails?: Record<string, unknown>;
  /** Suppresses automatic auditing (the route logs explicitly instead). */
  auditHandled?: boolean;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      ctx: RequestContext;
    }
  }
}

const SAFE_ID = /^[A-Za-z0-9._:-]{1,64}$/;

/** Honours a client-supplied correlation id only if it looks sane. */
function pickCorrelationId(req: Request): string {
  const supplied = req.header('x-correlation-id') ?? req.header('x-request-id');
  if (supplied && SAFE_ID.test(supplied)) return supplied;
  return randomUUID();
}

export function clientIp(req: Request): string {
  return req.ip ?? req.socket.remoteAddress ?? '0.0.0.0';
}

export const contextMiddleware: RequestHandler = (req: Request, _res: Response, next: NextFunction) => {
  const ip = clientIp(req);
  req.ctx = {
    correlationId: pickCorrelationId(req),
    startedAt: Date.now(),
    ip,
    ipFingerprint: ipFingerprint(ip),
    userAgent: (req.header('user-agent') ?? '').slice(0, 400) || null,
    actor: null,
  };
  next();
};

export const noStore: RequestHandler = (_req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  next();
};

/** Wraps an async handler so rejections reach the error middleware. */
export function asyncHandler<T extends RequestHandler>(fn: T): RequestHandler {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

export function actorOf(req: Request): Actor {
  if (!req.ctx.actor) throw new Error('actorOf() called on an unauthenticated route');
  return req.ctx.actor;
}
