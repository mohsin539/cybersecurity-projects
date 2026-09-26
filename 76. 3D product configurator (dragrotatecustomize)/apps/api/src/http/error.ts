/**
 * Terminal error handling.
 *
 * Guarantees (OWASP A05:2021, A09:2021):
 *   - the client receives a stable machine code, never an internal detail
 *   - the full error is written to the log with its correlation id
 *   - unhandled errors return a generic 500 with no stack trace
 */

import type { ErrorRequestHandler, RequestHandler } from 'express';
import { ZodError } from 'zod';
import { env } from '../config/env.js';
import { logger } from '../config/logger.js';
import { AppError, isAppError } from '../utils/errors.js';

export const notFoundHandler: RequestHandler = (req, _res, next) => {
  next(new AppError('NOT_FOUND', `No route matches ${req.method} ${req.path}`));
};

export const errorHandler: ErrorRequestHandler = (err, req, res, _next) => {
  const correlationId = req.ctx?.correlationId ?? 'unknown';

  let appError: AppError;
  if (isAppError(err)) {
    appError = err;
  } else if (err instanceof ZodError) {
    appError = new AppError('VALIDATION_FAILED', 'One or more fields are invalid', {
      details: { issues: err.issues.slice(0, 50).map((i) => ({ path: i.path.join('.'), message: i.message })) },
    });
  } else if (isBodyTooLarge(err)) {
    appError = new AppError('PAYLOAD_TOO_LARGE', 'Request body exceeds the permitted size');
  } else if (isSyntaxError(err)) {
    appError = new AppError('BAD_REQUEST', 'Request body is not valid JSON');
  } else {
    appError = new AppError('INTERNAL_ERROR', 'An unexpected error occurred', { cause: err });
  }

  const level = appError.status >= 500 ? 'error' : appError.status >= 400 ? 'warn' : 'info';
  logger[level](
    {
      err: appError.status >= 500 ? (err instanceof Error ? err : new Error(String(err))) : undefined,
      code: appError.code,
      status: appError.status,
      correlationId,
      method: req.method,
      path: req.path,
      actor: req.ctx?.actor?.id ?? null,
      detail: appError.status < 500 ? appError.message : undefined,
    },
    `${appError.code}: ${appError.message}`,
  );

  if (res.headersSent) return;

  res.status(appError.status);
  res.setHeader('X-Correlation-Id', correlationId);
  res.setHeader('Cache-Control', 'no-store');

  const body: {
    error: {
      code: string;
      message: string;
      correlationId: string;
      details?: unknown;
    };
  } = {
    error: {
      code: appError.code,
      message: appError.expose ? appError.message : 'An unexpected error occurred',
      correlationId,
    },
  };

  if (appError.expose && appError.details !== undefined) body.error.details = appError.details;
  if (env.exposeStackTraces && !isAppError(err) && err instanceof Error) {
    body.error.details = { ...(body.error.details as object), stack: err.stack?.split('\n').slice(0, 8) };
  }

  res.json(body);
};

function isBodyTooLarge(err: unknown): boolean {
  return typeof err === 'object' && err !== null && (err as { type?: string }).type === 'entity.too.large';
}

function isSyntaxError(err: unknown): boolean {
  return (
    err instanceof SyntaxError &&
    'body' in err &&
    typeof (err as { status?: unknown }).status === 'number'
  );
}
