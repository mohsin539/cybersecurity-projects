/**
 * Zod request validation.
 *
 * Validation happens *before* any business logic, so a malformed or hostile
 * payload can never reach the data layer (OWASP A03:2021 injection,
 * A08:2021 data integrity). Rejected payloads are reported with the offending
 * field paths so the client gets actionable feedback.
 */

import type { RequestHandler } from 'express';
import { ZodError, type ZodTypeAny, type z } from 'zod';
import { AppError } from '../utils/errors.js';

export interface FieldIssue {
  path: string;
  message: string;
  code: string;
}

function toFieldIssues(err: ZodError): FieldIssue[] {
  return err.issues.slice(0, 50).map((i) => ({
    path: i.path.join('.') || '(root)',
    message: i.message,
    code: i.code,
  }));
}

/**
 * @param source  'body' | 'query' | 'params'
 *
 * The parsed (and transformed - note `.trim()`, `.toLowerCase()`) value
 * REPLACES the raw one, so downstream handlers always see validated data.
 */
export function validate<S extends ZodTypeAny>(
  schema: S,
  source: 'body' | 'query' | 'params' = 'body',
): RequestHandler {
  return (req, _res, next) => {
    const result = schema.safeParse(req[source]);
    if (!result.success) {
      return next(
        new AppError('VALIDATION_FAILED', 'One or more fields are invalid', {
          details: { source, issues: toFieldIssues(result.error) },
        }),
      );
    }
    if (source === 'query') {
      // req.query is a getter in Express 5; assign defensively.
      Object.defineProperty(req, 'query', { value: result.data, writable: true, configurable: true });
    } else {
      req[source] = result.data as never;
    }
    return next();
  };
}

/** Convenience: validate several sources in one call. */
export function validateAll(handlers: RequestHandler[]): RequestHandler[] {
  return handlers;
}

export type Infer<T extends ZodTypeAny> = z.infer<T>;
