/**
 * Application error taxonomy.
 *
 * Every error carries a stable machine code. The HTTP layer never leaks stack
 * traces, SQL text or internal identifiers to the client
 * (OWASP A05:2021 - Security Misconfiguration).
 */

export type ErrorCode =
  // 400
  | 'BAD_REQUEST'
  | 'VALIDATION_FAILED'
  | 'UNSUPPORTED_MEDIA_TYPE'
  | 'PAYLOAD_TOO_LARGE'
  // 401
  | 'UNAUTHENTICATED'
  | 'INVALID_CREDENTIALS'
  | 'TOKEN_EXPIRED'
  | 'TOKEN_INVALID'
  | 'MFA_REQUIRED'
  | 'MFA_INVALID'
  // 403
  | 'FORBIDDEN'
  | 'CSRF_FAILED'
  | 'ACCOUNT_DISABLED'
  | 'ACCOUNT_LOCKED'
  // 404
  | 'NOT_FOUND'
  // 409
  | 'CONFLICT'
  | 'VERSION_CONFLICT'
  | 'TOKEN_REUSE'
  // 415 / 422
  | 'UNSUPPORTED_GEOMETRY'
  // 429
  | 'RATE_LIMITED'
  // 500
  | 'INTERNAL_ERROR'
  | 'INTEGRITY_FAILURE';

const STATUS_BY_CODE: Record<ErrorCode, number> = {
  BAD_REQUEST: 400,
  VALIDATION_FAILED: 422,
  UNSUPPORTED_MEDIA_TYPE: 415,
  PAYLOAD_TOO_LARGE: 413,

  UNAUTHENTICATED: 401,
  INVALID_CREDENTIALS: 401,
  TOKEN_EXPIRED: 401,
  TOKEN_INVALID: 401,
  MFA_REQUIRED: 401,
  MFA_INVALID: 401,

  FORBIDDEN: 403,
  CSRF_FAILED: 403,
  ACCOUNT_DISABLED: 403,
  ACCOUNT_LOCKED: 423,

  NOT_FOUND: 404,
  CONFLICT: 409,
  VERSION_CONFLICT: 409,
  TOKEN_REUSE: 409,

  UNSUPPORTED_GEOMETRY: 422,
  RATE_LIMITED: 429,

  INTERNAL_ERROR: 500,
  INTEGRITY_FAILURE: 500,
};

export class AppError extends Error {
  readonly code: ErrorCode;
  readonly status: number;
  readonly details: unknown;
  readonly expose: boolean;
  /** Set for auth failures that must be recorded in the audit trail. */
  readonly audit: boolean;

  constructor(
    code: ErrorCode,
    message: string,
    options: { details?: unknown; expose?: boolean; audit?: boolean; cause?: unknown } = {},
  ) {
    super(message, options.cause ? { cause: options.cause } : undefined);
    this.name = 'AppError';
    this.code = code;
    this.status = STATUS_BY_CODE[code];
    this.details = options.details;
    this.expose = options.expose ?? this.status < 500;
    this.audit = options.audit ?? this.status >= 400;
    Error.captureStackTrace?.(this, AppError);
  }

  static badRequest(message: string, details?: unknown): AppError {
    return new AppError('BAD_REQUEST', message, { details });
  }

  static validation(message = 'Request validation failed', details?: unknown): AppError {
    return new AppError('VALIDATION_FAILED', message, { details });
  }

  static unauthenticated(message = 'Authentication required'): AppError {
    return new AppError('UNAUTHENTICATED', message);
  }

  static forbidden(message = 'Insufficient privileges', details?: unknown): AppError {
    return new AppError('FORBIDDEN', message, { details });
  }

  static notFound(what = 'Resource'): AppError {
    return new AppError('NOT_FOUND', `${what} not found`);
  }

  static conflict(message: string, details?: unknown): AppError {
    return new AppError('CONFLICT', message, { details });
  }

  static internal(message = 'An unexpected error occurred', cause?: unknown): AppError {
    return new AppError('INTERNAL_ERROR', message, { cause, expose: false, audit: false });
  }
}

export function isAppError(err: unknown): err is AppError {
  return err instanceof AppError;
}

export function errorStatus(err: unknown): number {
  return isAppError(err) ? err.status : 500;
}
