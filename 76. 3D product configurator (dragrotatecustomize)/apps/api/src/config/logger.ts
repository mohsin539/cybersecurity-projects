/**
 * Structured logging with mandatory secret redaction
 * (OWASP A09:2021 - Security Logging and Monitoring Failures;
 *  ISO/IEC 27001 A.8.15 / A.8.16).
 *
 * Every log line is JSON so a SIEM can ingest it directly. The redaction list
 * below is applied to the serialised output, which catches accidental logging
 * of a `password` or `token` key at any nesting depth.
 */

import pino from 'pino';
import { env } from './env.js';

const REDACT_PATHS = [
  'password',
  'newPassword',
  'currentPassword',
  'mfaCode',
  'secret',
  'token',
  'accessToken',
  'refreshToken',
  'authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'deviceId',
  '*.password',
  '*.token',
  '*.refreshToken',
  '*.accessToken',
  '*.mfaCode',
  '*.secret',
  'req.headers.authorization',
  'req.headers.cookie',
  'res.headers["set-cookie"]',
  'config.spec',
  'spec',
  '*.spec',
];

export const logger = pino({
  level: env.logLevel,
  base: {
    service: 'prismforge-api',
    // Pseudo-ID only - never the raw IP, so logs stay useful without being PII.
    instance: process.env['WEBSITE_INSTANCE_ID'] ?? 'local',
  },
  timestamp: pino.stdTimeFunctions.isoTime,
  redact: { paths: REDACT_PATHS, censor: '[REDACTED]' },
  formatters: {
    level: (label) => ({ level: label }),
  },
  serializers: {
    err: pino.stdSerializers.err,
  },
  // Keep the console clean in test runs.
  ...(env.isTest ? { level: 'silent' as const } : {}),
});

export type Logger = typeof logger;

export const childLogger = (bindings: Record<string, unknown>) => logger.child(bindings);
