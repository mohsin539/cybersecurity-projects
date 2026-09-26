/**
 * Express application assembly.
 *
 * Middleware order is a security control in itself:
 *   1. proxy trust        - only then are client IPs meaningful
 *   2. security headers   - set before anything can respond
 *   3. CORS               - rejects foreign origins early
 *   4. body parsing       - bounded, so a huge body cannot exhaust memory
 *   5. request context    - correlation id + pseudonymised IP
 *   6. rate limiting      - before any expensive work
 *   7. CSRF               - before authentication state changes
 *   8. authentication     - resolves the actor
 *   9. routes
 *  10. audit emission    - wraps the response
 *  11. 404 + error handler
 */

import express, { type Express, type Request, type Response } from 'express';
import { pinoHttp } from 'pino-http';
import { env } from './config/env.js';
import { logger } from './config/logger.js';
import { contextMiddleware } from './http/context.js';
import { authenticate } from './http/auth.js';
import { auditMiddleware } from './http/audit.middleware.js';
import { errorHandler, notFoundHandler } from './http/error.js';
import {
  bodyParsers,
  corsMiddleware,
  csrfProtection,
  globalLimiter,
  issueCsrfToken,
  securityHeaders,
} from './http/security.js';
import { authRouter } from './modules/auth/auth.routes.js';
import { catalogRouter } from './modules/catalog/catalog.routes.js';
import { configurationRouter, shareRouter } from './modules/configurations/configurations.routes.js';
import { reportRouter } from './modules/reports/report.routes.js';
import { auditRouter } from './modules/audit/audit.routes.js';
import { adminRouter } from './modules/admin/admin.routes.js';
import { healthRouter } from './modules/health/health.routes.js';

export const API_PREFIX = '/api/v1';

export function createApp(): Express {
  const app = express();

  // 1. Trust proxy hops only as explicitly configured. Trusting X-Forwarded-For
  //    blindly would let any client spoof its own IP and defeat rate limiting
  //    and audit attribution (OWASP A04:2021).
  app.set('trust proxy', env.trustProxyHops);
  app.set('x-powered-by', false);
  app.set('etag', 'strong');

  // 2. Headers
  app.use(...securityHeaders());

  // 3. CORS
  app.use(corsMiddleware);

  // 4. Parsing
  app.use(...bodyParsers);

  // Request logging with redaction, correlation id propagation.
  app.use(
    pinoHttp({
      logger,
      genReqId: (req) => (req as Request).ctx?.correlationId ?? undefined,
      customLogLevel: (_req, res, err) => {
        if (err || res.statusCode >= 500) return 'error';
        if (res.statusCode >= 400) return 'warn';
        return 'info';
      },
      customSuccessMessage: (req, res) => `${req.method} ${req.url} -> ${res.statusCode}`,
      autoLogging: { ignore: (req) => req.url === '/api/v1/health/live' },
      serializers: {
        req: (req) => ({ method: req.method, url: req.url, correlationId: req.ctx?.correlationId }),
        res: (res) => ({ statusCode: res.statusCode }),
      },
    }),
  );

  // 5. Context
  app.use(contextMiddleware);
  app.use(issueCsrfToken);

  // 6. Rate limiting
  app.use(API_PREFIX, globalLimiter());

  // 7. CSRF
  app.use(API_PREFIX, csrfProtection);

  // 8. Authentication (optional; routes decide whether it is mandatory)
  app.use(authenticate);

  // 9. Routes
  app.use(`${API_PREFIX}/health`, healthRouter());
  app.use(`${API_PREFIX}/auth`, authRouter);
  app.use(`${API_PREFIX}/catalog`, catalogRouter);
  app.use(`${API_PREFIX}/configurations`, configurationRouter);
  app.use(`${API_PREFIX}/share`, shareRouter);
  app.use(`${API_PREFIX}/reports`, reportRouter);
  app.use(`${API_PREFIX}/audit`, auditRouter);
  app.use(`${API_PREFIX}/admin`, adminRouter);

  // 10. Audit emission - must wrap everything that can mutate state.
  app.use(auditMiddleware);

  app.get('/', (_req: Request, res: Response) => {
    res.json({
      data: {
        service: 'prismforge-api',
        version: '1.0.0',
        documentation: '/api/v1/health/verbose',
      },
      correlationId: 'n/a',
    });
  });

  // 11. Terminal handlers
  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
