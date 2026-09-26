/**
 * Process entry point.
 *
 * Boot sequence:
 *   1. apply migrations (so a fresh checkout works with one command)
 *   2. bind the listener on a loopback address by default
 *   3. install graceful shutdown: stop accepting, drain, checkpoint the audit
 *      chain, close the database
 *   4. arm a last-resort watchdog so a hung request cannot hold the process
 */

import { createServer, type Server } from 'node:http';
import { createApp, API_PREFIX } from './app.js';
import { env } from './config/env.js';
import { logger } from './config/logger.js';
import { closeDb } from './db/driver.js';
import { migrate } from './db/migrations.js';
import { createCheckpoint, flushOutbox, record } from './modules/audit/audit.service.js';
import { pruneSessions } from './modules/auth/token.service.js';

const BOOTED_AT = new Date().toISOString();

async function bootstrap(): Promise<Server> {
  migrate();

  const app = createApp();
  const server = createServer(app);

  // Slow-loris / resource-starvation protection.
  server.headersTimeout = 20_000;
  server.requestTimeout = 30_000;
  server.keepAliveTimeout = 10_000;
  server.maxHeadersCount = 96;
  server.maxRequestsPerSocket = 500;

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(env.port, env.host, () => {
      server.removeListener('error', reject);
      resolve();
    });
  });

  record({
    action: 'system.startup',
    outcome: 'SUCCESS',
    severity: 'NOTICE',
    resourceType: 'service',
    message: `PrismForge API listening on ${env.host}:${env.port}`,
    details: { environment: env.nodeEnv, node: process.version, bootedAt: BOOTED_AT },
  });

  // A checkpoint at boot gives the integrity verifier a fresh reference point.
  createCheckpoint(null);

  logger.info(
    {
      url: `http://${env.host}:${env.port}`,
      api: `${API_PREFIX}`,
      environment: env.nodeEnv,
      pid: process.pid,
      corsOrigins: env.corsOrigins,
      hsts: env.isProd,
    },
    'PrismForge API ready',
  );

  // eslint-disable-next-line no-console
  console.log(
    [
      '',
      '  \x1b[95m╔══════════════════════════════════════════════════════════════╗\x1b[0m',
      '  \x1b[95m║\x1b[0m  \x1b[1mPrismForge API\x1b[0m - secure 3D product configurator        \x1b[95m║\x1b[0m',
      '  \x1b[95m╚══════════════════════════════════════════════════════════════╝\x1b[0m',
      `     API        http://${env.host}:${env.port}${API_PREFIX}`,
      `     Health     http://${env.host}:${env.port}${API_PREFIX}/health/ready`,
      `     Env        ${env.nodeEnv}`,
      `     Database   ${env.databasePath}`,
      `     CORS       ${env.corsOrigins.join(', ')}`,
      '',
    ].join('\n'),
  );

  return server;
}

let server: Server | null = null;
let shuttingDown = false;

async function shutdown(signal: string): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info({ signal }, 'shutdown initiated');

  const force = setTimeout(() => {
    logger.error('graceful shutdown timed out; forcing exit');
    process.exit(1);
  }, env.shutdownTimeoutMs);
  force.unref();

  try {
    record({
      action: 'system.shutdown',
      outcome: 'SUCCESS',
      severity: 'NOTICE',
      resourceType: 'service',
      message: `Graceful shutdown on ${signal}`,
    });
    const flushed = flushOutbox();
    if (flushed) logger.info({ flushed }, 'audit outbox flushed');
    const pruned = pruneSessions();
    if (pruned) logger.info({ pruned }, 'expired sessions pruned');
    createCheckpoint(null);
  } catch (err) {
    logger.error({ err }, 'error during shutdown bookkeeping');
  }

  if (server) {
    await new Promise<void>((resolve) => server!.close(() => resolve()));
  }
  closeDb();
  clearTimeout(force);
  logger.info('shutdown complete');
  process.exit(0);
}

for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => void shutdown(signal));
}

process.on('unhandledRejection', (reason) => {
  logger.error({ err: reason }, 'unhandled promise rejection');
});
process.on('uncaughtException', (err) => {
  logger.fatal({ err }, 'uncaught exception - terminating');
  void shutdown('uncaughtException');
});

bootstrap()
  .then((s) => {
    server = s;
  })
  .catch((err: unknown) => {
    logger.fatal({ err }, 'failed to start');
    // eslint-disable-next-line no-console
    console.error('\n  \x1b[31mFATAL\x1b[0m PrismForge API could not start.\n');
    closeDb();
    process.exit(1);
  });
