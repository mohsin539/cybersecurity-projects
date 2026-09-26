/**
 * Database operations CLI.
 *
 *   npm run db:migrate      apply pending migrations
 *   npm run db:seed         insert reference data + demo accounts
 *   npm run db:reset        drop, recreate, migrate, seed (DESTRUCTIVE)
 *   npm run audit:verify    walk and verify the audit hash chain
 *   npm run audit:report    write a compliance extract to disk
 *   npm run keygen          generate fresh secrets for the .env file
 */

import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { API_ROOT, env } from '../config/env.js';
import { logger } from '../config/logger.js';
import { closeDb, run } from './driver.js';
import { migrate } from './migrations.js';
import { seed } from './seed.js';
import { auditStats, verifyChain } from '../modules/audit/audit.service.js';

const [, , command, ...rest] = process.argv;

function hr(title: string): void {
  // eslint-disable-next-line no-console
  console.log(`\n\x1b[35m━━ ${title} ${'━'.repeat(Math.max(0, 58 - title.length))}\x1b[0m\n`);
}

async function main(): Promise<number> {
  switch (command) {
    case 'migrate': {
      hr('MIGRATE');
      const applied = migrate();
      // eslint-disable-next-line no-console
      console.log(applied === 0 ? '  Already up to date.' : `  Applied ${applied} migration(s).`);
      return 0;
    }

    case 'seed': {
      hr('SEED');
      migrate();
      await seed();
      return 0;
    }

    case 'reset': {
      hr('RESET (DESTRUCTIVE)');
      if (env.isProd && process.env['ALLOW_PRODUCTION_SEED'] !== 'true') {
        throw new Error('Refusing to reset a production database.');
      }
      closeDb();
      for (const suffix of ['', '-wal', '-shm']) {
        const p = `${env.databasePath}${suffix}`;
        if (existsSync(p)) {
          rmSync(p, { force: true });
          // eslint-disable-next-line no-console
          console.log(`  removed ${p}`);
        }
      }
      mkdirSync(resolve(API_ROOT, 'data'), { recursive: true });
      migrate();
      await seed();
      return 0;
    }

    case 'verify': {
      hr('AUDIT CHAIN VERIFICATION');
      migrate();
      const result = verifyChain({ fromSeq: 0 });
      const stats = auditStats(30);

      // eslint-disable-next-line no-console
      console.log(`  entries verified : ${result.verifiedEntries}`);
      // eslint-disable-next-line no-console
      console.log(`  head seq         : ${stats.chain.headSeq}`);
      // eslint-disable-next-line no-console
      console.log(`  head hash        : ${stats.chain.headHash}`);
      // eslint-disable-next-line no-console
      console.log(`  sequence gaps    : ${result.sequenceGaps.length}`);
      // eslint-disable-next-line no-console
      console.log(`  checkpoint       : ${result.checkpoint ? (result.checkpoint.ok ? 'VALID' : 'INVALID') : 'none'}`);
      // eslint-disable-next-line no-console
      console.log(`  duration         : ${result.durationMs} ms`);

      if (result.errors.length) {
        // eslint-disable-next-line no-console
        console.log('\n  \x1b[31mDISCREPANCIES\x1b[0m');
        for (const e of result.errors) {
          // eslint-disable-next-line no-console
          console.log(`   seq ${e.seq}: ${e.reason}`);
          if (e.expected) // eslint-disable-next-line no-console
            console.log(`     expected: ${e.expected}`);
          if (e.actual) // eslint-disable-next-line no-console
            console.log(`     observed: ${e.actual}`);
        }
        // eslint-disable-next-line no-console
        console.log('\n  \x1b[31mRESULT: FAIL - the audit trail has been modified or truncated.\x1b[0m\n');
        return 2;
      }

      // eslint-disable-next-line no-console
      console.log('\n  \x1b[32mRESULT: PASS - the audit trail is intact.\x1b[0m\n');
      return 0;
    }

    case 'report': {
      hr('AUDIT EXTRACT');
      migrate();
      const days = Number(rest[0] ?? 30);
      const format = (rest[1] ?? 'json') as 'json' | 'csv';
      const stats = auditStats(days);
      mkdirSync(env.exportDir, { recursive: true });
      const stamp = new Date().toISOString().slice(0, 10);

      if (format === 'csv') {
        const rows = [
          'date,events,failures,denials',
          ...stats.daily.map((d) => `${d.date},${d.count},${d.failures},${d.denied}`),
        ];
        const file = resolve(env.exportDir, `audit-summary-${stamp}.csv`);
        writeFileSync(file, rows.join('\n'), 'utf8');
        // eslint-disable-next-line no-console
        console.log(`  Wrote ${file}`);
      } else {
        const file = resolve(env.exportDir, `audit-summary-${stamp}.json`);
        writeFileSync(file, JSON.stringify(stats, null, 2), 'utf8');
        // eslint-disable-next-line no-console
        console.log(`  Wrote ${file}`);
      }
      // eslint-disable-next-line no-console
      console.log(`  Window: ${days} days, ${stats.total} events\n`);
      return 0;
    }

    case 'keygen': {
      hr('KEY GENERATION');
      const keys = {
        CONFIG_ENCRYPTION_KEY: randomBytes(48).toString('base64url'),
        AUDIT_HMAC_KEY: randomBytes(48).toString('base64url'),
        JWT_SIGNING_KEY: randomBytes(48).toString('base64url'),
      };
      // eslint-disable-next-line no-console
      console.log('  Add these to apps/api/.env (keep them secret and version-controlled OUT):\n');
      for (const [k, v] of Object.entries(keys)) {
        // eslint-disable-next-line no-console
        console.log(`  ${k}=${v}`);
      }
      // eslint-disable-next-line no-console
      console.log('\n  NOTE: rotating CONFIG_ENCRYPTION_KEY makes existing sealed rows unreadable.');
      // eslint-disable-next-line no-console
      console.log('        rotating AUDIT_HMAC_KEY invalidates historical chain verification.');
      // eslint-disable-next-line no-console
      console.log('        both rotations must be recorded in the change log.\n');
      return 0;
    }

    case 'stats': {
      migrate();
      const stats = auditStats(30);
      // eslint-disable-next-line no-console
      console.log(JSON.stringify(stats, null, 2));
      return 0;
    }

    case 'vacuum': {
      migrate();
      run('VACUUM');
      // eslint-disable-next-line no-console
      console.log('  Database compacted.');
      return 0;
    }

    default: {
      // eslint-disable-next-line no-console
      console.log('Usage: tsx src/db/cli.ts <migrate|seed|reset|verify|report|keygen|stats|vacuum>');
      return 1;
    }
  }
}

main()
  .then((code) => {
    closeDb();
    process.exit(code);
  })
  .catch((err: unknown) => {
    logger.error({ err }, 'cli command failed');
    // eslint-disable-next-line no-console
    console.error('\n  \x1b[31mERROR\x1b[0m:', err instanceof Error ? err.message : err);
    closeDb();
    process.exit(1);
  });
