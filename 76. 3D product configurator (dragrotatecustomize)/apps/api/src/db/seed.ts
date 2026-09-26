/**
 * Database seed.
 *
 * Creates one account per role so the whole authorisation model can be
 * exercised, plus a set of sample configurations that make the audit console
 * and the report generators immediately meaningful.
 *
 * Credentials are printed once, at the terminal, never stored in clear text.
 * In production the seed refuses to run unless `ALLOW_PRODUCTION_SEED=true`.
 */

import {
  DEFAULT_PRODUCT_ID,
  PARTS,
  computePrice,
  type ConfigurationSpec,
  type PartId,
} from '@prismforge/shared';
import { get, insertIgnore, run } from './driver.js';
import { logger } from '../config/logger.js';
import { sealJson, sha256 } from '../utils/crypto.js';
import { env } from '../config/env.js';
import { hashPassword } from '../utils/password.js';
import { newId, newSecret, nowIso } from '../utils/ids.js';
import { createCheckpoint, record } from '../modules/audit/audit.service.js';
import { emailHash } from '../modules/auth/auth.service.js';

const SEED_PASSWORD = 'PrismForge!2024';

interface SeedUser {
  key: string;
  email: string;
  role: 'viewer' | 'configurator' | 'auditor' | 'security_officer' | 'admin';
  displayName: string;
}

const SEED_USERS: SeedUser[] = [
  { key: 'admin', email: 'admin@prismforge.test', role: 'admin', displayName: 'Avery Administrator' },
  { key: 'security', email: 'security@prismforge.test', role: 'security_officer', displayName: 'Sloane Security' },
  { key: 'auditor', email: 'auditor@prismforge.test', role: 'auditor', displayName: 'Quinn Auditor' },
  { key: 'configurator', email: 'designer@prismforge.test', role: 'configurator', displayName: 'Devon Designer' },
  { key: 'viewer', email: 'viewer@prismforge.test', role: 'viewer', displayName: 'Val Viewer' },
];

const PALETTES: Array<{ name: string; colours: Record<PartId, string> }> = [
  { name: 'Solar Flare', colours: { body: '#f97316', grille: '#0f172a', cap: '#fbbf24', ring: '#22d3ee', base: '#1e293b', buttons: '#f8fafc', strap: '#0f172a' } },
  { name: 'Ultraviolet', colours: { body: '#8b5cf6', grille: '#1e1b4b', cap: '#c4b5fd', ring: '#f472b6', base: '#0f172a', buttons: '#f8fafc', strap: '#0f172a' } },
  { name: 'Cyber Lime', colours: { body: '#a3e635', grille: '#14532d', cap: '#ecfccb', ring: '#22d3ee', base: '#052e16', buttons: '#f8fafc', strap: '#0f172a' } },
  { name: 'Carbon Noir', colours: { body: '#1f2937', grille: '#4b5563', cap: '#9ca3af', ring: '#38bdf8', base: '#030712', buttons: '#e5e7eb', strap: '#111827' } },
];

function buildSpec(paletteIndex: number, quantity: number, engraving?: string): ConfigurationSpec {
  const palette = PALETTES[paletteIndex % PALETTES.length]!;
  const parts = {} as ConfigurationSpec['parts'];
  for (const partId of Object.keys(PARTS) as PartId[]) {
    parts[partId] = {
      colour: palette.colours[partId] ?? '#94a3b8',
      finish:
        partId === 'cap'
          ? 'brushedMetal'
          : partId === 'ring'
            ? 'gloss'
            : partId === 'base' || partId === 'strap'
              ? 'rubberized'
              : partId === 'grille'
                ? 'matte'
                : 'satin',
      enabled: true,
    };
  }
  parts.body = { ...parts.body!, finish: paletteIndex % 2 === 0 ? 'anodized' : 'carbonWeave' };

  return {
    productId: DEFAULT_PRODUCT_ID,
    name: `${palette.name} Configuration`,
    dimensions: { height: 220 + paletteIndex * 12, diameter: 96 },
    parts,
    accessories: ['cap', 'ringLight', 'stand'],
    engraving: {
      enabled: Boolean(engraving),
      text: engraving ?? '',
      position: 'front',
      font: 'grotesk',
      colour: '#f8fafc',
    },
    quantity,
    notes: 'Seeded sample configuration for demonstration and reporting.',
    snapshot: '',
  };
}

export async function seed(): Promise<void> {
  if (env.isProd && process.env['ALLOW_PRODUCTION_SEED'] !== 'true') {
    throw new Error('Refusing to seed a production database. Set ALLOW_PRODUCTION_SEED=true to override.');
  }

  const now = nowIso();
  const passwordHash = await hashPassword(SEED_PASSWORD);
  const created: Array<{ email: string; role: string; id: string }> = [];

  for (const u of SEED_USERS) {
    const existing = get<{ id: string }>('SELECT id FROM users WHERE email_hash = ?', emailHash(u.email));
    if (existing) {
      created.push({ email: u.email, role: u.role, id: existing.id });
      continue;
    }
    const id = newId('usr');
    insertIgnore(
      `INSERT INTO users (id, email, email_hash, display_name, role, password_hash, is_active, created_at, updated_at)
       VALUES (?,?,?,?,?,?,?,?,?)`,
      id,
      u.email,
      emailHash(u.email),
      u.displayName,
      u.role,
      passwordHash,
      1,
      now,
      now,
    );
    created.push({ email: u.email, role: u.role, id });
  }

  const admin = created.find((u) => u.role === 'admin')!;
  const designer = created.find((u) => u.role === 'configurator')!;

  let configCount = 0;
  PALETTES.forEach((_, i) => {
    const spec = buildSpec(i, [1, 25, 120, 640][i] ?? 1, i % 2 === 0 ? 'PRISM-' + (1000 + i) : undefined);
    const price = computePrice(spec);
    const publicId = newId('pub');
    const id = newId('cfg');

    const dup = get<{ id: string }>(
      'SELECT id FROM configurations WHERE fingerprint = ? AND owner_id = ?',
      price.fingerprint,
      designer.id,
    );
    if (dup) return;

    run(
      `INSERT INTO configurations
         (id, public_id, version, name, product_id, owner_id, spec_enc, price_enc, fingerprint,
          quantity, total_minor, currency, status, notes, created_at, updated_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      id,
      publicId,
      1,
      spec.name,
      spec.productId,
      designer.id,
      sealJson(spec, `config:spec:${id}`),
      sealJson(price, `config:price:${id}`),
      price.fingerprint,
      spec.quantity,
      price.totalMinor,
      price.currency,
      i === 0 ? 'ordered' : 'quoted',
      spec.notes,
      now,
      now,
    );

    // One read-only share link on the first sample.
    if (i === 0) {
      run(
        `INSERT INTO configuration_shares (id, config_id, token_hash, created_by, expires_at, created_at)
         VALUES (?,?,?,?,?,?)`,
        newId('shr'),
        id,
        sha256(newSecret(24)),
        admin.id,
        new Date(Date.now() + 30 * 86_400_000).toISOString(),
        now,
      );
    }

    record({
      action: 'config.create',
      outcome: 'SUCCESS',
      severity: 'NOTICE',
      actorId: designer.id,
      actorEmail: designer.email,
      actorRole: designer.role,
      resourceType: 'configuration',
      resourceId: id,
      message: `Seeded configuration "${spec.name}"`,
      details: { quantity: spec.quantity, totalMinor: price.totalMinor, seeded: true },
    });
    configCount++;
  });

  record({
    action: 'system.startup',
    outcome: 'SUCCESS',
    severity: 'NOTICE',
    resourceType: 'database',
    message: 'Database seeded with reference data and demonstration accounts',
    details: { users: created.length, configurations: configCount },
  });

  // Anchor the chain with a checkpoint so verification has a reference point.
  createCheckpoint(admin.id);

  logger.info(
    { users: created.length, configurations: configCount },
    'seed complete',
  );

  // eslint-disable-next-line no-console
  console.log(
    [
      '',
      '  ┌───────────────────────────────────────────────────────────────┐',
      '  │  PrismForge reference accounts                                │',
      '  ├───────────────────────────────────────────────────────────────┤',
      ...created.map((u) => `  │  ${u.role.padEnd(18)} ${u.email.padEnd(30)} │`),
      '  │                                                               │',
      `  │  Shared password: ${SEED_PASSWORD.padEnd(47)} │`,
      '  └───────────────────────────────────────────────────────────────┘',
      '',
    ].join('\n'),
  );
}
