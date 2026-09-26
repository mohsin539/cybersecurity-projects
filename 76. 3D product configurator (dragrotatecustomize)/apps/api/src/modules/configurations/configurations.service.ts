/**
 * Configuration persistence.
 *
 * Security properties:
 *   - The specification and the authoritative price are sealed with AES-256-GCM
 *     before they touch the disk, with the row id bound in as AAD. A stolen
 *     database file yields ciphertext only (ISO/IEC 27001 A.8.24, A.8.25).
 *   - Prices are always recomputed server-side; the client never supplies one.
 *   - Optimistic concurrency via `version` + `If-Match`-style `expectedVersion`
 *     prevents lost updates (A.8.25 secure development lifecycle / integrity).
 *   - Every read/write is ownership-checked (A.5.15) and audited (A.8.16).
 */

import {
  computePrice,
  configurationSpecSchema,
  getProduct,
  type ConfigurationSpec,
  type PriceBreakdown,
} from '@prismforge/shared';
import { all, get, run, transaction } from '../../db/driver.js';
import { openJson, sealJson, sha256 } from '../../utils/crypto.js';
import { AppError } from '../../utils/errors.js';
import { newId, newSecret, nowIso } from '../../utils/ids.js';
import { canAccessOwned } from '../../http/auth.js';
import type { Actor } from '../../http/context.js';

export interface ConfigurationRow {
  id: string;
  public_id: string;
  version: number;
  name: string;
  product_id: string;
  owner_id: string;
  spec_enc: string;
  price_enc: string;
  fingerprint: string;
  quantity: number;
  total_minor: number;
  currency: string;
  status: 'draft' | 'quoted' | 'ordered' | 'archived';
  notes: string;
  created_at: string;
  updated_at: string;
  deleted_at: string | null;
}

export interface ConfigurationSummary {
  id: string;
  publicId: string;
  version: number;
  name: string;
  productId: string;
  productName: string;
  productSku: string;
  ownerId: string;
  quantity: number;
  totalMinor: number;
  currency: string;
  status: ConfigurationRow['status'];
  notes: string;
  fingerprint: string;
  createdAt: string;
  updatedAt: string;
}

export interface ConfigurationDetail extends ConfigurationSummary {
  spec: ConfigurationSpec;
  price: PriceBreakdown;
  share: { active: boolean; url: string | null; expiresAt: string | null; viewCount: number } | null;
}

function summary(row: ConfigurationRow): ConfigurationSummary {
  const product = getProduct(row.product_id);
  return {
    id: row.id,
    publicId: row.public_id,
    version: Number(row.version),
    name: row.name,
    productId: row.product_id,
    productName: product.name,
    productSku: product.sku,
    ownerId: row.owner_id,
    quantity: Number(row.quantity),
    totalMinor: Number(row.total_minor),
    currency: row.currency,
    status: row.status,
    notes: row.notes,
    fingerprint: row.fingerprint,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function specAad(row: { id: string }): string {
  return `config:spec:${row.id}`;
}

function priceAad(row: { id: string }): string {
  return `config:price:${row.id}`;
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

export interface CreateResult {
  configuration: ConfigurationDetail;
  shareToken: string | null;
  shareUrl: string | null;
}

export function createConfiguration(
  actor: Actor,
  spec: ConfigurationSpec,
  options: { share: boolean; publicWebOrigin: string; notes?: string },
): CreateResult {
  // Re-validate server-side: the client may have been tampered with or simply
  // be an older build. Zod's parse also applies the defaults consistently.
  const validated = configurationSpecSchema.parse(spec);
  const price = computePrice(validated);
  const product = getProduct(validated.productId);

  if (validated.quantity < product.minOrderQty) {
    throw new AppError('UNSUPPORTED_GEOMETRY', `Minimum order quantity for ${product.name} is ${product.minOrderQty}`);
  }

  const id = newId('cfg');
  const publicId = newId('pub');
  const now = nowIso();

  const result = transaction((): CreateResult => {
    run(
      `INSERT INTO configurations
         (id, public_id, version, name, product_id, owner_id, spec_enc, price_enc, fingerprint,
          quantity, total_minor, currency, status, notes, created_at, updated_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      id,
      publicId,
      1,
      validated.name,
      validated.productId,
      actor.id,
      sealJson(validated, `config:spec:${id}`),
      sealJson(price, `config:price:${id}`),
      price.fingerprint,
      validated.quantity,
      price.totalMinor,
      price.currency,
      'draft',
      options.notes ?? validated.notes,
      now,
      now,
    );

    let shareToken: string | null = null;
    let shareUrl: string | null = null;

    if (options.share) {
      shareToken = newSecret(24);
      run(
        `INSERT INTO configuration_shares (id, config_id, token_hash, created_by, expires_at, created_at)
         VALUES (?,?,?,?,?,?)`,
        newId('shr'),
        id,
        sha256(shareToken),
        actor.id,
        new Date(Date.now() + 30 * 86_400_000).toISOString(),
        now,
      );
      shareUrl = `${options.publicWebOrigin.replace(/\/$/, '')}/share/${publicId}?t=${shareToken}`;
    }

    const row = get<ConfigurationRow>('SELECT * FROM configurations WHERE id = ?', id)!;
    return {
      configuration: { ...summary(row), spec: validated, price, share: shareInfo(row.id, shareToken) },
      shareToken,
      shareUrl,
    };
  });

  return result;
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

function shareInfo(configId: string, token: string | null) {
  const row = get<{ revoked_at: string | null; expires_at: string | null; view_count: number; token_hash: string }>(
    'SELECT revoked_at, expires_at, view_count, token_hash FROM configuration_shares WHERE config_id = ? ORDER BY created_at DESC LIMIT 1',
    configId,
  );
  if (!row) return null;
  return {
    active: !row.revoked_at && (!row.expires_at || Date.parse(row.expires_at) > Date.now()),
    url: token ? `/share?t=${token}` : null,
    expiresAt: row.expires_at,
    viewCount: Number(row.view_count),
  };
}

export function readConfiguration(actor: Actor, id: string): ConfigurationDetail {
  const row = get<ConfigurationRow>('SELECT * FROM configurations WHERE id = ? AND deleted_at IS NULL', id);
  if (!row) throw AppError.notFound('Configuration');
  if (!canAccessOwned(actor, row.owner_id)) {
    throw new AppError('FORBIDDEN', 'You do not have access to this configuration');
  }
  return hydrate(row);
}

function hydrate(row: ConfigurationRow): ConfigurationDetail {
  const spec = configurationSpecSchema.parse(openJson<ConfigurationSpec>(row.spec_enc, specAad(row)));
  const price = openJson<PriceBreakdown>(row.price_enc, priceAad(row));
  const share = shareInfo(row.id, null);
  return { ...summary(row), spec, price, share };
}

export function readByPublicId(publicId: string): ConfigurationRow | undefined {
  return get<ConfigurationRow>('SELECT * FROM configurations WHERE public_id = ? AND deleted_at IS NULL', publicId);
}

// ---------------------------------------------------------------------------
// Update (optimistic concurrency)
// ---------------------------------------------------------------------------

export function updateConfiguration(
  actor: Actor,
  id: string,
  patch: { spec?: ConfigurationSpec; name?: string; notes?: string; expectedVersion: number },
): ConfigurationDetail {
  const row = get<ConfigurationRow>('SELECT * FROM configurations WHERE id = ? AND deleted_at IS NULL', id);
  if (!row) throw AppError.notFound('Configuration');
  if (!canAccessOwned(actor, row.owner_id)) {
    throw new AppError('FORBIDDEN', 'You do not have access to this configuration');
  }
  if (Number(row.version) !== patch.expectedVersion) {
    throw new AppError('VERSION_CONFLICT', 'This configuration was modified by someone else. Reload and try again.', {
      details: { expected: patch.expectedVersion, actual: Number(row.version) },
    });
  }

  const spec = patch.spec
    ? configurationSpecSchema.parse(patch.spec)
    : openJson<ConfigurationSpec>(row.spec_enc, specAad(row));
  const price = computePrice(spec);
  const product = getProduct(spec.productId);

  run(
    `UPDATE configurations
        SET version = version + 1, name = ?, product_id = ?, spec_enc = ?, price_enc = ?,
            fingerprint = ?, quantity = ?, total_minor = ?, currency = ?, notes = ?, updated_at = ?
      WHERE id = ? AND version = ?`,
    patch.name ?? spec.name,
    spec.productId,
    sealJson(spec, `config:spec:${id}`),
    sealJson(price, `config:price:${id}`),
    price.fingerprint,
    spec.quantity,
    price.totalMinor,
    product.currency,
    patch.notes ?? row.notes,
    nowIso(),
    id,
    patch.expectedVersion,
  );

  return hydrate(get<ConfigurationRow>('SELECT * FROM configurations WHERE id = ?', id)!);
}

// ---------------------------------------------------------------------------
// Soft delete
// ---------------------------------------------------------------------------

export function deleteConfiguration(actor: Actor, id: string): void {
  const row = get<ConfigurationRow>('SELECT * FROM configurations WHERE id = ? AND deleted_at IS NULL', id);
  if (!row) throw AppError.notFound('Configuration');
  if (!canAccessOwned(actor, row.owner_id)) {
    throw new AppError('FORBIDDEN', 'You do not have access to this configuration');
  }
  // Soft delete preserves the evidentiary chain: the record (and therefore the
  // ability to prove what was quoted) is never physically removed (A.5.28).
  run('UPDATE configurations SET deleted_at = ?, updated_at = ? WHERE id = ?', nowIso(), nowIso(), id);
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

export interface ListQuery {
  page: number;
  pageSize: number;
  order: 'asc' | 'desc';
  q?: string;
  productId?: string;
  ownerId?: string;
  createdFrom?: string;
  createdTo?: string;
}

export function listConfigurations(
  actor: Actor,
  query: ListQuery,
): { rows: ConfigurationSummary[]; total: number; page: number; pageSize: number } {
  const where: string[] = ['deleted_at IS NULL'];
  const params: unknown[] = [];

  // Row-level scoping is applied in SQL, not in JavaScript (A.5.15).
  const elevated = actor.role === 'auditor' || actor.role === 'security_officer' || actor.role === 'admin';
  if (!elevated) {
    where.push('owner_id = ?');
    params.push(actor.id);
  } else if (query.ownerId) {
    where.push('owner_id = ?');
    params.push(query.ownerId);
  }
  if (query.q) {
    where.push('(name LIKE ? OR notes LIKE ? OR fingerprint = ?)');
    const like = `%${query.q.replace(/[%_]/g, (m) => `\\${m}`)}%`;
    params.push(like, like, query.q);
  }
  if (query.productId) {
    where.push('product_id = ?');
    params.push(query.productId);
  }
  if (query.createdFrom) {
    where.push('created_at >= ?');
    params.push(query.createdFrom);
  }
  if (query.createdTo) {
    where.push('created_at <= ?');
    params.push(query.createdTo);
  }

  const clause = `WHERE ${where.join(' AND ')}`;
  const total = Number(get<{ c: number }>(`SELECT COUNT(*) AS c FROM configurations ${clause}`, ...params)?.c ?? 0);
  const order = query.order === 'asc' ? 'ASC' : 'DESC';
  const rows = all<ConfigurationRow>(
    `SELECT * FROM configurations ${clause} ORDER BY created_at ${order} LIMIT ? OFFSET ?`,
    ...params,
    query.pageSize,
    (query.page - 1) * query.pageSize,
  );

  return { rows: rows.map(summary), total, page: query.page, pageSize: query.pageSize };
}

// ---------------------------------------------------------------------------
// Share links
// ---------------------------------------------------------------------------

export function createShare(actor: Actor, configId: string, expiresDays = 30): { url: string; expiresAt: string } {
  const row = get<ConfigurationRow>('SELECT * FROM configurations WHERE id = ? AND deleted_at IS NULL', configId);
  if (!row) throw AppError.notFound('Configuration');
  if (!canAccessOwned(actor, row.owner_id)) {
    throw new AppError('FORBIDDEN', 'You do not have access to this configuration');
  }
  const token = newSecret(24);
  const expiresAt = new Date(Date.now() + Math.min(Math.max(expiresDays, 1), 90) * 86_400_000).toISOString();
  run(
    `INSERT INTO configuration_shares (id, config_id, token_hash, created_by, expires_at, created_at) VALUES (?,?,?,?,?,?)`,
    newId('shr'),
    configId,
    sha256(token),
    actor.id,
    expiresAt,
    nowIso(),
  );
  return { url: `/share/${row.public_id}?t=${token}`, expiresAt };
}

export function revokeShare(actor: Actor, configId: string): number {
  const row = get<ConfigurationRow>('SELECT * FROM configurations WHERE id = ? AND deleted_at IS NULL', configId);
  if (!row) throw AppError.notFound('Configuration');
  if (!canAccessOwned(actor, row.owner_id)) {
    throw new AppError('FORBIDDEN', 'You do not have access to this configuration');
  }
  return run('UPDATE configuration_shares SET revoked_at = ? WHERE config_id = ? AND revoked_at IS NULL', nowIso(), configId).changes;
}

export interface ShareResolution {
  configuration: ConfigurationSummary;
  spec: ConfigurationSpec;
  price: PriceBreakdown;
}

/**
 * Anonymous, read-only access via an opaque bearer token. The token is stored
 * only as a SHA-256 digest, so a database leak does not expose live links.
 * Every access is counted and audited - share links are a real data-exfiltration
 * route and must be monitored (A.8.12, A.5.15).
 */
export function resolveShare(publicId: string, token: string): ShareResolution {
  const row = readByPublicId(publicId);
  if (!row) throw AppError.notFound('Shared configuration');

  const share = get<{ id: string; revoked_at: string | null; expires_at: string | null; token_hash: string }>(
    'SELECT id, revoked_at, expires_at, token_hash FROM configuration_shares WHERE config_id = ? AND token_hash = ?',
    row.id,
    sha256(token),
  );
  if (!share) throw new AppError('NOT_FOUND', 'This share link is not valid');
  if (share.revoked_at) throw new AppError('FORBIDDEN', 'This share link has been revoked');
  if (share.expires_at && Date.parse(share.expires_at) < Date.now()) {
    throw new AppError('FORBIDDEN', 'This share link has expired');
  }

  run(
    'UPDATE configuration_shares SET view_count = view_count + 1, last_viewed_at = ? WHERE id = ?',
    nowIso(),
    share.id,
  );

  const spec = configurationSpecSchema.parse(openJson<ConfigurationSpec>(row.spec_enc, specAad(row)));
  const price = openJson<PriceBreakdown>(row.price_enc, priceAad(row));
  return { configuration: summary(row), spec, price };
}

export function configurationAuditTrail(actor: Actor, configId: string, limit = 100) {
  const row = get<ConfigurationRow>('SELECT * FROM configurations WHERE id = ? AND deleted_at IS NULL', configId);
  if (!row) throw AppError.notFound('Configuration');
  if (!canAccessOwned(actor, row.owner_id)) {
    throw new AppError('FORBIDDEN', 'You do not have access to this configuration');
  }
  return all(
    `SELECT id, seq, occurred_at AS occurredAt, action, outcome, severity, actor_email AS actorEmail, message
       FROM audit_log
      WHERE resource_id = ? AND action LIKE 'config.%'
      ORDER BY seq DESC LIMIT ?`,
    configId,
    Math.min(limit, 500),
  );
}
