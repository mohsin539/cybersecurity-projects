/**
 * Cryptographic primitives - built exclusively on `node:crypto`.
 *
 * NIST SP 800-131A Rev.2 aligned choices:
 *   - AES-256-GCM for data at rest (authenticated encryption, 96-bit IV)
 *   - HMAC-SHA-256 for the audit hash chain (keyed, so an attacker who gains
 *     DB write access still cannot forge a valid chain without the key)
 *   - HKDF-SHA256 for sub-key separation
 *   - SHA-256 for non-keyed integrity digests
 */

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  hkdfSync,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from 'node:crypto';
import { env } from '../config/env.js';

// ---------------------------------------------------------------------------
// Sub-key derivation (NIST SP 800-108)
// ---------------------------------------------------------------------------

const cache = new Map<string, Buffer>();

function deriveKey(purpose: string, secret: string): Buffer {
  const hit = cache.get(purpose);
  if (hit) return hit;
  // 32-byte subkey, salt is a fixed domain-separation label, info binds the
  // purpose so a key can never be reused across contexts.
  const key = Buffer.from(
    hkdfSync('sha256', Buffer.from(secret, 'base64url'), Buffer.from('prismforge.v1'), Buffer.from(purpose), 32),
  );
  cache.set(purpose, key);
  return key;
}

function encKey(): Buffer {
  return deriveKey('aes-256-gcm-config', env.configEncryptionKey);
}

// ---------------------------------------------------------------------------
// AES-256-GCM (ISO/IEC 27001 A.8.24)
// ---------------------------------------------------------------------------

const IV_BYTES = 12;
const TAG_BYTES = 16;

export interface SealedBox {
  v: 1;
  iv: string;
  tag: string;
  ct: string;
}

/**
 * @param plaintext  UTF-8 JSON payload
 * @param aad        Additional authenticated data bound to the ciphertext -
 *                   e.g. the row id, so a ciphertext cannot be moved between
 *                   records (ciphertext-swapping / cut-and-paste attack).
 */
export function seal(plaintext: string, aad: string): SealedBox {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', encKey(), iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return {
    v: 1,
    iv: iv.toString('base64url'),
    tag: cipher.getAuthTag().toString('base64url'),
    ct: ct.toString('base64url'),
  };
}

export function open(box: SealedBox, aad: string): string {
  const decipher = createDecipheriv('aes-256-gcm', encKey(), Buffer.from(box.iv, 'base64url'), {
    authTagLength: TAG_BYTES,
  });
  decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(Buffer.from(box.tag, 'base64url'));
  return Buffer.concat([
    decipher.update(Buffer.from(box.ct, 'base64url')),
    decipher.final(),
  ]).toString('utf8');
}

export function sealJson(value: unknown, aad: string): string {
  return JSON.stringify(seal(JSON.stringify(value), aad));
}

export function openJson<T>(serialised: string, aad: string): T {
  return JSON.parse(open(JSON.parse(serialised) as SealedBox, aad)) as T;
}

// ---------------------------------------------------------------------------
// Digests / HMAC
// ---------------------------------------------------------------------------

export function sha256(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

export function auditMac(input: string): string {
  return createHmac('sha256', deriveKey('audit-chain-hmac', env.auditHmacKey))
    .update(input, 'utf8')
    .digest('hex');
}

/** Constant-time comparison that tolerates unequal lengths. */
export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ab.length !== bb.length) {
    // Still burn a comparison so timing does not reveal length equality.
    timingSafeEqual(ab, ab);
    return false;
  }
  return timingSafeEqual(ab, bb);
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

/** Deterministic, non-reversible fingerprint of an IP for abuse analytics. */
export function ipFingerprint(ip: string): string {
  return scryptSync(ip, 'prismforge.ip.v1', 16).toString('base64url');
}

// ---------------------------------------------------------------------------
// Canonical serialisation for the hash chain
// ---------------------------------------------------------------------------

/**
 * RFC 8785-flavoured canonical JSON: keys sorted, no insignificant whitespace,
 * undefined dropped. Determinism is what makes the chain verifiable by any
 * third party who can reproduce the canonical form.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map(sortValue);
  const src = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(src).sort()) {
    const v = src[key];
    if (v === undefined) continue;
    out[key] = sortValue(v);
  }
  return out;
}
