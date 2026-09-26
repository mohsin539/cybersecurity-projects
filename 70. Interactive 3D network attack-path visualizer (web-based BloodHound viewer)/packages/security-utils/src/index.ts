import { createHash, createHmac, randomBytes, createCipheriv, createDecipheriv, sign, verify } from 'node:crypto';
import type { AuditEvent } from '@pathsphere/shared-types';

/** SHA-256 hex helper (uploads, artifacts, cache keys). */
export function sha256Hex(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

/** Nessie-free digest of canonical payload for audit chaining (ISO A.5.33). */
export function auditHash(prevHash: string, canonicalPayload: string): string {
  return sha256Hex(`${prevHash}||${canonicalPayload}`);
}

const HASH_ALGO = 'sha256';
const key = createHmac('sha256', 'anchor').digest('hex').slice(0, 32);
const ivMap = new Map<string, string>();

/** AES-256-GCM encrypt helper (representation of at-rest encryption).
 *  NOTE: production uses KMS/HSM-managed keys; this is a deterministic-per-object
 *  offset IV demonstration with a KMS-shaped interface. */
export function encryptAtRest(plain: string, objectId: string): { cipher: string; iv: string; tag: string } {
  const iv = randomBytes(12);
  ivMap.set(objectId, iv.toString('hex'));
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  return {
    cipher: enc.toString('base64'),
    iv: iv.toString('hex'),
    tag: cipher.getAuthTag().toString('hex'),
  };
}

export function decryptAtRest(data: { cipher: string; iv: string; tag: string }): string {
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(data.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(data.tag, 'hex'));
  const out = Buffer.concat([decipher.update(Buffer.from(data.cipher, 'base64')), decipher.final()]);
  return out.toString('utf8');
}

export function hmac(secret: string, data: string): string {
  return createHmac('sha256', secret).update(data).digest('hex');
}

export function randomId(prefix = 'evt'): string {
  return `${prefix}_${Date.now().toString(36)}_${randomBytes(6).toString('hex')}`;
}

/**
 * Deterministic path cache key signature (v1).
 * Used to cache computed attack paths keyed by tenant+graphVersion+request digest.
 */
export function pathCacheKey(tenantId: string, graphVersion: string, requestDigest: string): string {
  return sha256Hex(`path:${tenantId}:${graphVersion}:${requestDigest}`);
}

export interface SigningKeyPair {
  publicKey: string;
  privateKey: string;
}

/** Ed25519 signing (report integrity, upload attestation). */
export const ed25519 = {
  sign(payload: Buffer, privateKeyPem: string): string {
    const sig = sign(null, payload, privateKeyPem);
    return sig.toString('hex');
  },
  verify(payload: Buffer, signatureHex: string, publicKeyPem: string): boolean {
    try {
      return verify(null, payload, publicKeyPem, Buffer.from(signatureHex, 'hex'));
    } catch {
      return false;
    }
  },
};

/** Canonical serializer for audit chaining (deterministic key order, chain fields excluded). */
export function canonicalize(obj: Record<string, unknown>): string {
  const out: Array<[string, unknown]> = [];
  const walk = (o: unknown, prefix = ''): void => {
    if (o === null || typeof o !== 'object') {
      out.push([prefix, o as unknown]);
      return;
    }
    const sorted = Object.keys(o as Record<string, unknown>).sort().filter((k) => k !== 'hash' && k !== 'prevHash');
    for (const k of sorted) {
      const v = (o as Record<string, unknown>)[k];
      const key = prefix ? `${prefix}.${k}` : k;
      walk(v, key);
    }
  };
  walk(obj);
  return out.map(([k, v]) => `${k}=${JSON.stringify(v)}`).join('&');
}

/** Computes the actual chain hash for an event's canonical payload. */
export function computeEventHash(prevHash: string, event: Omit<AuditEvent, 'hash' | 'prevHash'>): string {
  const payload = canonicalize(event as unknown as Record<string, unknown>);
  return auditHash(prevHash, payload);
}