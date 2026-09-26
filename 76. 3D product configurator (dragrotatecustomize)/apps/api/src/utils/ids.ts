/**
 * Identifier + time helpers.
 *
 * Identifiers use the URL-safe alphabet with a timestamp prefix (ULID-like):
 * lexicographically sortable by creation time, which makes the audit trail and
 * the configuration register naturally chronological without a secondary index.
 */

import { randomBytes, randomUUID } from 'node:crypto';

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // Crockford base32, no I/L/O/U

function encodeTime(ms: number, len: number): string {
  let out = '';
  let n = ms;
  for (let i = len - 1; i >= 0; i--) {
    out = ALPHABET[n % 32] + out;
    n = Math.floor(n / 32);
  }
  return out;
}

function randomPart(len: number): string {
  const bytes = randomBytes(len);
  let out = '';
  for (let i = 0; i < len; i++) out += ALPHABET[bytes[i]! % 32];
  return out;
}

/** e.g. `01J8Z6K2QW9M4T7YB3C0N5P8RD` */
export function newId(prefix: string): string {
  return `${prefix}_${encodeTime(Date.now(), 10)}${randomPart(16)}`;
}

export function newUuid(): string {
  return randomUUID();
}

/** 256-bit URL-safe secret used for refresh tokens and share links. */
export function newSecret(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

export function nowIso(): string {
  return new Date().toISOString();
}

export function isoPlusSeconds(seconds: number): string {
  return new Date(Date.now() + seconds * 1000).toISOString();
}

export function isExpired(iso: string | null | undefined): boolean {
  if (!iso) return true;
  return Date.parse(iso) <= Date.now();
}

export function daysAgo(days: number): string {
  return new Date(Date.now() - days * 86_400_000).toISOString();
}

/** Compares two version integers (optimistic concurrency). */
export function versionOf(v: unknown): number {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}
