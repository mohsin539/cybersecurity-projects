/**
 * Password hashing - scrypt (RFC 7914), driven through `node:crypto`.
 *
 * Rationale (defensible choice, documented in docs/SECURITY-COMPLIANCE.md):
 *   - scrypt is a memory-hard KDF approved by NIST SP 800-132 and explicitly
 *     listed as acceptable by OWASP Password Storage Cheat Sheet alongside
 *     Argon2id. Using the platform primitive avoids a native addon, which
 *     removes an entire class of supply-chain risk (OWASP A06:2021).
 *   - Parameters follow the OWASP minimum: N = 2^17, r = 8, p = 1
 *     (~128 MiB memory hardness, ~50 ms on commodity hardware).
 *   - Parameters are stored per-hash so they can be raised later without
 *     invalidating existing credentials (transparent rehash on next login).
 *   - Verification is constant-time.
 */

import { randomBytes, scrypt as scryptCb, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCb) as (
  password: string | Buffer,
  salt: string | Buffer,
  keylen: number,
  options: { N: number; r: number; p: number; maxmem: number },
) => Promise<Buffer>;

export interface ScryptParams {
  N: number;
  r: number;
  p: number;
  keylen: number;
}

export const CURRENT_PARAMS: ScryptParams = {
  N: 131_072, // 2^17
  r: 8,
  p: 1,
  keylen: 32,
};

/** Hard ceiling so a malicious stored parameter cannot force a memory DoS. */
const MAX_N = 1_048_576;
const MAXMEM = 2 * 1024 * 1024 * 1024;

const PREFIX = 'scrypt';

/**
 * Encoded form:  scrypt$N$r$p$saltB64$hashB64
 * Self-describing so verification always uses the *stored* parameters.
 */
export async function hashPassword(password: string, params: ScryptParams = CURRENT_PARAMS): Promise<string> {
  const salt = randomBytes(16);
  const derived = await scrypt(password.normalize('NFKC'), salt, params.keylen, {
    N: params.N,
    r: params.r,
    p: params.p,
    maxmem: MAXMEM,
  });
  return [
    PREFIX,
    params.N,
    params.r,
    params.p,
    salt.toString('base64'),
    derived.toString('base64'),
  ].join('$');
}

export interface VerifyResult {
  valid: boolean;
  needsRehash: boolean;
}

export async function verifyPassword(password: string, encoded: string): Promise<VerifyResult> {
  const parts = encoded.split('$');
  if (parts.length !== 6 || parts[0] !== PREFIX) return { valid: false, needsRehash: false };

  const N = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  if (
    !Number.isInteger(N) ||
    !Number.isInteger(r) ||
    !Number.isInteger(p) ||
    N < 2 ||
    N > MAX_N ||
    !Number.isInteger(Math.log2(N)) || // N must be a power of two
    r < 1 ||
    p < 1
  ) {
    return { valid: false, needsRehash: false };
  }

  let salt: Buffer;
  let expected: Buffer;
  try {
    salt = Buffer.from(parts[4]!, 'base64');
    expected = Buffer.from(parts[5]!, 'base64');
  } catch {
    return { valid: false, needsRehash: false };
  }
  if (salt.length === 0 || expected.length === 0) return { valid: false, needsRehash: false };

  let derived: Buffer;
  try {
    derived = await scrypt(password.normalize('NFKC'), salt, expected.length, {
      N,
      r,
      p,
      maxmem: MAXMEM,
    });
  } catch {
    return { valid: false, needsRehash: false };
  }

  const valid = derived.length === expected.length && timingSafeEqual(derived, expected);
  const needsRehash =
    valid && (N < CURRENT_PARAMS.N || r < CURRENT_PARAMS.r || p < CURRENT_PARAMS.p);
  return { valid, needsRehash };
}

/**
 * Burn roughly the same CPU/memory as a real verification. Called on unknown
 * accounts so that response timing does not disclose account existence.
 */
export async function fakeVerify(): Promise<void> {
  await hashPassword(randomBytes(24).toString('base64'));
}
