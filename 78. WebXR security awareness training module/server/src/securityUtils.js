'use strict';
/**
 * securityUtils.js — Core security primitives (zero external dependencies)
 * Standards: ISO/IEC 27001:2022 A.8.24 (cryptography), A.8.15 (logging),
 *            NIST SP 800-63B (authenticator assurance), OWASP ASVS 4.0 V2/V3/V6/V7
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

// ─── Rate limiting (OWASP A07 brute-force defense; NIST AC-7) ───────────────

const buckets = new Map(); // key → { count, resetAt }

/**
 * Fixed-window rate limiter. Deny-by-default on invalid input.
 * @returns {{allowed: boolean, remaining: number, retryAfter: number}}
 */
function rateLimit(key, { windowMs = 60000, max = 100 } = {}) {
  if (typeof key !== 'string' || key.length === 0 || key.length > 256) {
    return { allowed: false, remaining: 0, retryAfter: Math.ceil(windowMs / 1000) };
  }
  const now = Date.now();
  let b = buckets.get(key);
  if (!b || now >= b.resetAt) {
    b = { count: 0, resetAt: now + windowMs };
    buckets.set(key, b);
  }
  b.count += 1;
  // Opportunistic cleanup to bound memory (A.5.9 asset hygiene)
  if (buckets.size > 10000) {
    for (const [k, v] of buckets) {
      if (now >= v.resetAt) buckets.delete(k);
    }
  }
  return {
    allowed: b.count <= max,
    remaining: Math.max(0, max - b.count),
    retryAfter: Math.ceil((b.resetAt - now) / 1000),
  };
}

// ─── Password hashing (OWASP A02; NIST SP 800-63B — salted, memory-hard) ────

const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(password), salt, 64, SCRYPT_PARAMS);
  return `scrypt$${salt.toString('base64')}$${hash.toString('base64')}`;
}

function verifyPassword(password, stored) {
  try {
    const [scheme, saltB64, hashB64] = String(stored).split('$');
    if (scheme !== 'scrypt') return false;
    const salt = Buffer.from(saltB64, 'base64');
    const expected = Buffer.from(hashB64, 'base64');
    const actual = crypto.scryptSync(String(password), salt, expected.length, SCRYPT_PARAMS);
    return crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

// ─── Signed tokens (HMAC; IETF RFC 7515-style, HS256) ────────────────────────

const JWT_TTL_MS = 8 * 60 * 60 * 1000; // 8h learner sessions (see architecture.md §8.2)

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

function signToken(payload, secret, ttlMs = JWT_TTL_MS) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64url(JSON.stringify({ ...payload, iat: Date.now(), exp: Date.now() + ttlMs }));
  const sig = crypto.createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}

/** Constant-time token verification (rejects alg-confusion, expired, tampered). */
function verifyToken(token, secret) {
  try {
    const parts = String(token).split('.');
    if (parts.length !== 3) return null;
    const [header, body, sig] = parts;
    const hdr = JSON.parse(Buffer.from(header, 'base64url').toString('utf8'));
    if (hdr.alg !== 'HS256') return null; // anti alg-confusion (JWT best current practice)
    const expected = crypto.createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
    const a = Buffer.from(sig);
    const b = Buffer.from(expected);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (typeof payload.exp !== 'number' || Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

// ─── Content / data integrity (SI-7, A.8.24) ────────────────────────────────

function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// ─── Tamper-evident audit chain (A.8.15; NIST AU-9; SOC 2 CC7.2) ─────────────

/**
 * Append-only, hash-chained audit log. Each record binds the previous hash,
 * so any mutation/reorder/deletion breaks verification.
 */
class AuditChain {
  constructor(filePath) {
    this.filePath = filePath;
    this.lastHash = '0'.repeat(64);
    if (fs.existsSync(filePath)) {
      // Rebuild chain head from existing log (survives restarts)
      const lines = fs.readFileSync(filePath, 'utf8').split('\n').filter(Boolean);
      for (const line of lines) {
        try { this.lastHash = JSON.parse(line).hash; } catch { /* skip corrupt tail */ }
      }
    }
  }

  append(event) {
    const record = {
      seq: undefined,
      ts: new Date().toISOString(),
      actor: event.actor || 'system',
      action: event.action,
      detail: event.detail || {},
      prev: this.lastHash,
    };
    record.hash = sha256(JSON.stringify({ ...record, hash: null }));
    fs.appendFileSync(this.filePath, JSON.stringify(record) + '\n');
    this.lastHash = record.hash;
    return record;
  }

  /** Verify whole-chain integrity. Returns { valid, brokenAt }. */
  verify() {
    if (!fs.existsSync(this.filePath)) return { valid: true, entries: 0 };
    const lines = fs.readFileSync(this.filePath, 'utf8').split('\n').filter(Boolean);
    let prev = '0'.repeat(64);
    for (let i = 0; i < lines.length; i++) {
      let rec;
      try { rec = JSON.parse(lines[i]); } catch { return { valid: false, brokenAt: i }; }
      const expected = sha256(JSON.stringify({ ...rec, hash: null }));
      if (rec.prev !== prev || rec.hash !== expected) return { valid: false, brokenAt: i };
      prev = rec.hash;
    }
    return { valid: true, entries: lines.length };
  }
}

// ─── Field-level encryption for PII at rest (A.8.24; SC-28) ──────────────────

function encryptField(plaintext, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  return `${iv.toString('base64')}.${cipher.getAuthTag().toString('base64')}.${enc.toString('base64')}`;
}

function decryptField(blob, key) {
  try {
    const [ivB64, tagB64, dataB64] = String(blob).split('.');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64'));
    decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
    return Buffer.concat([decipher.update(Buffer.from(dataB64, 'base64')), decipher.final()]).toString('utf8');
  } catch {
    return null;
  }
}

// ─── Input validation & sanitization (OWASP A03; SI-10) ──────────────────────

/** Strip control chars, cap length, escape HTML-significant characters. */
function sanitizeText(value, maxLen = 200) {
  if (typeof value !== 'string') return '';
  return value
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .replace(/[<>&"']/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;' }[c]))
    .slice(0, maxLen);
}

function isSafeEmail(value) {
  return typeof value === 'string' && value.length <= 254 && /^[^\s@<>&"']+@[^\s@<>&"']+\.[^\s@<>&"']+$/.test(value);
}

function isSafeId(value) {
  return typeof value === 'string' && /^[a-z0-9_-]{1,64}$/i.test(value);
}

module.exports = {
  rateLimit,
  hashPassword,
  verifyPassword,
  signToken,
  verifyToken,
  sha256,
  AuditChain,
  encryptField,
  decryptField,
  sanitizeText,
  isSafeEmail,
  isSafeId,
  JWT_TTL_MS,
};
