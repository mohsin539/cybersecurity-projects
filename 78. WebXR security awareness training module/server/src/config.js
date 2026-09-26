'use strict';
/**
 * config.js — Central configuration (12-factor; ISO A.5.9 asset inventory)
 * Secrets come from environment variables — never hardcoded (A.8.12).
 */

const path = require('node:path');
const crypto = require('node:crypto');

const ROOT = path.resolve(__dirname, '..', '..');
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, 'data');
const isLocal = process.env.NODE_ENV === 'local';
const VERSION = require('../../package.json').version;

function env(name, fallback) {
  const v = process.env[name];
  return v === undefined || v === '' ? fallback : v;
}

// CLI override: `--port 9443` or `--port=9443` (run.bat passes this through).
// Precedence: CLI flag > PORT env var > 8443.
function cliPort() {
  const argv = process.argv.slice(2);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--port' || a === '-p') {
      const n = Number(argv[i + 1]);
      if (Number.isInteger(n) && n > 0 && n < 65536) return String(n);
    }
    if (a.startsWith('--port=')) {
      const n = Number(a.slice('--port='.length));
      if (Number.isInteger(n) && n > 0 && n < 65536) return String(n);
    }
  }
  return null;
}

// JWT secret: env-provided in production; ephemeral random in local dev only
// (documented deviation — see security.md §2.1).
const JWT_SECRET = env('JWT_SECRET', isLocal ? crypto.randomBytes(48).toString('hex') : '');
if (!JWT_SECRET) {
  console.error('[config] FATAL: JWT_SECRET must be set outside local mode (ISO A.5.23).');
  process.exit(1);
}

// 32-byte key for field-level AES-256-GCM encryption of PII (A.8.24).
const FIELD_KEY = Buffer.from(env('FIELD_KEY', isLocal ? crypto.randomBytes(32).toString('hex') : ''), 'hex');
if (FIELD_KEY.length !== 32) {
  console.error('[config] FATAL: FIELD_KEY must be a 64-char hex (32 bytes) outside local mode.');
  process.exit(1);
}

module.exports = {
  ROOT,
  DATA_DIR,
  VERSION,
  PORT: Number(cliPort() || env('PORT', '8443')),
  NODE_ENV: env('NODE_ENV', 'production'),
  IS_LOCAL: isLocal,
  JWT_SECRET,
  FIELD_KEY,
  ADMIN_SEED_PASSWORD: env('ADMIN_SEED_PASSWORD', isLocal ? 'Admin#Passw0rd!' : ''),
  RATE_LIMITS: {
    login: { windowMs: 60_000, max: 5 }, // OWASP A07 / NIST AC-7
    api: { windowMs: 60_000, max: 120 },
    telemetry: { windowMs: 60_000, max: 600 },
  },
  RETENTION: {
    auditDays: 400, // hash-chained WORM-equivalent (architecture.md §16)
    sessionDays: 90,
  },
  SECURITY_HEADERS: {
    // OWASP Secure Headers Project / ASVS V14
    'Content-Security-Policy': [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self' data:",
      "connect-src 'self'",
      "font-src 'self'",
      "object-src 'none'",
      "base-uri 'none'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      'upgrade-insecure-requests',
    ].join('; '),
    'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), xr-spatial-tracking=(self)',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Cache-Control': 'no-store',
  },
};
