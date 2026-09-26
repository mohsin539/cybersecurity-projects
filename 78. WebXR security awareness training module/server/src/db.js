'use strict';
/**
 * db.js — JSON-file persistence layer (swap-in ready for PostgreSQL per architecture.md §7).
 * Multi-tenant style namespacing + PII field encryption (A.8.24, SC-28).
 */

const fs = require('node:fs');
const path = require('node:path');
const { encryptField, decryptField } = require('./securityUtils');

const { DATA_DIR, FIELD_KEY } = require('./config');

function ensureDataDir() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

function dbFile(name) {
  return path.join(DATA_DIR, `${name}.json`);
}

/** Load a JSON collection; returns [] when absent or corrupt (fail-safe to empty). */
function load(name) {
  ensureDataDir();
  try {
    const raw = fs.readFileSync(dbFile(name), 'utf8');
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

/** Atomic save: write temp file then rename (prevents partial writes / torn state). */
function save(name, rows) {
  ensureDataDir();
  const tmp = `${dbFile(name)}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(rows, null, 2));
  fs.renameSync(tmp, dbFile(name));
}

/** Encrypt a PII field before persisting (ciphertext, never plaintext at rest). */
function encPII(value) {
  return encryptField(value, FIELD_KEY);
}

function decPII(blob) {
  return decryptField(blob, FIELD_KEY);
}

module.exports = { load, save, encPII, decPII, ensureDataDir };
