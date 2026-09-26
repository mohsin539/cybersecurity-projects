/**
 * @prismforge/shared - public barrel.
 *
 * Imported by the web client (via a Vite alias) and by the API (via tsconfig
 * `paths`, resolved by tsx). Keeping one source of truth guarantees the client
 * preview and the server-authoritative record can never drift apart.
 */

export * from './constants.js';
export * from './catalog.js';
export * from './schema.js';
export * from './pricing.js';
