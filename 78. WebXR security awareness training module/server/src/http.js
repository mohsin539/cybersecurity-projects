'use strict';
/**
 * http.js — Minimal zero-dependency HTTP framework for the training API.
 * Enforces security headers (ASVS V14), body size caps, and JSON-only parsing.
 */

const http = require('node:http');
const { SECURITY_HEADERS, IS_LOCAL } = require('./config');

/** Create an app with route registration and middleware hooks. */
function createApp() {
  const routes = [];
  const middlewares = [];

  function add(method, pattern, handler) {
    // Convert '/sessions/:id/complete' to regex with named capture keys
    const keys = [];
    const regex = new RegExp(
      '^' +
        pattern
          .split('/')
          .map((seg) => {
            if (seg.startsWith(':')) {
              keys.push(seg.slice(1));
              return '([^/]+)';
            }
            return seg.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
          })
          .join('/') +
        '$'
    );
    routes.push({ method, regex, keys, handler });
  }

  return {
    get: (p, h) => add('GET', p, h),
    post: (p, h) => add('POST', p, h),
    put: (p, h) => add('PUT', p, h),
    delete: (p, h) => add('DELETE', p, h),
    use: (fn) => middlewares.push(fn),
    routes,

    /** Dispatch one request through middleware, then routes. */
    async handle(req, res) {
      for (const mw of middlewares) await mw(req, res);
      if (res.writableEnded) return;

      const url = new URL(req.url, 'http://internal');
      const pathname = decodeURIComponent(url.pathname).replace(/\/+$/, '') || '/';
      req.path = pathname;
      req.query = Object.fromEntries(url.searchParams);

      // Security headers on every response (OWASP Secure Headers / ASVS 14.4)
      for (const [k, v] of Object.entries(SECURITY_HEADERS)) {
        res.setHeader(k, v);
      }
      if (IS_LOCAL) {
        res.setHeader('X-Dev-Mode', 'local');
      }

      for (const r of routes) {
        if (r.method !== req.method) continue;
        const m = r.regex.exec(pathname);
        if (!m) continue;
        req.params = {};
        r.keys.forEach((k, i) => {
          req.params[k] = m[i + 1];
        });
        return r.handler(req, res);
      }

      res.statusCode = 404;
      res.setHeader('Content-Type', 'application/json; charset=utf-8');
      res.end(JSON.stringify({ error: 'not_found' }));
    },
  };
}

/** Body reader with hard size cap (DoS guard) and JSON validation. */
function readJsonBody(req, maxBytes = 16 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > maxBytes) {
        reject(new Error('payload_too_large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        const text = Buffer.concat(chunks).toString('utf8');
        if (text === '') {
          resolve({});
          return;
        }
        const parsed = JSON.parse(text);
        if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
          reject(new Error('invalid_json'));
          return;
        }
        resolve(parsed);
      } catch {
        reject(new Error('invalid_json'));
      }
    });
    req.on('error', reject);
  });
}

/**
 * Create the HTTP server around a single request dispatcher.
 * Centralizes 500 handling so responses are never written twice.
 */
function listen(dispatcher) {
  return http.createServer((req, res) => {
    Promise.resolve(dispatcher(req, res)).catch((err) => {
      console.error('[http] handler error:', err.message);
      if (!res.writableEnded && !res.headersSent) {
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        res.end(JSON.stringify({ error: 'internal_error' }));
      } else if (!res.writableEnded) {
        res.end();
      }
    });
  });
}

module.exports = { createApp, readJsonBody, listen };
