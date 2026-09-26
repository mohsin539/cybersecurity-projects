'use strict';
/**
 * index.js — Server entry point.
 * Serves the WebXR client (public/) and the REST API with uniform security headers.
 * Production deployment: put behind a TLS-terminating proxy (see security.md §2.3).
 */

const fs = require('node:fs');
const path = require('node:path');
const { listen } = require('./http');
const { createRoutes, audit } = require('./routes');
const auth = require('./auth');
const { PORT, DATA_DIR, IS_LOCAL, ADMIN_SEED_PASSWORD } = require('./config');

fs.mkdirSync(DATA_DIR, { recursive: true });
auth.seedUsers(ADMIN_SEED_PASSWORD);

const app = createRoutes();
const PUBLIC_DIR = path.join(__dirname, '..', '..', 'public');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.wasm': 'application/wasm',
  '.gltf': 'model/gltf+json',
  '.glb': 'model/gltf-binary',
};

// Static file handler with path-traversal protection (OWASP A01 / ASVS V12)
function serveStatic(req, res) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return false;
  let pathname;
  try {
    pathname = decodeURIComponent(new URL(req.url, 'http://internal').pathname);
  } catch {
    return false;
  }
  if (!pathname.startsWith('/')) return false;

  const resolved = path.normalize(path.join(PUBLIC_DIR, pathname));
  if (!resolved.startsWith(PUBLIC_DIR + path.sep) && resolved !== PUBLIC_DIR) {
    return false; // traversal attempt
  }

  let filePath = resolved;
  if (pathname === '/' || !path.extname(filePath)) {
    filePath = path.join(PUBLIC_DIR, 'index.html'); // SPA fallback
  }
  if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
    filePath = path.join(PUBLIC_DIR, 'index.html');
  }
  if (!fs.existsSync(filePath)) return false;

  // Uniform security headers on static responses too (ASVS V14.4)
  const { SECURITY_HEADERS } = require('./config');
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) {
    res.setHeader(k, v);
  }
  const ext = path.extname(filePath).toLowerCase();
  res.statusCode = 200;
  res.setHeader('Content-Type', MIME[ext] || 'application/octet-stream');
  // Static assets are immutable and integrity-hashed in production CDN (A.8.24/SI-7);
  // in this local build we serve fresh to ease development.
  res.setHeader('Cache-Control', IS_LOCAL ? 'no-store' : 'public, max-age=3600');
  if (req.method === 'HEAD') {
    res.end();
    return true;
  }
  fs.createReadStream(filePath).pipe(res);
  return true;
}

/**
 * Single request dispatcher: /api/* → app router, everything else → static SPA.
 * Static serving includes path-traversal protection (OWASP A01 / ASVS V12).
 */
function dispatch(req, res) {
  if (req.url.startsWith('/api/')) {
    return app.handle(req, res);
  }
  if (!serveStatic(req, res)) {
    res.statusCode = 404;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify({ error: 'not_found' }));
  }
}

const server = listen(dispatch);

server.listen(PORT, () => {
  console.log(`[webxr-training] listening on http://localhost:${PORT} (${IS_LOCAL ? 'LOCAL DEV' : 'production'} mode)`);
  console.log(`[webxr-training] data dir: ${DATA_DIR}`);
  const v = audit.verify();
  console.log(`[webxr-training] audit chain: ${v.valid ? 'valid' : 'BROKEN at ' + v.brokenAt} (${v.entries ?? 0} entries)`);
  if (IS_LOCAL) {
    console.log('[webxr-training] demo login enabled: POST /api/auth/demo-login');
  }
});

// Graceful shutdown (A.5.30 ICT readiness basics)
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    console.log(`[webxr-training] ${sig} received, shutting down…`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 2000).unref();
  });
}

module.exports = { server };
