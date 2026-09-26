'use strict';
/**
 * auth.js — Identity & Access Service (A.5.15, A.8.2, A.8.5)
 * SSO-federation-ready: users carry idp_subject for OIDC/SAML mapping.
 * Local demo login is seeded for evaluation; see security.md §2.1.
 */

const { load, save, encPII, decPII } = require('./db');
const { verifyPassword, signToken, verifyToken, isSafeEmail, sanitizeText } = require('./securityUtils');
const { JWT_SECRET } = require('./config');

const USERS_FILE = 'users';

/** Seed demo users on first run (local evaluation only — disabled in production). */
function seedUsers(adminPassword) {
  if (load(USERS_FILE).length > 0) return;
  save(USERS_FILE, [
    {
      id: 'u-admin',
      email: encPII('admin@corp.example'),
      name: 'Security Admin',
      role: 'admin',
      idp_subject: 'seed-admin',
      password: adminPassword ? require('./securityUtils').hashPassword(adminPassword) : null,
      mfaEnrolled: true,
      createdAt: Date.now(),
    },
    {
      id: 'u-learner',
      email: encPII('learner@corp.example'),
      name: 'Sample Learner',
      role: 'learner',
      idp_subject: 'seed-learner',
      password: null, // demo learners authenticate via demo-login (no local passwords)
      mfaEnrolled: false,
      createdAt: Date.now(),
    },
  ]);
}

function findUserByEmail(email) {
  const users = load(USERS_FILE);
  const found = users.find((u) => decPII(u.email) === String(email).toLowerCase());
  return found || null;
}

function getUserById(id) {
  return load(USERS_FILE).find((u) => u.id === id) || null;
}

/**
 * Login with rate limiting and generic error messages (no user enumeration — ASVS V2.5).
 * Returns a signed token or null.
 */
function login(email, password, ctx) {
  const { rateLimit } = require('./securityUtils');
  const key = `login:${ctx.ip}`;
  const rl = rateLimit(key, { windowMs: 60_000, max: 5 });
  if (!rl.allowed) {
    return { error: 'too_many_attempts', retryAfter: rl.retryAfter };
  }
  if (!isSafeEmail(email) || typeof password !== 'string' || password.length > 1024) {
    return { error: 'invalid_credentials' };
  }
  const user = findUserByEmail(email);
  const ok = user && user.password && verifyPassword(password, user.password);
  if (!ok) {
    return { error: 'invalid_credentials' };
  }
  const token = signToken({ sub: user.id, role: user.role, idp: user.idp_subject }, JWT_SECRET);
  return { token, user: publicUser(user) };
}

/** Demo learner login (no password) — visible only in local mode. */
function demoLogin(ctx) {
  const { rateLimit } = require('./securityUtils');
  const rl = rateLimit(`demo:${ctx.ip}`, { windowMs: 60_000, max: 10 });
  if (!rl.allowed) return { error: 'too_many_attempts', retryAfter: rl.retryAfter };
  const user = load(USERS_FILE).find((u) => u.id === 'u-learner');
  if (!user) return { error: 'unavailable' };
  const token = signToken({ sub: user.id, role: user.role, idp: user.idp_subject }, JWT_SECRET);
  return { token, user: publicUser(user) };
}

/** Verify Authorization header and attach req.user (deny-by-default). */
function requireAuth(req, res) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) {
    res.statusCode = 401;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify({ error: 'unauthorized' }));
    return null;
  }
  const payload = verifyToken(token, JWT_SECRET);
  if (!payload || !payload.sub) {
    res.statusCode = 401;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify({ error: 'unauthorized' }));
    return null;
  }
  req.user = payload;
  return payload;
}

/** Role gate (RBAC — A.5.15). Admin/author-only endpoints. */
function requireRole(req, res, roles) {
  const payload = requireAuth(req, res);
  if (!payload) return null;
  if (!roles.includes(payload.role)) {
    res.statusCode = 403;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify({ error: 'forbidden' }));
    return null;
  }
  return payload;
}

/** Public projection of a user record — strips secrets/PII ciphertext. */
function publicUser(u) {
  return {
    id: u.id,
    name: u.name,
    role: u.role,
    email: decPII(u.email),
    mfaEnrolled: u.mfaEnrolled,
  };
}

/** Create a user (admin console / SCIM-style provisioning). */
function createUser({ email, name, role, password }) {
  if (!isSafeEmail(email)) return { error: 'invalid_email' };
  if (!['learner', 'author', 'admin'].includes(role)) return { error: 'invalid_role' };
  if (findUserByEmail(email)) return { error: 'exists' };
  const users = load(USERS_FILE);
  const user = {
    id: `u-${Date.now().toString(36)}${Math.floor(Math.random() * 1e4).toString(36)}`,
    email: encPII(String(email).toLowerCase()),
    name: sanitizeText(name || email.split('@')[0], 80),
    role,
    idp_subject: `local-${Date.now().toString(36)}`,
    password: password ? require('./securityUtils').hashPassword(password) : null,
    mfaEnrolled: false,
    createdAt: Date.now(),
  };
  users.push(user);
  save(USERS_FILE, users);
  return { user: publicUser(user) };
}

function listUsers() {
  return load(USERS_FILE).map(publicUser);
}

module.exports = {
  seedUsers,
  login,
  demoLogin,
  requireAuth,
  requireRole,
  publicUser,
  createUser,
  listUsers,
  findUserByEmail,
  getUserById,
};
