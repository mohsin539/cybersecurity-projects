'use strict';
/**
 * retention.js — Storage-limitation job (GDPR Art.5(1)(e); memory.md §3).
 * Purges sessions older than the configured retention window.
 * Run via: npm run retention  (schedule via cron/CI in production)
 */

const { load, save } = require('../server/src/db');
const { RETENTION } = require('../server/src/config');

const cutoff = Date.now() - RETENTION.sessionDays * 86400000;
const sessions = load('sessions');
const kept = sessions.filter((s) => (s.completedAt ?? s.startedAt) >= cutoff);
save('sessions', kept);

console.log(
  `[retention] kept ${kept.length}/${sessions.length} sessions ` +
    `(purging ${sessions.length - kept.length} older than ${RETENTION.sessionDays}d)`
);
