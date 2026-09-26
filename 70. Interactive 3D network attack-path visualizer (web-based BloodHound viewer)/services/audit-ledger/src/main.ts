import { jsonServer, health, isMain } from '@pathsphere/server-kit';
import { computeEventHash, randomId } from '@pathsphere/security-utils';
import type { AuditEvent } from '@pathsphere/shared-types';

/** Append-only hash-chained audit ledger.
 *  Each event: hash = sha256(prevHash || canonical(eventBody)).
 *  Verify endpoint walks the chain; any tamper breaks prevHash linkage (ISO A.5.33,
 *  A.8.15, NIST SP 800-53 AU-3/AU-6). Written to WORM object storage in production. */

export interface LedgerStore {
  events: AuditEvent[];
  append(entry: Omit<AuditEvent, 'hash' | 'prevHash' | 'eventId'>): AuditEvent;
  verify(): { ok: boolean; lastEventId: string; count: number; mismatchAt?: number };
  walk(): AuditEvent[];
}

export function createLedger(): LedgerStore {
  const events: AuditEvent[] = [];
  const GENESIS = '0'.repeat(64);

  return {
    events,
    append(entry) {
      const prevHash = events.length ? events[events.length - 1]!.hash : GENESIS;
      const event: AuditEvent = {
        ...entry,
        eventId: randomId('evt'),
        prevHash,
        hash: '',
      };
      event.hash = computeEventHash(prevHash, event);
      events.push(event);
      return event;
    },
    verify() {
      let prev = GENESIS;
      for (let i = 0; i < events.length; i++) {
        const ev = events[i]!;
        const recomputed = computeEventHash(prev, ev);
        if (recomputed !== ev.hash) {
          return { ok: false, lastEventId: ev.eventId, count: events.length, mismatchAt: i + 1 };
        }
        prev = ev.hash;
      }
      return { ok: true, lastEventId: events.length ? events[events.length - 1]!.hash : GENESIS, count: events.length };
    },
    walk() {
      return [...events];
    },
  };
}

export function createAuditService(store: LedgerStore) {
  return jsonServer([
    { method: 'GET', path: /^\/service$/, handler: health('audit-ledger') },
    {
      method: 'POST',
      path: /^\/events$/,
      handler: async (ctx) => {
        const body = await ctx.json<Omit<AuditEvent, 'hash' | 'prevHash' | 'eventId'>>();
        if (!body || !body.actor || !body.action) throw new Error('bad_request');
        const event = store.append(body);
        return ctx.send(201, { event, chainHash: event.hash });
      },
    },
    {
      method: 'GET',
      path: /^\/events$/,
      handler: (ctx) => {
        const limit = Math.min(Number(ctx.query.get('limit') ?? 100), 1000);
        return ctx.jsonOk({ events: store.walk().slice(-limit) });
      },
    },
    {
      method: 'GET',
      path: /^\/verify$/,
      handler: (ctx) => ctx.jsonOk({ ...store.verify(), ts: new Date().toISOString() }),
    },
    {
      // demo convenience: prime the ledger with a few canonical entries
      method: 'POST',
      path: /^\/seed$/,
      handler: (ctx) => {
        const seed = [
          { ts: new Date().toISOString(), actor: 'system', role: 'Admin', action: 'graph.ingested', objectType: 'graph', objectId: 'g-2026-09-23-001', tenantId: 'T-001', ip: '127.0.0.1', userAgent: 'ps3d-bootstrap', mfa: false, meta: { nodes: 19, edges: 30 } },
          { ts: new Date(Date.now() - 1000).toISOString(), actor: 'system', role: 'Admin', action: 'path.computed', objectType: 'attack_path', objectId: 'job-demo-1', tenantId: 'T-001', ip: '127.0.0.1', userAgent: 'ps3d-bootstrap', mfa: false, meta: { paths: 5 } },
        ];
        const appended = seed.map((s) => store.append(s));
        return ctx.jsonOk({ seeded: appended.length, chainHash: appended[appended.length - 1]!.hash });
      },
    },
  ]);
}

export function createInMemoryLedger(): LedgerStore {
  return createLedger();
}

export async function main(): Promise<void> {
  const port = Number(process.env.AUDIT_PORT) || 8083;
  const store = createInMemoryLedger();
  const server = createAuditService(store);
  server.listen(port, '0.0.0.0', () => console.log(`[audit-ledger] listening on :${port}`));
}

if (isMain(import.meta.url)) {
  void main();
}