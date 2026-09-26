import type { BHNode, LogEntry, Severity } from '../../types';
import { mulberry32, pick } from '../../lib/rng';
import { MITRE_CATALOG } from './templates';

const LOG_SEED = 0x10c4;

const LOG_SOURCES: { source: string; eventIds: string[]; sev: Severity[]; words: string[] }[] = [
  {
    source: 'auth',
    eventIds: ['4625', '4624', '4740', '4776'],
    sev: ['low', 'low', 'medium', 'info'],
    words: ['failed logon', 'successful logon', 'account locked out', 'credential validation'],
  },
  {
    source: 'windows',
    eventIds: ['4688', '7045', '1102', '4720', '4732', '6416'],
    sev: ['info', 'medium', 'low', 'low', 'high', 'medium'],
    words: ['process creation', 'service installed', 'audit log cleared', 'user created', 'member added', 'new device'],
  },
  {
    source: 'firewall',
    eventIds: ['5156', '5157', '5906'],
    sev: ['info', 'high', 'medium'],
    words: ['connection allowed', 'connection blocked', 'traffic policy applied'],
  },
  {
    source: 'edr',
    eventIds: ['EDR-1001', 'EDR-2042', 'EDR-3091'],
    sev: ['high', 'critical', 'medium'],
    words: ['suspicious process', 'memory dump attempt', 'behavioral anomaly'],
  },
  {
    source: 'waf',
    eventIds: ['WAF-403', 'WAF-500'],
    sev: ['medium', 'high'],
    words: ['request blocked', 'signature match'],
  },
  {
    source: 'web',
    eventIds: ['IIS-200', 'IIS-404', 'IIS-500'],
    sev: ['info', 'low', 'medium'],
    words: ['http request', 'route not found', 'server error'],
  },
  {
    source: 'netflow',
    eventIds: ['FLOW-CONN'],
    sev: ['info', 'medium'],
    words: ['egress transfer', 'tor exit observed', 'dns tunnel anomaly'],
  },
];

function hostFor(rng: () => number, servers: string[], workstations: string[]): string {
  return rng() < 0.82
    ? pick(rng, workstations)
    : pick(rng, servers);
}

export function generateLogs(nodes: BHNode[], count: number): LogEntry[] {
  const rng = mulberry32(LOG_SEED);
  const users = nodes.filter((n) => n.kind === 'user');
  const servers = nodes.filter((n) => n.kind === 'computer' && /-(DC|SQL|WEB|FILE|APP|MAIL|BACKUP|ITSRV|VAULT)/.test(n.label));
  const workstations = nodes.filter((n) => n.kind === 'computer' && n.label.startsWith('CORP-WS'));
  const serverNames = servers.map((n) => n.label).concat(['edge-proxy-01', 'vpn-gw-01']);
  const wsNames = workstations.map((n) => n.label);

  const now = Date.now();
  const out: LogEntry[] = [];
  const ids = Math.floor(now / 1000);

  for (let i = 0; i < count; i++) {
    const src = pick(rng, LOG_SOURCES);
    const ts = now - Math.floor(rng() * 24 * 60 * 60 * 1000) - Math.floor(rng() * 1000);
    const user = users.length ? pick(rng, users).label : 'unknown';
    const host = hostFor(rng, serverNames, wsNames);
    const eventId = pick(rng, src.eventIds);
    const severity = pick(rng, src.sev);
    const word = pick(rng, src.words);
    const mitreId = severity === 'high' || severity === 'critical' ? pick(rng, Object.keys(MITRE_CATALOG)) : undefined;
    out.push({
      id: `L-${ids}-${i}`,
      ts,
      source: src.source,
      host,
      user,
      eventId,
      message: `[${src.source}] ${eventId} ${word} host=${host} user=${user}`,
      severity,
      mitreId,
    });
  }

  return out.sort((a, b) => b.ts - a.ts).slice(0, count);
}

export interface QueryToken {
  key?: string;
  value: string;
}

export function tokenizeQuery(query: string): QueryToken[] {
  const parts = query.trim().split(/\s+/);
  const tokens: QueryToken[] = [];
  for (const p of parts) {
    const eq = p.indexOf('=');
    if (eq > 0) tokens.push({ key: p.slice(0, eq).toLowerCase(), value: p.slice(eq + 1).toLowerCase() });
    else tokens.push({ value: p.toLowerCase() });
  }
  return tokens;
}

export function runQuery(logs: LogEntry[], query: string): LogEntry[] {
  const tokens = tokenizeQuery(query);
  if (tokens.length === 0) return [];
  return logs.filter((l) => {
    for (const t of tokens) {
      if (t.key) {
        let fieldValue = '';
        switch (t.key) {
          case 'source':
          case 'src':
            fieldValue = l.source;
            break;
          case 'eventid':
            fieldValue = l.eventId;
            break;
          case 'user':
            fieldValue = l.user;
            break;
          case 'host':
            fieldValue = l.host;
            break;
          case 'severity':
            fieldValue = l.severity;
            break;
          case 'mitre':
            fieldValue = l.mitreId ?? '';
            break;
          default:
            fieldValue = `${l.message} ${l.source} ${l.eventId}`;
        }
        if (!fieldValue.toLowerCase().includes(t.value)) return false;
      } else {
        const hay = `${l.message} ${l.host} ${l.user} ${l.source}`.toLowerCase();
        if (!hay.includes(t.value)) return false;
      }
    }
    return true;
  });
}

export const PRESET_QUERIES: { name: string; query: string }[] = [
  { name: 'Failed logons', query: 'source=auth eventid=4625' },
  { name: 'Critical EDR hits', query: 'source=edr severity=critical' },
  { name: 'Process creation on DC', query: 'eventid=4688 host=corp-dc01' },
  { name: 'PowerShell execution', query: 'source=windows mitre=T1059' },
  { name: 'Privileged group changes', query: 'eventid=4732' },
  { name: 'Blocked connections', query: 'source=firewall eventid=5157' },
  { name: 'Service installs', query: 'eventid=7045' },
  { name: 'WAF blocks', query: 'source=waf' },
];