import type {
  BHNode,
  BHEdge,
  Incident,
  IntelItem,
  NodeHealth,
  RegionState,
  SecurityAlert,
  Severity,
  SocMetrics,
  SocState,
  StreamLine,
} from '../../types';
import { mulberry32, pick, randInt } from '../../lib/rng';
import {
  ALERT_TEMPLATES,
  ANALYSTS,
  INCIDENT_EVIDENCE,
  INCIDENT_TITLES,
  INTEL_TEMPLATES,
  MITRE_CATALOG,
  REGIONS,
  SEVERITY_SLA_MIN,
  defaultAlertSummary,
  makeTasks,
} from './templates';
import { generateLogs } from './logStore';
import { SimBus } from './simBus';

const SIM_SEED = 0x50c0;

let uid = 0;
const nextId = (p: string) => `${p}-${Date.now().toString(36)}-${++uid}`;

function mkSeverity(rng: () => number, base: Severity): Severity {
  const roll = rng();
  if (roll > 0.86) return base;
  if (roll > 0.72) return base === 'critical' ? 'high' : base === 'low' ? 'medium' : base;
  return base;
}

export class SocSim {
  private bus = new SimBus();
  private nodes: BHNode[] = [];
  private edges: BHEdge[] = [];
  private users: string[] = [];
  private computers: string[] = [];
  private servers: string[] = [];
  private rng = mulberry32(SIM_SEED);
  private timer: number | null = null;
  private revertQueue: { nodeId: string; until: number }[] = [];
  private nodePool: string[] = [];

  readonly on = this.bus.on.bind(this.bus);
  readonly off = this.bus.off.bind(this.bus);

  configure(nodes: BHNode[], edges: BHEdge[]): void {
    this.nodes = nodes;
    this.edges = edges;
    this.users = nodes.filter((n) => n.kind === 'user').map((n) => n.id);
    this.computers = nodes.filter((n) => n.kind === 'computer').map((n) => n.id);
    this.servers = nodes
      .filter((n) => n.kind === 'computer' && /-(DC|SQL|WEB|FILE|APP|MAIL|BACKUP|ITSRV|VAULT)/.test(n.label))
      .map((n) => n.id);
    this.nodePool = [...this.users, ...this.computers, ...this.servers];
  }

  start(): void {
    if (this.timer != null) return;
    this.timer = window.setInterval(() => this.tick(), 1400);
  }

  stop(): void {
    if (this.timer != null) {
      window.clearInterval(this.timer);
      this.timer = null;
    }
  }

  dispose(): void {
    this.stop();
    this.bus.clear();
  }

  seed(): SocState {
    const now = Date.now();
    const alerts = this.seedAlerts(now);
    const incidents = this.seedIncidents(now, alerts);
    const intel = this.seedIntel(now);
    const nodeHealth = this.seedNodeHealth();
    const regions = this.seedRegions();
    const stream: StreamLine[] = [];
    const logs = generateLogs(this.nodes, 520);

    for (const a of [...alerts].slice(-3).reverse()) {
      stream.push({
        id: nextId('S'),
        ts: a.ts,
        level: a.severity,
        text: `${a.source} · ${a.title}`,
        module: 'alerts',
      });
    }

    return {
      alerts,
      incidents,
      intel,
      nodeHealth,
      stream,
      metrics: { eps: 286, alertRate: 3.2, exposure: Math.round(this.nodePool.length * 0.14), coverage: 97.4 },
      epsHistory: this.sparkFill(),
      alertRateHistory: this.sparkFillRate(),
      regions,
      trafficEdges: [],
      logs,
    };
  }

  private seedAlerts(now: number): SecurityAlert[] {
    const out: SecurityAlert[] = [];
    const statuses: SecurityAlert['status'][] = ['new', 'new', 'triaging', 'triaging', 'escalated'];
    const count = 15;
    for (let i = 0; i < count; i++) {
      const t = pick(this.rng, ALERT_TEMPLATES);
      const age = 4 + Math.floor(this.rng() * 52);
      const a = this.buildAlert(t, now - age * 60_000, out.length);
      a.status = i < 2 ? 'closed' : statuses[i % statuses.length];
      out.push(a);
    }
    return out.sort((x, y) => y.ts - x.ts);
  }

  private buildAlert(t: (typeof ALERT_TEMPLATES)[number], ts: number, index: number): SecurityAlert {
    const sev = mkSeverity(this.rng, t.baseSeg);
    const assets = this.pickAssets(t.assetsOf, 1 + randInt(this.rng, 0, 2));
    const id = nextId('ALERT');
    const mitre = MITRE_CATALOG[t.mitreId];
    return {
      id,
      ts,
      severity: sev,
      title: t.title,
      description: t.description,
      source: t.source,
      mitreId: t.mitreId,
      mitreName: mitre?.name ?? t.mitreId,
      technique: `${t.mitreId} · ${mitre?.name ?? ''}`,
      assets,
      status: 'new',
      slaMinutes: SEVERITY_SLA_MIN[sev],
      raw: `raw.${index}`,
    };
  }

  private pickAssets(kinds: NonNullable<SecurityAlert['assets']>, count: number): string[] {
    const out: string[] = [];
    for (let i = 0; i < count && i < kinds.length * 2; i++) {
      const kind = kinds[i % kinds.length];
      const pool = kind === 'user' ? this.users : kind === 'group' ? [] : kind === 'domain' ? [] : this.computers;
      if (pool.length === 0) continue;
      out.push(pick(this.rng, pool));
    }
    return out.slice(0, count);
  }

  private seedIncidents(now: number, alerts: SecurityAlert[]): Incident[] {
    const critical = alerts.find((a) => a.severity === 'critical') ?? alerts.find((a) => a.severity === 'high');
    const escalated = alerts.filter((a) => a.status === 'escalated');
    const source = critical ?? escalated[0] ?? alerts[0];
    const n: Incident[] = [this.buildIncident(now, source, 0)];

    for (let i = 1; i < 4; i++) {
      const a = alerts[i * 3];
      if (a) n.push(this.buildIncident(now - i * 7 * 60_000, a, i));
    }
    return n;
  }

  private buildIncident(now: number, source: SecurityAlert, index: number): Incident {
    const id = `INC-${nextId('x').slice(-5)}`;
    const created = now - randInt(this.rng, 4, 42) * 60_000;
    const tasks = makeTasks([index + 1]);
    const owner = ANALYSTS[index % ANALYSTS.length];
    const status: Incident['status'] = index === 0 ? 'investigating' : 'new';
    const events: Incident['events'] = [
      { ts: created, actor: 'SiemEngine', action: 'Alert created', note: source.title },
      { ts: created + 2 * 60_000, actor: owner, action: 'Assigned', note: `Owned by ${owner}` },
    ];
    if (status === 'investigating') {
      events.push({ ts: now - 3 * 60_000, actor: owner, action: 'Isolation requested', note: 'Waiting approval' });
    }
    return {
      id,
      title: INCIDENT_TITLES[index % INCIDENT_TITLES.length],
      severity: index === 0 ? 'critical' : source.severity,
      status,
      description: `Incident opened from correlated alerts. Primary signal: ${source.title} (${source.mitreId}).`,
      createdAt: created,
      owner,
      alertIds: [source.id],
      assets: source.assets,
      tasks,
      events,
      evidence: [pick(this.rng, INCIDENT_EVIDENCE)],
      notes: '',
    };
  }

  private seedIntel(now: number): IntelItem[] {
    const count = Math.min(8, INTEL_TEMPLATES.length);
    return INTEL_TEMPLATES.slice(0, count).map((t, i) => ({
      ...t,
      id: nextId('IOC'),
      publishedAt: now - (i + 1) * 4 * 60 * 60 * 1000,
    }));
  }

  private seedNodeHealth(): Record<string, NodeHealth> {
    const health: Record<string, NodeHealth> = {};
    const assign = (id: string, h: NodeHealth) => (health[id] = h);

    const web = this.servers.find((s) => s.endsWith('CORP-WEB01'));
    if (web) assign(web, 'critical');
    const sql = this.servers.find((s) => s.endsWith('CORP-SQL01'));
    if (sql) assign(sql, 'warning');
    const backup = this.servers.find((s) => s.endsWith('CORP-BACKUP01'));
    if (backup) assign(backup, 'investigation');
    const helpdesk = this.users.find((u) => u.endsWith('svc-helpdesk'));
    if (helpdesk) assign(helpdesk, 'investigation');
    const ws = this.computers.find((c) => c.endsWith('CORP-WS-007'));
    if (ws) assign(ws, 'offline');
    const file = this.servers.find((s) => s.endsWith('CORP-FILE01'));
    if (file) assign(file, 'warning');

    for (let i = 0; i < 3 && this.nodePool.length; i++) {
      const n = pick(this.rng, this.nodePool);
      if (!health[n]) assign(n, 'warning');
    }
    return health;
  }

  private seedRegions(): Record<string, RegionState> {
    const out: Record<string, RegionState> = {};
    for (const r of REGIONS) {
      out[r.id] = { ...r, status: 'healthy' };
    }
    out['eu-west'] = { ...out['eu-west'], status: 'warning', online: 24 };
    out['cloud-azure'] = { ...out['cloud-azure'], status: 'warning', online: 50 };
    return out;
  }

  private sparkFill(): number[] {
    const arr: number[] = [];
    for (let i = 0; i < 40; i++) arr.push(240 + Math.floor(this.rng() * 90));
    return arr;
  }

  private sparkFillRate(): number[] {
    const arr: number[] = [];
    for (let i = 0; i < 40; i++) arr.push(2 + Math.round(this.rng() * 40) / 10);
    return arr;
  }

  // ---------------------------------------------------------------- tick

  private tick(): void {
    const now = Date.now();

    if (this.rng() < 0.52) this.emitAlert(now);
    else if (this.rng() < 0.42) this.emitIntel(now);

    if (this.rng() < 0.5) this.emitTopologyEvent(now);
    if (this.rng() < 0.6) this.emitTraffic();
    if (this.rng() < 0.34) this.emitRegionEvent();
    if (this.rng() < 0.24) this.emitIncidentUpdate(now);

    this.emitMetrics();
    this.drainReverts(now);
  }

  private emitAlert(now: number): void {
    const t = pick(this.rng, ALERT_TEMPLATES);
    const a = this.buildAlert(t, now, Math.floor(this.rng() * 1000));
    this.bus.emit('alert', a);
    this.bus.emit('stream', {
      id: nextId('S'),
      ts: now,
      level: a.severity,
      text: `${a.source} · ${defaultAlertSummary(a)}`,
      module: 'alerts',
    });
  }

  private emitIntel(now: number): void {
    const t = pick(this.rng, INTEL_TEMPLATES);
    const item: IntelItem = { ...t, id: nextId('IOC'), publishedAt: now };
    this.bus.emit('intel', item);
    this.bus.emit('stream', {
      id: nextId('S'),
      ts: now,
      level: 'info',
      text: `Threat intel · ${item.title}`,
      module: 'intel',
    });
  }

  private emitTopologyEvent(now: number): void {
    if (this.nodePool.length === 0) return;
    const nodeId = pick(this.rng, this.nodePool);
    const roll = this.rng();
    const health: NodeHealth = roll > 0.62 ? 'warning' : roll > 0.34 ? 'investigation' : roll > 0.18 ? 'critical' : 'quarantined';
    this.bus.emit('topology', { nodeId, health });
    this.revertQueue.push({ nodeId, until: now + 12_000 + randInt(this.rng, 0, 14_000) });
    this.bus.emit('stream', {
      id: nextId('S'),
      ts: now,
      level: health === 'critical' || health === 'quarantined' ? 'high' : health === 'warning' ? 'medium' : 'low',
      text: `Topology · ${nodeId.replace('COMPUTER-', '').replace('USER-', '')} → ${health}`,
      module: 'topology',
    });
  }

  private emitTraffic(): void {
    if (this.edges.length === 0) return;
    const edge = pick(this.rng, this.edges);
    this.bus.emit('traffic', { sourceId: edge.source, targetId: edge.target, edgeId: edge.id });
  }

  private emitRegionEvent(): void {
    const r = pick(this.rng, REGIONS);
    const status: NodeHealth = this.rng() > 0.7 ? 'warning' : this.rng() > 0.55 ? 'critical' : 'healthy';
    const online = Math.max(0, Math.min(r.sensors, r.online + randInt(this.rng, -2, 3)));
    this.bus.emit('region', {
      id: r.id,
      patch: { status, online, impact: status === 'critical' ? randInt(this.rng, 3, 9) : status === 'warning' ? 1 : 0 },
    });
  }

  private emitIncidentUpdate(now: number): void {
    const source = this.buildAlert(pick(this.rng, ALERT_TEMPLATES), now, Math.floor(this.rng() * 1000));
    const existing = this.buildIncident(now, source, Math.floor(this.rng() * 5));
    existing.id = nextId('INC');
    existing.createdAt = now - 2 * 60_000;
    existing.status = 'investigating';
    existing.events = [
      { ts: now - 2 * 60_000, actor: 'SiemEngine', action: 'Alert created', note: existing.title },
      { ts: now, actor: ANALYSTS[1], action: 'Verification started', note: 'Correlating with threat-intel feed' },
    ];
    this.bus.emit('incident', existing);
  }

  private emitMetrics(): void {
    const eps = Math.max(120, Math.round(240 + (this.rng() - 0.5) * 180));
    const alertRate = Math.max(0.5, Math.round((2.4 + this.rng() * 4.2) * 10) / 10);
    const coverage = Math.min(99.9, Math.round((96 + this.rng() * 3.9) * 10) / 10);
    const metrics: SocMetrics = {
      eps,
      alertRate,
      exposure: Math.round(this.nodePool.length * (0.12 + this.rng() * 0.05)),
      coverage,
      mtb: 41 + Math.floor(this.rng() * 12),
      mttr: 87 + Math.floor(this.rng() * 46),
    };
    this.bus.emit('metric', metrics);
  }

  private drainReverts(now: number): void {
    const due = this.revertQueue.filter((r) => r.until <= now);
    if (due.length === 0) return;
    this.revertQueue = this.revertQueue.filter((r) => r.until > now);
    for (const r of due) {
      this.bus.emit('topology', { nodeId: r.nodeId, health: 'healthy' });
    }
  }
}

export const socSim = new SocSim();