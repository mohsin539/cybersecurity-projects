import { useEffect, useMemo, useState } from 'react';
import type { Incident, SecurityAlert, Severity, SocState } from '../../types';
import { ANALYSTS, INCIDENT_EVIDENCE, MITRE_CATALOG, makeTasks } from '../../lib/sim/templates';

interface AlertWorkbenchProps {
  state: SocState;
  dispatch: React.Dispatch<import('../../state/socStore').SocAction>;
}

const SEV_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const SEV_COLOR: Record<Severity, string> = {
  critical: '#FF1744',
  high: '#FF6E40',
  medium: '#FFB300',
  low: '#3EC6FF',
  info: '#9aa7c7',
};

const STATUS_LABEL: Record<SecurityAlert['status'], string> = {
  new: 'New',
  triaging: 'Triaging',
  escalated: 'Escalated',
  dismissed: 'Dismissed',
  incident: 'Incident',
  closed: 'Closed',
};

function timeAgo(ts: number): string {
  const d = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (d < 60) return `${d}s`;
  if (d < 3600) return `${Math.floor(d / 60)}m`;
  if (d < 86400) return `${Math.floor(d / 3600)}h`;
  return `${Math.floor(d / 86400)}d`;
}

function fmtSla(ms: number): { text: string; cls: string } {
  if (ms < 0) return { text: 'BREACH', cls: 'sla-breach' };
  const total = ms;
  const mins = Math.floor(total / 60000);
  const secs = Math.floor((total % 60000) / 1000);
  const text = mins > 0 ? `${mins}m ${secs.toString().padStart(2, '0')}s` : `${secs}s`;
  const cls = total < 5 * 60 * 1000 ? 'sla-breach' : total < 30 * 60 * 1000 ? 'sla-warn' : 'sla-ok';
  return { text, cls };
}

function makeIncidentFromAlert(a: SecurityAlert, seq: number): Incident {
  return {
    id: `INC-${Date.now().toString(36)}-${seq}`,
    title: a.title,
    severity: a.severity,
    status: 'new',
    description: `Incident opened from alert ${a.id}. ${a.description}`,
    createdAt: Date.now(),
    owner: ANALYSTS[seq % ANALYSTS.length],
    alertIds: [a.id],
    assets: a.assets,
    tasks: makeTasks([seq + 1]),
    events: [
      { ts: a.ts, actor: 'SiemEngine', action: 'Alert created', note: a.title },
      { ts: Date.now(), actor: 'SOC Console', action: 'Incident raised', note: `Linked ${a.id}` },
    ],
    evidence: [INCIDENT_EVIDENCE[seq % INCIDENT_EVIDENCE.length]],
    notes: '',
  };
}

export function AlertWorkbench({ state, dispatch }: AlertWorkbenchProps) {
  const [now, setNow] = useState(Date.now());
  const [sevFilter, setSevFilter] = useState<Set<Severity>>(new Set(SEV_ORDER));
  const [statusFilter, setStatusFilter] = useState<Set<SecurityAlert['status']>>(
    new Set(['new', 'triaging', 'escalated']),
  );
  const [q, setQ] = useState('');
  const [onlyCritical, setOnlyCritical] = useState(false);
  const [lastId, setLastId] = useState<string | null>(null);

  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(t);
  }, []);

  useEffect(() => {
    const latest = state.alerts[0];
    if (latest && latest.id !== lastId) setLastId(latest.id);
  }, [state.alerts.length]);

  const bySeverity = useMemo(() => {
    const m = new Map<Severity, number>();
    for (const s of SEV_ORDER) m.set(s, 0);
    for (const a of state.alerts) m.set(a.severity, (m.get(a.severity) ?? 0) + 1);
    return m;
  }, [state.alerts]);

  const rows = useMemo(() => {
    const qq = q.trim().toLowerCase();
    return state.alerts
      .filter((a) => sevFilter.has(a.severity))
      .filter((a) => statusFilter.has(a.status))
      .filter((a) => !onlyCritical || a.severity === 'critical')
      .filter((a) => {
        if (!qq) return true;
        return `${a.title} ${a.source} ${a.mitreId} ${a.mitreName} ${a.assets.join(' ')}`.toLowerCase().includes(qq);
      })
      .slice(0, 120);
  }, [state.alerts, sevFilter, statusFilter, q, onlyCritical]);

  const toggleSev = (s: Severity) => {
    setSevFilter((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  };

  const toggleStatus = (s: SecurityAlert['status']) => {
    setStatusFilter((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  };

  const triage = (a: SecurityAlert) => {
    dispatch({
      type: 'UPDATE_ALERT',
      id: a.id,
      patch: { status: 'triaging', assignee: ANALYSTS[(a.assets.length + a.mitreId.length) % ANALYSTS.length] },
    });
    dispatch({
      type: 'PUSH_STREAM',
      line: { id: `S-${Date.now()}`, ts: Date.now(), level: 'info', text: `Triage · ${a.id} assigned`, module: 'alerts' },
    });
  };

  const escalate = (a: SecurityAlert) => {
    dispatch({ type: 'UPDATE_ALERT', id: a.id, patch: { status: 'escalated' } });
    dispatch({
      type: 'PUSH_STREAM',
      line: { id: `S-${Date.now()}`, ts: Date.now(), level: 'high', text: `Escalated · ${a.title}`, module: 'alerts' },
    });
  };

  const dismiss = (a: SecurityAlert) => {
    dispatch({ type: 'UPDATE_ALERT', id: a.id, patch: { status: 'dismissed', assignee: 'SOC Console' } });
  };

  const openIncident = (a: SecurityAlert) => {
    const inc = makeIncidentFromAlert(a, state.incidents.length);
    dispatch({ type: 'ADD_INCIDENT', incident: inc });
    dispatch({ type: 'UPDATE_ALERT', id: a.id, patch: { status: 'incident' } });
    dispatch({
      type: 'PUSH_STREAM',
      line: { id: `S-${Date.now()}`, ts: Date.now(), level: inc.severity, text: `Incident raised · ${inc.id} ${inc.title}`, module: 'incidents' },
    });
  };

  return (
    <div className="module-page">
      <div className="module-head">
        <div>
          <h1>Alert Triage Workbench</h1>
          <p className="module-sub">Live queue with SLA pressure, MITRE ATT&CK mapping and triage actions</p>
        </div>
        <div className="module-head-stats">
          {SEV_ORDER.map((s) => (
            <button key={s} className={`sev-pill ${sevFilter.has(s) ? '' : 'off'}`} onClick={() => toggleSev(s)}>
              <i style={{ background: SEV_COLOR[s] }} />
              {s} {bySeverity.get(s) ?? 0}
            </button>
          ))}
        </div>
      </div>

      <div className="card workbench-toolbar">
        <input
          className="query-input grow"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Filter by title, source, MITRE id, asset…"
          aria-label="Filter alerts"
        />
        {(['new', 'triaging', 'escalated', 'dismissed', 'closed', 'incident'] as const).map((s) => (
          <button key={s} className={`chip-btn ${statusFilter.has(s) ? 'on' : ''}`} onClick={() => toggleStatus(s)}>
            {STATUS_LABEL[s]}
          </button>
        ))}
        <button className={`chip-btn ${onlyCritical ? 'on danger' : ''}`} onClick={() => setOnlyCritical((v) => !v)}>
          Critical only
        </button>
      </div>

      <div className="alert-table card">
        <div className="alert-table-head">
          <span>Severity</span>
          <span>Time</span>
          <span>Detection</span>
          <span>Source</span>
          <span>Technique</span>
          <span>Assets</span>
          <span>Status</span>
          <span>SLA</span>
          <span>Actions</span>
        </div>
        {rows.length === 0 && <div className="table-empty">No alerts match current filters</div>}
        {rows.map((a) => {
          const rem = a.ts + a.slaMinutes * 60_000 - now;
          const sla = fmtSla(rem);
          const fresh = a.id === lastId;
          const mitre = MITRE_CATALOG[a.mitreId];
          return (
            <div className={`alert-row ${fresh ? 'fresh' : ''}`} key={a.id}>
              <span className={`sev-badge sev-${a.severity}`}>{a.severity}</span>
              <span className="row-time" title={new Date(a.ts).toLocaleString()}>{timeAgo(a.ts)}</span>
              <span className="row-detection">
                <b>{a.title}</b>
                <small>{a.description}</small>
              </span>
              <span className="row-source">{a.source}</span>
              <span className="row-technique">
                <span className="tech-badge">{a.mitreId}</span>
                <small>{mitre ? `${mitre.name} · ${mitre.tactic.split(' /')[0]}` : a.mitreName}</small>
              </span>
              <span className="row-assets">{a.assets.slice(0, 2).join(', ')}</span>
              <span className={`status-badge status-${a.status}`}>{STATUS_LABEL[a.status]}</span>
              <span className={`sla ${sla.cls}`}>{sla.text}</span>
              <span className="row-actions">
                {a.status === 'new' && (
                  <button className="btn sm" onClick={() => triage(a)}>Triage</button>
                )}
                {a.status === 'triaging' && (
                  <button className="btn sm" onClick={() => escalate(a)}>Escalate</button>
                )}
                {a.status !== 'dismissed' && a.status !== 'closed' && a.status !== 'incident' && (
                  <>
                    <button className="btn sm primary" onClick={() => openIncident(a)}>Incident</button>
                    <button className="btn sm ghost" onClick={() => dismiss(a)}>Dismiss</button>
                  </>
                )}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}