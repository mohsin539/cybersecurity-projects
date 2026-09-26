import { useMemo } from 'react';
import type { RegionState, Severity, SocState } from '../../types';
import { REGIONS } from '../../lib/sim/templates';

interface BlanketMapModuleProps {
  state: SocState;
  onGoto: (module: 'incidents') => void;
}

const REGION_STATUS_COLOR: Record<string, string> = {
  healthy: '#00E676',
  warning: '#FFB300',
  critical: '#FF1744',
  offline: '#9E9E9E',
  investigation: '#2979FF',
  quarantined: '#7E57C2',
};

const SEV_COLOR: Record<Severity, string> = {
  critical: '#FF1744',
  high: '#FF6E40',
  medium: '#FFB300',
  low: '#3EC6FF',
  info: '#53F6FF',
};

function arcFor(seed: number): { from: RegionState; to: RegionState; severity: Severity } | null {
  const a = REGIONS[seed % REGIONS.length];
  const b = REGIONS[(seed * 7 + 3) % REGIONS.length];
  if (!a || !b || a.id === b.id) return null;
  const severity: Severity = ['critical', 'high', 'medium', 'low'][seed % 4] as Severity;
  return { from: a as RegionState, to: b as RegionState, severity };
}

export function BlanketMapModule({ state, onGoto }: BlanketMapModuleProps) {
  const regions = useMemo(() => {
    const entries = Object.values(state.regions);
    return entries.length ? entries : (REGIONS.map((r) => ({ ...r, status: 'healthy' })) as RegionState[]);
  }, [state.regions]);

  const totals = useMemo(() => {
    const sensors = regions.reduce((s, r) => s + r.sensors, 0);
    const online = regions.reduce((s, r) => s + r.online, 0);
    return { sensors, online, coverage: sensors ? (online / sensors) * 100 : 0 };
  }, [regions]);

  const arcs = useMemo(() => {
    const critical = state.incidents.filter((i) => i.severity === 'critical' || i.severity === 'high');
    const out: { from: RegionState; to: RegionState; severity: Severity; key: string }[] = [];
    critical.slice(-8).forEach((inc, i) => {
      const seed = Math.abs(inc.id.split('').reduce((a, c) => a + c.charCodeAt(0), 0));
      const arc = arcFor(seed + i);
      if (arc) out.push({ ...arc, key: inc.id });
    });
    return out;
  }, [state.incidents]);

  const alertsPerMin = state.metrics.alertRate;

  return (
    <div className="module-page blanket-module">
      <div className="module-head">
        <div>
          <h1>Live Blanket Map</h1>
          <p className="module-sub">Sensor coverage and active attack propagation across monitored regions & clouds</p>
        </div>
        <button className="btn" onClick={() => onGoto('incidents')}>
          Open incident center →
        </button>
      </div>

      <div className="kpi-row">
        <div className="card kpi">
          <span className="kpi-value">{totals.sensors}</span>
          <span className="kpi-label">Sensors deployed</span>
        </div>
        <div className="card kpi">
          <span className="kpi-value good">{totals.online}</span>
          <span className="kpi-label">Online</span>
        </div>
        <div className="card kpi">
          <span className={`kpi-value ${totals.coverage > 99 ? 'good' : 'warn'}`}>{totals.coverage.toFixed(1)}%</span>
          <span className="kpi-label">Coverage</span>
        </div>
        <div className="card kpi">
          <span className="kpi-value danger">{alertsPerMin.toFixed(1)}/min</span>
          <span className="kpi-label">Alert ingress</span>
        </div>
        <div className="card kpi">
          <span className={`kpi-value ${arcs.length ? 'warn' : ''}`}>{arcs.length}</span>
          <span className="kpi-label">Active attack paths</span>
        </div>
      </div>

      <div className="blanket-layout">
        <div className="card blanket-map-card">
          <svg className="blanket-map" viewBox="0 0 100 70" preserveAspectRatio="xMidYMid meet" aria-label="SOC blanket map">
            {Array.from({ length: 11 }, (_, i) => (
              <line key={`v${i}`} x1={i * 10} y1="0" x2={i * 10} y2="70" className="bm-grid" />
            ))}
            {Array.from({ length: 8 }, (_, i) => (
              <line key={`h${i}`} x1="0" y1={i * 10} x2="100" y2={i * 10} className="bm-grid" />
            ))}

            {arcs.map((a) => {
              const c = SEV_COLOR[a.severity];
              const mx = (a.from.x + a.to.x) / 2;
              const my = Math.min(a.from.y, a.to.y) - 6;
              return (
                <g key={a.key}>
                  <path
                    d={`M ${a.from.x} ${a.from.y} Q ${mx} ${my} ${a.to.x} ${a.to.y}`}
                    className="bm-arc"
                    pathLength={1}
                    stroke={c}
                  />
                  <circle cx={a.to.x} cy={a.to.y} r="0.55" className="bm-burst" fill={c} />
                </g>
              );
            })}

            {regions.map((r) => {
              const color = REGION_STATUS_COLOR[r.status] ?? '#9E9E9E';
              const ratio = r.sensors ? r.online / r.sensors : 0;
              const r2 = 1 + r.impact * 0.4;
              return (
                <g key={r.id}>
                  <circle cx={r.x} cy={r.y} r={r2 + 1.4} className="bm-halo" fill={color} opacity={r.impact ? 0.28 : 0.08} />
                  <circle cx={r.x} cy={r.y} r={0.5 + ratio * 0.9} fill={color} className="bm-region" />
                  <text x={r.x} y={r.y + 3.1} className="bm-label" textAnchor="middle">
                    {r.label} · {r.online}/{r.sensors}
                  </text>
                </g>
              );
            })}
            <text x="4" y="67" className="bm-foot">
              Live coverage grid · simulated global SOC estate
            </text>
          </svg>

          <div className="blanket-legend">
            {(['healthy', 'warning', 'critical', 'offline', 'investigation'] as const).map((s) => (
              <span className="blanket-legend-item" key={s}>
                <i style={{ background: REGION_STATUS_COLOR[s] }} />
                {s}
              </span>
            ))}
            <span className="blanket-legend-item">
              <i className="arc-sample" style={{ borderTopColor: SEV_COLOR.critical }} />
              attack arc
            </span>
          </div>
        </div>

        <div className="blanket-side">
          <div className="card panic-card">
            <div className="panel-head">
              <h2>Current posture</h2>
            </div>
            <div className="panel-body">
              <div className="posture-line">
                <span>Critical alerts open</span>
                <b className="tone-danger">{state.alerts.filter((a) => a.severity === 'critical' && a.status === 'new').length}</b>
              </div>
              <div className="posture-line">
                <span>Active incidents</span>
                <b>{state.incidents.filter((i) => i.status !== 'closed').length}</b>
              </div>
              <div className="posture-line">
                <span>EPS ingress</span>
                <b>{Math.round(state.metrics.eps)}</b>
              </div>
              <div className="posture-line">
                <span>Mean time to respond</span>
                <b>{state.metrics.mttr ?? '—'} m</b>
              </div>
            </div>
          </div>

          <div className="card coverage-card">
            <div className="panel-head">
              <h2>Coverage matrix</h2>
            </div>
            <div className="match-list">
              {regions.map((r) => (
                <div className="match-row" key={r.id}>
                  <span className="match-dot" style={{ background: REGION_STATUS_COLOR[r.status] }} />
                  <span className="match-name">{r.label}</span>
                  <span className="match-num">{r.online}/{r.sensors}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}