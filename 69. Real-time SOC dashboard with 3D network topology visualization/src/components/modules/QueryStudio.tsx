import { useMemo, useRef, useState } from 'react';
import type { LogEntry, Severity, SocState } from '../../types';
import { PRESET_QUERIES, runQuery } from '../../lib/sim/logStore';
import { Sparkline } from '../Sparkline';
import { MITRE_CATALOG } from '../../lib/sim/templates';

interface QueryStudioProps {
  state: SocState;
}

const SEV_COLOR: Record<Severity, string> = {
  critical: '#FF1744',
  high: '#FF6E40',
  medium: '#FFB300',
  low: '#3EC6FF',
  info: '#9aa7c7',
};

function fmtT(ts: number): string {
  return new Date(ts).toLocaleTimeString('en-GB', { hour12: false });
}

function severityByCount(rows: LogEntry[]): Record<Severity, number> {
  const out: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const r of rows) out[r.severity] = (out[r.severity] ?? 0) + 1;
  return out;
}

function timeline(rows: LogEntry[]): number[] {
  if (rows.length === 0) return [];
  const span = 30 * 60 * 1000;
  const end = Math.max(...rows.map((r) => r.ts));
  const buckets = Math.min(40, Math.max(6, Math.ceil((end - Math.min(...rows.map((r) => r.ts))) / span)));
  const width = Math.max(1, Math.ceil((end - Math.min(...rows.map((r) => r.ts))) / buckets));
  const out = new Array(buckets).fill(0);
  for (const r of rows) {
    const idx = Math.min(buckets - 1, Math.max(0, Math.floor((end - r.ts) / width)));
    out[buckets - 1 - idx]++;
  }
  return out;
}

export function QueryStudio({ state }: QueryStudioProps) {
  const [query, setQuery] = useState(PRESET_QUERIES[0].query);
  const [saved, setSaved] = useState<string[]>(() => {
    try {
      const raw = window.localStorage.getItem('soc.savedQueries');
      return raw ? (JSON.parse(raw) as string[]) : [];
    } catch {
      return [];
    }
  });
  const [ranQuery, setRanQuery] = useState(PRESET_QUERIES[0].query);
  const [lastDur, setLastDur] = useState<number | null>(null);
  const startRef = useRef<number | null>(null);

  const results = useMemo(() => {
    if (!ranQuery.trim()) return [];
    if (startRef.current == null) startRef.current = performance.now();
    const rows = runQuery(state.logs, ranQuery);
    if (startRef.current != null) {
      setLastDur(Math.max(1, Math.round((performance.now() - startRef.current) * 100) / 100));
    }
    return rows;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.logs, ranQuery]);

  const counts = useMemo(() => severityByCount(results), [results]);
  const tl = useMemo(() => timeline(results), [results]);

  const run = (q: string) => {
    setQuery(q);
    setRanQuery(q);
    startRef.current = performance.now();
  };

  const saveQuery = () => {
    if (!query.trim()) return;
    const next = [query, ...saved.filter((s) => s !== query)].slice(0, 8);
    setSaved(next);
    window.localStorage.setItem('soc.savedQueries', JSON.stringify(next));
  };

  return (
    <div className="module-page">
      <div className="module-head">
        <div>
          <h1>SIEM Query Studio</h1>
          <p className="module-sub">Search the synthetic event store with a mini query language · <em>242k simulated events in 24h</em></p>
        </div>
      </div>

      <div className="card query-card">
        <div className="panel-head">
          <h2>Query editor</h2>
          <div className="query-actions">
            <span className="query-hint">source= · eventid= · host= · user= · severity= · mitre=</span>
            <button className="btn sm ghost" onClick={saveQuery}>Save</button>
            <button className="btn sm primary" onClick={() => run(query)}>Run ▸</button>
          </div>
        </div>
        <div className="query-body">
          <textarea
            className="query-editor"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            spellCheck={false}
            onKeyDown={(e) => {
              if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                e.preventDefault();
                run(query);
              }
            }}
            placeholder="e.g. source=auth eventid=4625"
          />
          <div className="preset-chips">
            {PRESET_QUERIES.map((p) => (
              <button key={p.name} className="chip-btn" onClick={() => run(p.query)} title={p.query}>
                {p.name}
              </button>
            ))}
          </div>
          {saved.length > 0 && (
            <div className="preset-chips saved">
              {saved.map((q) => (
                <button key={q} className="chip-btn" onClick={() => run(q)} title={q}>
                  ↺ {q}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="query-results">
        <div className="card result-summary">
          {['critical', 'high', 'medium', 'low', 'info'].map((s) => (
            <div className="result-sev" key={s}>
              <i style={{ background: SEV_COLOR[s as Severity] }} />
              <span>{s}</span>
              <b>{counts[s as Severity]}</b>
            </div>
          ))}
          <div className="result-total">
            <b>{results.length}</b>
            <span>matches</span>
          </div>
          <div className="result-total">
            <b>{lastDur ?? '—'}</b>
            <span>ms</span>
          </div>
          <div className="result-total">
            <b>{state.logs.length}</b>
            <span>scanned</span>
          </div>
          <div className="result-spark">
            <Sparkline data={tl} width={140} height={34} color="var(--c-user)" />
          </div>
        </div>

        <div className="card query-table">
          <div className="alert-table-head">
            <span>Time</span>
            <span>Severity</span>
            <span>Source</span>
            <span>Host</span>
            <span>User</span>
            <span>Event ID</span>
            <span>Message</span>
          </div>
          {results.length === 0 && <div className="table-empty">No matching events</div>}
          {results.slice(0, 200).map((r) => (
            <div className="query-row" key={r.id}>
              <span className="row-time">{fmtT(r.ts)}</span>
              <span className={`sev-badge sev-${r.severity}`}>{r.severity}</span>
              <span className="row-source">{r.source}</span>
              <span className="row-mono">{r.host}</span>
              <span className="row-mono">{r.user}</span>
              <span className="row-mono">{r.eventId}</span>
              <span className="row-msg">
                {r.message}
                {r.mitreId && <span className="tech-badge">{r.mitreId} · {MITRE_CATALOG[r.mitreId]?.name ?? ''}</span>}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}