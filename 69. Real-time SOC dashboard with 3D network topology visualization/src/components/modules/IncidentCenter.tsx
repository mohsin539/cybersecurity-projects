import { useMemo, useState } from 'react';
import type { Incident, IncidentStatus, Severity, SocState } from '../../types';

interface IncidentCenterProps {
  state: SocState;
  dispatch: React.Dispatch<import('../../state/socStore').SocAction>;
}

const STATUS_FLOW: IncidentStatus[] = ['new', 'investigating', 'contained', 'eradicated', 'recovered', 'closed'];

const STATUS_LABEL: Record<IncidentStatus, string> = {
  new: 'New',
  investigating: 'Investigating',
  contained: 'Contained',
  eradicated: 'Eradicated',
  recovered: 'Recovered',
  closed: 'Closed',
};

const SEV_COLOR: Record<Severity, string> = {
  critical: '#FF1744',
  high: '#FF6E40',
  medium: '#FFB300',
  low: '#3EC6FF',
  info: '#9aa7c7',
};

const STATUS_STEP: Record<IncidentStatus, number> = {
  new: 0,
  investigating: 1,
  contained: 2,
  eradicated: 3,
  recovered: 4,
  closed: 5,
};

function timeAgo(ts: number): string {
  const d = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (d < 60) return `${d}s`;
  if (d < 3600) return `${Math.floor(d / 60)}m`;
  if (d < 86400) return `${Math.floor(d / 3600)}h`;
  return `${Math.floor(d / 86400)}d`;
}

export function IncidentCenter({ state, dispatch }: IncidentCenterProps) {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<Set<IncidentStatus>>(new Set(STATUS_FLOW));
  const [note, setNote] = useState('');

  const incidents = useMemo(() => {
    const open = state.incidents.filter((i) => i.status !== 'closed');
    const closed = state.incidents.filter((i) => i.status === 'closed');
    return [...open, ...closed].filter((i) => statusFilter.has(i.status));
  }, [state.incidents, statusFilter]);

  const selected = selectedId ? (state.incidents.find((i) => i.id === selectedId) ?? null) : null;

  const toggleStatus = (id: string, s: IncidentStatus) => {
    dispatch({ type: 'UPDATE_INCIDENT', id, patch: { status: s } });
  };

  const advanceStatus = (i: Incident) => {
    const idx = STATUS_FLOW.indexOf(i.status);
    if (idx >= 0 && idx < STATUS_FLOW.length - 1) {
      const next = STATUS_FLOW[idx + 1];
      toggleStatus(i.id, next);
      dispatch({
        type: 'PUSH_STREAM',
        line: { id: `S-${Date.now()}`, ts: Date.now(), level: 'info', text: `Incident ${i.id} → ${STATUS_LABEL[next]}`, module: 'incidents' },
      });
    }
  };

  const addNote = (i: Incident) => {
    if (!note.trim()) return;
    dispatch({ type: 'ADD_INCIDENT_NOTE', incidentId: i.id, actor: 'SOC Analyst', note: note.trim() });
    setNote('');
  };

  return (
    <div className="module-page incident-module">
      <div className="module-head">
        <div>
          <h1>Incident Command Center</h1>
          <p className="module-sub">Lifecycle management, task tracking, evidence chain and timeline</p>
        </div>
        <div className="module-head-stats">
          <span className="mini-stat"><b>{state.incidents.filter((i) => i.status === 'new').length}</b> new</span>
          <span className="mini-stat"><b>{state.incidents.filter((i) => i.status === 'investigating').length}</b> investigating</span>
          <span className="mini-stat"><b>{state.incidents.filter((i) => i.status === 'closed').length}</b> closed</span>
        </div>
      </div>

      <div className="chip-row">
        {STATUS_FLOW.map((s) => (
          <button
            key={s}
            className={`chip-btn ${statusFilter.has(s) ? 'on' : ''}`}
            onClick={() => {
              setStatusFilter((prev) => {
                const next = new Set(prev);
                if (next.has(s)) next.delete(s);
                else next.add(s);
                return next;
              });
            }}
          >
            {STATUS_LABEL[s]}
          </button>
        ))}
      </div>

      <div className="incident-grid">
        {incidents.length === 0 && <div className="table-empty card">No incidents match current filter</div>}
        {incidents.map((i) => {
          const done = i.tasks.filter((t) => t.done).length;
          const pct = i.tasks.length ? Math.round((done / i.tasks.length) * 100) : 0;
          return (
            <div
              className={`card incident-card ${selectedId === i.id ? 'sel' : ''}`}
              key={i.id}
              onClick={() => setSelectedId(i.id)}
            >
              <div className="incident-card-top">
                <span className="incident-id">{i.id}</span>
                <span className={`sev-badge sev-${i.severity}`} style={{ color: SEV_COLOR[i.severity], borderColor: SEV_COLOR[i.severity] }}>
                  {i.severity} · {STATUS_LABEL[i.status]}
                </span>
              </div>
              <h3 className="incident-title">{i.title}</h3>
              <p className="incident-desc">{i.description}</p>
              <div className="incident-meta">
                <span>owner {i.owner}</span>
                <span>opened {timeAgo(i.createdAt)} ago</span>
              </div>
              <div className="task-progress">
                <div className="progress-track">
                  <div className="progress-fill" style={{ width: `${pct}%` }} />
                </div>
                <span className="progress-label">{done}/{i.tasks.length} tasks</span>
              </div>
              <div className="incident-actions">
                <button className="btn sm primary" onClick={(e) => { e.stopPropagation(); setSelectedId(i.id); }}>
                  Open
                </button>
                {i.status !== 'closed' && (
                  <button className="btn sm" onClick={(e) => { e.stopPropagation(); advanceStatus(i); }}>
                    Advance →
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {selected && (
        <aside className="card side-panel incident-detail">
          <div className="panel-head">
            <div className="node-title-row">
              <span className="incident-id">{selected.id}</span>
              <h2 title={selected.title}>{selected.title}</h2>
            </div>
            <button className="icon-btn" onClick={() => setSelectedId(null)} aria-label="Close detail">
              ×
            </button>
          </div>
          <div className="panel-body">
            <div className="badge-row">
              <span className={`sev-badge sev-${selected.severity}`}>{selected.severity}</span>
              <span className={`status-badge status-${selected.status}`}>{STATUS_LABEL[selected.status]}</span>
              <span className="badge badge-ghost">owner {selected.owner}</span>
            </div>

            <p className="node-desc">{selected.description}</p>

            <div className="section-title">Lifecycle</div>
            <div className="lifecycle-strip">
              {STATUS_FLOW.map((s, i) => {
                const step = STATUS_STEP[selected.status];
                return (
                  <button
                    key={s}
                    className={`lifecycle-step ${i <= step ? 'at' : ''} ${i === step ? 'cur' : ''}`}
                    onClick={() => {
                      toggleStatus(selected.id, s);
                      dispatch({
                        type: 'PUSH_STREAM',
                        line: { id: `S-${Date.now()}`, ts: Date.now(), level: 'info', text: `Incident ${selected.id} → ${STATUS_LABEL[s]}`, module: 'incidents' },
                      });
                    }}
                    title={STATUS_LABEL[s]}
                  >
                    <span className="step-dot" />
                    <span className="step-label">{STATUS_LABEL[s]}</span>
                  </button>
                );
              })}
            </div>

            <div className="section-title">Tasks</div>
            <div className="task-list">
              {selected.tasks.map((t) => (
                <label className="task-item" key={t.id}>
                  <input
                    type="checkbox"
                    checked={t.done}
                    onChange={() => dispatch({ type: 'TOGGLE_TASK', incidentId: selected.id, taskId: t.id })}
                  />
                  <span className={t.done ? 'done' : ''}>{t.title}</span>
                </label>
              ))}
            </div>

            <div className="section-title">Evidence</div>
            <div className="evidence-list">
              {selected.evidence.map((e) => (
                <div className="evidence-item" key={e}>
                  <span className="hash-dot" /> {e} <span className="hash-dim">sha256:…3f9c</span>
                </div>
              ))}
              {selected.evidence.length === 0 && <div className="no-path">None attached</div>}
            </div>

            <div className="section-title">Timeline</div>
            <div className="timeline">
              {[...selected.events].reverse().map((ev, i) => (
                <div className="timeline-item" key={`${ev.ts}-${i}`}>
                  <span className="timeline-time">
                    {new Date(ev.ts).toLocaleTimeString('en-GB', { hour12: false })}
                  </span>
                  <div className="timeline-body">
                    <b>{ev.actor}</b> — {ev.action}
                    {ev.note && <div className="timeline-note">{ev.note}</div>}
                  </div>
                </div>
              ))}
            </div>

            <div className="section-title">Notes</div>
            <div className="note-editor">
              <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={3} placeholder="Add investigation note…" />
              <button className="btn sm primary" onClick={() => addNote(selected)}>Add note</button>
            </div>
          </div>
        </aside>
      )}
    </div>
  );
}