import { useMemo, useState } from 'react';
import type { IntelType, SocState } from '../../types';
import { MITRE_CATALOG } from '../../lib/sim/templates';

interface ThreatIntelFeedProps {
  state: SocState;
}

const TYPE_LABEL: Record<IntelType, string> = {
  vulnerability: 'Vulnerability',
  malware: 'Malware',
  actor: 'Threat Actor',
  campaign: 'Campaign',
  indicator: 'Indicators',
};

const TYPE_COLOR: Record<IntelType, string> = {
  vulnerability: '#FF6E40',
  malware: '#FF1744',
  actor: '#7E57C2',
  campaign: '#2979FF',
  indicator: '#00E676',
};

function timeAgo(ts: number): string {
  const h = Math.floor((Date.now() - ts) / 3600_000);
  if (h < 1) return 'just now';
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function trustStars(trust: number): string {
  return '★'.repeat(trust) + '☆'.repeat(Math.max(0, 5 - trust));
}

export function ThreatIntelFeed({ state }: ThreatIntelFeedProps) {
  const [typeFilter, setTypeFilter] = useState<Set<IntelType>>(new Set());
  const [q, setQ] = useState('');

  const items = useMemo(() => {
    const qq = q.trim().toLowerCase();
    return state.intel
      .filter((i) => typeFilter.size === 0 || typeFilter.has(i.type))
      .filter((i) => {
        if (!qq) return true;
        return `${i.title} ${i.description} ${i.tags.join(' ')} ${i.iocs.join(' ')}`.toLowerCase().includes(qq);
      })
      .sort((a, b) => b.publishedAt - a.publishedAt);
  }, [state.intel, typeFilter, q]);

  const ttpCounts = useMemo(() => {
    const m = new Map<string, number>();
    for (const i of state.intel) for (const t of i.ttps) m.set(t, (m.get(t) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
  }, [state.intel]);

  const toggleType = (t: IntelType) => {
    setTypeFilter((prev) => {
      const next = new Set(prev);
      if (next.has(t)) next.delete(t);
      else next.add(t);
      return next;
    });
  };

  const copyIoc = async (ioc: string) => {
    try {
      await navigator.clipboard.writeText(ioc);
    } catch {
      /* clipboard unavailable */
    }
  };

  return (
    <div className="module-page intel-module">
      <div className="module-head">
        <div>
          <h1>Threat Intelligence Feed</h1>
          <p className="module-sub">STIX-style intel with TTP mapping, IOC indicators and 5-level source trust</p>
        </div>
      </div>

      <div className="card workbench-toolbar">
        <input
          className="query-input grow"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search intel, TTPs, IOCs…"
          aria-label="Search intel"
        />
        {(Object.keys(TYPE_LABEL) as IntelType[]).map((t) => (
          <button
            key={t}
            className={`chip-btn ${typeFilter.has(t) ? 'on' : ''}`}
            style={typeFilter.has(t) ? { borderColor: TYPE_COLOR[t], color: TYPE_COLOR[t] } : undefined}
            onClick={() => toggleType(t)}
          >
            {TYPE_LABEL[t]}
          </button>
        ))}
      </div>

      <div className="intel-layout">
        <div className="intel-feed">
          {items.length === 0 && <div className="table-empty card">No intelligence matching filter</div>}
          {items.map((i) => (
            <div className="card intel-card" key={i.id}>
              <div className="intel-card-top">
                <span className="intel-type" style={{ color: TYPE_COLOR[i.type], borderColor: TYPE_COLOR[i.type] }}>
                  {TYPE_LABEL[i.type]}
                </span>
                {i.cve && <span className="tech-badge">{i.cve}</span>}
                <span className="intel-time">{timeAgo(i.publishedAt)}</span>
              </div>
              <h3 className="intel-title">{i.title}</h3>
              <p className="intel-desc">{i.description}</p>

              <div className="intel-meta">
                <div className="confidence">
                  <span>Confidence</span>
                  <div className="confidence-track">
                    <div className="confidence-fill" style={{ width: `${Math.round(i.confidence * 100)}%` }} />
                  </div>
                  <b>{Math.round(i.confidence * 100)}%</b>
                </div>
                <div className="intel-source">
                  <span>Source</span>
                  <b>{i.source}</b>
                  <span className="trust-stars">{trustStars(i.sourceTrust)}</span>
                </div>
              </div>

              <div className="intel-tags">
                {i.tags.map((t) => (
                  <span className="badge badge-ghost" key={t}>#{t}</span>
                ))}
              </div>

              <div className="intel-ttps">
                <span className="intel-subtitle">TTPs</span>
                {i.ttps.map((t) => (
                  <span className="tech-badge" key={t} title={MITRE_CATALOG[t]?.tactic ?? ''}>
                    {t} · {MITRE_CATALOG[t]?.name ?? t}
                  </span>
                ))}
              </div>

              <div className="intel-iocs">
                <span className="intel-subtitle">Indicators</span>
                <div className="ioc-list">
                  {i.iocs.map((ioc) => (
                    <button className="ioc-chip" key={ioc} onClick={() => void copyIoc(ioc)} title="Copy IOC">
                      {ioc}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="card intel-ttp-panel">
          <div className="panel-head">
            <h2>Top TTPs in feed</h2>
          </div>
          <div className="panel-body">
            {ttpCounts.map(([ttp, count]) => (
              <div className="ttp-row" key={ttp}>
                <span className="ttp-id">{ttp}</span>
                <span className="ttp-name" title={MITRE_CATALOG[ttp]?.tactic ?? ''}>
                  {MITRE_CATALOG[ttp]?.name ?? ttp}
                </span>
                <span className="ttp-count">{count}</span>
              </div>
            ))}
            {ttpCounts.length === 0 && <div className="no-path">No TTP data yet</div>}
          </div>
          <div className="panel-head intel-legend-head">
            <h2>Source trust tiers</h2>
          </div>
          <div className="panel-body">
            <div className="trust-row">
              <span>★★★★★</span> Vetted vendor / first-party
            </div>
            <div className="trust-row">
              <span>★★★☆☆</span> Community + manual review
            </div>
            <div className="trust-row">
              <span>★☆☆☆☆</span> Automated / unverified
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}