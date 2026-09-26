/**
 * AEGIS-SENTINEL — Filter rail (architecture.md §4.4)
 */
import { useThreatStore, DEFAULT_FILTER } from '../state/threatStore'
import { useUiStore } from '../state/uiStore'
import { FEED_SOURCES, CATEGORY_LABELS, SEVERITY_ORDER, SEVERITY_COLORS, SEVERITY_SHAPES } from '../domain/sources'
import { auditLedger } from '../security/auditLedger'
import type { Severity, ThreatCategory } from '../domain/types'

export function FilterRail() {
  const filter = useThreatStore((s) => s.filter)
  const setFilter = useThreatStore((s) => s.setFilter)
  const resetFilter = useThreatStore((s) => s.resetFilter)
  const role = useUiStore((s) => s.role)

  const apply = (patch: Parameters<typeof setFilter>[0]) => {
    setFilter(patch)
    auditLedger.append('demo-user', role, 'filter.apply', 'threat.filter', patch as Record<string, unknown>)
  }

  const toggleSev = (s: Severity) => {
    const has = filter.severities.includes(s)
    apply({ severities: has ? filter.severities.filter((x) => x !== s) : [...filter.severities, s] })
  }

  const toggleCat = (c: ThreatCategory) => {
    const has = filter.categories.includes(c)
    apply({ categories: has ? filter.categories.filter((x) => x !== c) : [...filter.categories, c] })
  }

  const toggleSrc = (id: string) => {
    const has = filter.sources.includes(id)
    apply({ sources: has ? filter.sources.filter((x) => x !== id) : [...filter.sources, id] })
  }

  return (
    <aside className="rail glass" aria-label="Threat filters">
      <div className="panel-title">Threat Filters</div>

      <div className="rail-row">
        <label>Severity (min {filter.severities.length} of 5)</label>
        <div className="check-row">
          {SEVERITY_ORDER.map((s) => (
            <label key={s} className={'check' + (filter.severities.includes(s) ? ' on' : '')}>
              <input type="checkbox" checked={filter.severities.includes(s)} onChange={() => toggleSev(s)} />
              <span style={{ color: SEVERITY_COLORS[s] }}>{SEVERITY_SHAPES[s]} {s}</span>
            </label>
          ))}
        </div>
      </div>

      <div className="rail-row">
        <label>Category</label>
        <div className="check-row">
          {(Object.keys(CATEGORY_LABELS) as ThreatCategory[]).map((c) => (
            <label key={c} className={'check' + (filter.categories.includes(c) ? ' on' : '')}>
              <input type="checkbox" checked={filter.categories.includes(c)} onChange={() => toggleCat(c)} />
              {CATEGORY_LABELS[c]}
            </label>
          ))}
        </div>
      </div>

      <div className="rail-row rail-sep">
        <label>Min risk: {filter.minRisk}</label>
        <input type="range" min={0} max={100} value={filter.minRisk}
          onChange={(e) => apply({ minRisk: Number(e.target.value) })} />
      </div>

      <div className="rail-row">
        <label>Window: {filter.windowMinutes} min</label>
        <input type="range" min={5} max={120} step={5} value={filter.windowMinutes}
          onChange={(e) => apply({ windowMinutes: Number(e.target.value) })} />
      </div>

      <div className="rail-row rail-sep">
        <label>Feed sources</label>
        <div className="check-row">
          {FEED_SOURCES.map((s) => (
            <label key={s.id} className={'check' + (filter.sources.includes(s.id) ? ' on' : '')}>
              <input type="checkbox" checked={filter.sources.includes(s.id)} onChange={() => toggleSrc(s.id)} />
              {s.name} <span className="c-muted">[{s.trust_tier}]</span>
            </label>
          ))}
        </div>
      </div>

      <button className="btn btn-ghost" onClick={() => { resetFilter(); auditLedger.append('demo-user', role, 'filter.apply', 'threat.filter', { reset: true, defaults: DEFAULT_FILTER.windowMinutes }) }}>
        ↺ Reset filters
      </button>
    </aside>
  )
}
