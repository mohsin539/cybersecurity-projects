/**
 * AEGIS-SENTINEL — Threat ticker (architecture.md §4.4): marquee of latest events.
 */
import { useThreatStore } from '../state/threatStore'
import { SEVERITY_SHAPES } from '../domain/sources'

export function Ticker() {
  const events = useThreatStore((s) => s.visible)
  const select = useThreatStore((s) => s.select)
  const items = events.slice(0, 14)
  if (items.length === 0) return null

  const row = (key: string) => (
    <div key={key} className="ticker-track" aria-hidden={key === 'b'}>
      {items.map((e) => (
        <button key={key + e.event_id} className="ticker-item" style={{ background: 'none', border: 'none' }}
          onClick={() => select(e.event_id)}>
          {e.severity === 'critical' || e.severity === 'zero-day' ? (
            <span className="ticker-crit">⚡ {e.severity.toUpperCase()}</span>
          ) : (
            <span className={'c-' + e.severity}>{SEVERITY_SHAPES[e.severity]}</span>
          )}
          <b>{e.title}</b>
          <span>risk {e.risk_score}</span>
          <span className="c-muted">{e.geo.src.country}→{e.geo.dst.country}</span>
        </button>
      ))}
    </div>
  )

  return (
    <div className="ticker glass" aria-live="polite">
      {row('a')}
      {row('b')}
    </div>
  )
}
