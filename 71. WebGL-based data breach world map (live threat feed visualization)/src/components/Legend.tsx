/**
 * AEGIS-SENTINEL — Severity legend (color + shape coding, WCAG §4.6)
 */
import { SEVERITY_ORDER, SEVERITY_SHAPES } from '../domain/sources'

export function Legend({ counts }: { counts: Record<string, number> }) {
  return (
    <div className="legend glass" role="legend" aria-label="Severity legend">
      {SEVERITY_ORDER.map((s) => (
        <span key={s} className={'chip legend-chip chip-' + s}>
          {SEVERITY_SHAPES[s]} {s} · {counts[s] ?? 0}
        </span>
      ))}
    </div>
  )
}
