/**
 * AEGIS-SENTINEL — Threat state store (state.md §3)
 * Single source of truth for the live threat set, filters and derived stats.
 */
import { create } from 'zustand'
import type { Severity, ThreatCategory, ThreatEvent, ThreatFilter } from '../domain/types'
import { SEVERITY_ORDER } from '../domain/sources'

const MAX_EVENTS = 3000
const DEFAULT_WINDOW_MIN = 60

export const DEFAULT_FILTER: ThreatFilter = {
  severities: [...SEVERITY_ORDER],
  categories: [],
  minRisk: 0,
  sources: [],
  windowMinutes: DEFAULT_WINDOW_MIN,
}

interface ThreatState {
  events: ThreatEvent[]
  filter: ThreatFilter
  visible: ThreatEvent[]
  selected: ThreatEvent | null
  lastUpdate: number

  ingest: (batch: ThreatEvent[]) => void
  setFilter: (patch: Partial<ThreatFilter>) => void
  resetFilter: () => void
  select: (id: string | null) => void
}

function applyFilter(events: ThreatEvent[], f: ThreatFilter): ThreatEvent[] {
  const cutoff = Date.now() - f.windowMinutes * 60_000
  return events.filter((e) => {
    if (!f.severities.includes(e.severity)) return false
    if (f.categories.length > 0 && !f.categories.includes(e.category)) return false
    if (e.risk_score < f.minRisk) return false
    if (f.sources.length > 0 && !e.sources.some((s) => f.sources.includes(s.source_id))) return false
    if (new Date(e.occurred_at).getTime() < cutoff) return false
    return true
  })
}

export const useThreatStore = create<ThreatState>((set, get) => ({
  events: [],
  filter: { ...DEFAULT_FILTER },
  visible: [],
  selected: null,
  lastUpdate: 0,

  ingest: (batch) => {
    const merged = [...batch, ...get().events].slice(0, MAX_EVENTS)
    const visible = applyFilter(merged, get().filter)
    set({ events: merged, visible, lastUpdate: Date.now() })
  },

  setFilter: (patch) => {
    const filter = { ...get().filter, ...patch }
    set({ filter, visible: applyFilter(get().events, filter) })
  },

  resetFilter: () => {
    const filter = { ...DEFAULT_FILTER }
    set({ filter, visible: applyFilter(get().events, filter) })
  },

  select: (id) => {
    if (id === null) return set({ selected: null })
    const sel = get().events.find((e) => e.event_id === id) ?? null
    set({ selected: sel })
  },
}))

/** Derived aggregates for the HUD (memo-free; cheap at 3k rows). */
export function computeStats(events: ThreatEvent[]) {
  const bySeverity: Record<Severity, number> = {
    low: 0, medium: 0, high: 0, critical: 0, 'zero-day': 0,
  }
  const byCategory = new Map<ThreatCategory, number>()
  let records = 0
  let riskSum = 0
  for (const e of events) {
    bySeverity[e.severity]++
    byCategory.set(e.category, (byCategory.get(e.category) ?? 0) + 1)
    records += e.impact.records
    riskSum += e.risk_score
  }
  const topCountries = new Map<string, number>()
  for (const e of events) {
    topCountries.set(e.geo.src.country, (topCountries.get(e.geo.src.country) ?? 0) + 1)
  }
  return {
    total: events.length,
    bySeverity,
    byCategory,
    records,
    avgRisk: events.length ? riskSum / events.length : 0,
    topCountries: [...topCountries.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5),
  }
}
