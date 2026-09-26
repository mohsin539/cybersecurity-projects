import { useEffect, useMemo, useState } from 'react'
import { api, type Finding, type WhatIfBatch } from '../api'

/** What-if remediation simulator: pick findings, see attack-path & risk
 *  impact before touching production. Store is never mutated. */
export default function WhatIf({ findings }: { findings: Finding[] }) {
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [result, setResult] = useState<WhatIfBatch | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const candidates = useMemo(
    () => findings.map(f => ({ id: f.id, title: f.title, severity: f.severity })),
    [findings])

  function toggle(id: string) {
    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
  }

  async function run() {
    if (selected.size === 0) return
    setBusy(true); setError('')
    try {
      // Roadmap order: critical first (GRC-style prioritization)
      const order = [...selected].sort((a, b) => {
        const rank = (id: string) => {
          const f = findings.find(x => x.id === id)
          return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[f?.severity ?? 'info']
        }
        return rank(a) - rank(b)
      })
      setResult(await api.whatIf(order))
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Simulation failed')
    } finally { setBusy(false) }
  }

  const before = result?.before
  const final = result?.final
  const firstRisk = result?.roadmap_steps[0]?.risk_index

  return (
    <section className="bg-ink-800 border border-ink-700 rounded-xl p-5">
      <div className="flex items-start justify-between gap-4 mb-3">
        <div>
          <h2 className="text-sm font-semibold text-slate-200">What-if remediation simulator</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Simulates fixes on a filtered view of the live graph — nothing is changed.
          </p>
        </div>
        <button onClick={run} disabled={selected.size === 0 || busy}
                className="shrink-0 bg-accent text-ink-950 font-semibold rounded-lg px-4 py-2 text-xs hover:bg-accent/90 disabled:opacity-40">
          {busy ? 'Simulating…' : `Simulate fix (${selected.size})`}
        </button>
      </div>

      <div className="flex flex-wrap gap-2 mb-4">
        {candidates.map(f => (
          <button key={f.id} onClick={() => toggle(f.id)}
                  className={`text-[11px] rounded-full px-2.5 py-1 border transition ${
                    selected.has(f.id)
                      ? 'bg-accent/20 border-accent text-accent'
                      : 'bg-ink-900 border-ink-700 text-slate-400 hover:border-slate-500'}`}>
            {f.title}
          </button>
        ))}
      </div>

      {error && <p className="text-xs text-danger mb-2">{error}</p>}

      {result && before && final && (
        <div className="grid md:grid-cols-3 gap-4">
          <div className="bg-ink-900 border border-ink-700 rounded-xl p-4">
            <div className="text-[10px] uppercase tracking-wider text-slate-500">Risk score (raw)</div>
            <div className="mt-1 flex items-baseline gap-2">
              <span className="text-xl font-semibold text-slate-100">{before.risk_index}</span>
              <span className="text-slate-500">→</span>
              <span className="text-xl font-semibold text-ok">{final.risk_index}</span>
              <span className="text-xs text-ok">({result.total_delta.risk_index})</span>
            </div>
            <div className="text-[11px] text-slate-500 mt-1">findings: {before.findings_total} → {final.findings_total}</div>
          </div>
          <div className="bg-ink-900 border border-ink-700 rounded-xl p-4">
            <div className="text-[10px] uppercase tracking-wider text-slate-500">Tier-0 exposure</div>
            <div className="mt-1 text-xl font-semibold text-slate-100">
              {before.tier0_exposed_principals} <span className="text-slate-500">→</span> {final.tier0_exposed_principals}
            </div>
            <div className="text-[11px] text-slate-500 mt-1">
              principals able to reach crown jewels
            </div>
          </div>
          <div className="bg-ink-900 border border-ink-700 rounded-xl p-4">
            <div className="text-[10px] uppercase tracking-wider text-slate-500">Remediation roadmap</div>
            <div className="mt-1 space-y-1">
              {result.roadmap_steps.map((s, i) => (
                <div key={s.finding_id} className="flex justify-between text-[11px]">
                  <span className="text-slate-400">{i + 1}. {s.finding_id}</span>
                  <span className="text-slate-200">{s.risk_index}</span>
                </div>
              ))}
            </div>
            {firstRisk !== undefined && (
              <div className="text-[10px] text-slate-500 mt-1">risk after each step</div>
            )}
          </div>
        </div>
      )}
    </section>
  )
}
