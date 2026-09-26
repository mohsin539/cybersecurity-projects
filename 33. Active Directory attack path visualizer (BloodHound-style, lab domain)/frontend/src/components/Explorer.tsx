import { useCallback, useEffect, useState } from 'react'
import { api, type GraphData, type PathResponse } from '../api'
import GraphView from './GraphView'

export default function Explorer() {
  const [graph, setGraph] = useState<GraphData | null>(null)
  const [selected, setSelected] = useState<string | null>(null)
  const [result, setResult] = useState<PathResponse | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => { api.graph().then(setGraph).catch(e => setError(e.message)) }, [])

  const runPaths = useCallback(async (source: string) => {
    if (!source) return
    setBusy(true); setError('')
    try { setResult(await api.paths(source, 5, 8)) }
    catch (e) { setError(e instanceof Error ? e.message : 'Analysis failed') }
    finally { setBusy(false) }
  }, [])

  const pathNodes = new Set<string>(result?.paths[0]?.nodes ?? [])
  const sourceLabel = graph?.nodes.find(n => n.id === selected)?.label ?? selected

  return (
    <div className="h-full flex">
      <div className="flex-1 relative">
        {graph && <GraphView data={graph} pathNodes={pathNodes} onSelect={setSelected} />}
        {graph && (
          <div className="absolute top-3 left-3 bg-ink-900/85 backdrop-blur border border-ink-700 rounded-xl px-4 py-3 text-[11px] text-slate-400 space-y-1">
            <div className="font-semibold text-slate-200 text-xs mb-1">Legend</div>
            <div><span className="inline-block w-2 h-2 rounded-full bg-[#22d3ee] mr-2" />user · <span className="inline-block w-2 h-2 rounded-full bg-[#a78bfa] mr-2" />group · <span className="inline-block w-2 h-2 rounded-full bg-[#34d399] mr-2" />computer</div>
            <div><span className="inline-block w-2 h-2 rounded-full bg-[#f59e0b] mr-2" />domain/Tier-0 ring · <span className="inline-block w-2 h-2 rounded-full bg-[#f43f5e] mr-2" />DCSync · <span className="inline-block w-2 h-2 rounded-full bg-[#eab308] mr-2" />ACL writes</div>
            <div><span className="inline-block w-2 h-2 rounded-full bg-[#ef4444] mr-2" />CA · <span className="inline-block w-2 h-2 rounded-full bg-[#fb923c] mr-2" />cert template · <span className="inline-block w-2 h-2 rounded-full bg-[#fb923c] mr-2" />enroll edges</div>
          </div>
        )}
        {!graph && !error && <div className="absolute inset-0 grid place-items-center text-slate-500 text-sm">Loading graph…</div>}
        {error && <div className="absolute inset-0 grid place-items-center text-danger text-sm">{error}</div>}
      </div>

      <aside className="w-80 border-l border-ink-700 bg-ink-900 overflow-y-auto">
        <div className="p-4 space-y-4">
          <div>
            <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-2">Attack path simulation</h2>
            <p className="text-xs text-slate-400 mb-2">Selected:</p>
            <div className="bg-ink-800 border border-ink-700 rounded-lg px-3 py-2 text-sm text-slate-200 break-all">{sourceLabel ?? 'click a node'}</div>
            <button disabled={!selected || busy} onClick={() => selected && runPaths(selected)}
                    className="mt-3 w-full bg-accent text-ink-950 font-semibold rounded-lg py-2 text-sm hover:bg-accent/90 disabled:opacity-40">
              {busy ? 'Analyzing…' : 'Find attack paths'}
            </button>
          </div>

          {result && (
            <>
              <div className="bg-ink-800 border border-ink-700 rounded-xl p-4">
                <div className="text-[11px] uppercase tracking-wider text-slate-500 mb-1">Blast radius</div>
                <div className="flex items-baseline gap-2">
                  <span className={`text-2xl font-semibold ${result.blast_radius.reachable_tier0 ? 'text-danger' : 'text-ok'}`}>
                    {result.blast_radius.risk_score}
                  </span>
                  <span className="text-xs text-slate-500">/ 100</span>
                </div>
                <div className="text-xs text-slate-400 mt-1">
                  {result.blast_radius.total_reachable} nodes reachable · {result.blast_radius.tier0_count} Tier-0 targets
                  {result.blast_radius.reachable_tier0 && <span className="text-danger"> · DOMAIN COMPROMISE POSSIBLE</span>}
                </div>
              </div>
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-2">Paths ({result.paths.length})</h3>
                <div className="space-y-2">
                  {result.paths.map((p, i) => (
                    <div key={i} className={`border rounded-lg p-3 ${i === 0 ? 'border-accent/50 bg-accent/5' : 'border-ink-700 bg-ink-800'}`}>
                      <div className="flex justify-between text-xs mb-1">
                        <span className="text-slate-300">{p.hops} hops</span>
                        <span className="font-semibold text-warn">risk {p.risk}</span>
                      </div>
                      <div className="text-[11px] text-slate-400 break-words">
                        {p.nodes.map(n => n.split(':', 1)[0][0] + '·' + (n.split(':')[1] ?? '')).join(' → ')}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>
      </aside>
    </div>
  )
}
