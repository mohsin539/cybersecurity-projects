/**
 * AEGIS-SENTINEL — Perf HUD (architecture.md §5.3 budgets, §13.1 client RUM)
 */
import { useEffect, useState } from 'react'
import { useUiStore } from '../state/uiStore'
import type { GlobeEngine } from '../engine/GlobeEngine'

export function PerfHud({ engine }: { engine: GlobeEngine | null }) {
  const visible = useUiStore((s) => s.perfHud)
  const [perf, setPerf] = useState({ fps: 0, frameMs: 0, drawCalls: 0, arcs: 0 })

  useEffect(() => {
    if (!engine) return
    const id = window.setInterval(() => setPerf(engine.getPerf()), 500)
    return () => window.clearInterval(id)
  }, [engine])

  if (!visible) return null
  const ok = perf.fps >= 55
  return (
    <div className="perf-hud glass" aria-label="Performance">
      <div><b>{perf.fps}</b> fps {ok ? '· within 16.6ms budget' : '· frame budget exceeded'}</div>
      <div>frame <b>{perf.frameMs}ms</b> · calls <b>{perf.drawCalls}</b> · arcs <b>{perf.arcs}</b></div>
      <div className="c-muted">WebGL · bloom · dpr-capped</div>
    </div>
  )
}
