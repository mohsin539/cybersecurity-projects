/**
 * AEGIS-SENTINEL — App shell (architecture.md §2 presentation layer)
 */
import { useEffect, useRef, useState } from 'react'
import { GlobeEngine } from './engine/GlobeEngine'
import { ThreatStream } from './data/stream'
import { useThreatStore } from './state/threatStore'
import { useUiStore } from './state/uiStore'
import { auditLedger } from './security/auditLedger'
import { Hud } from './components/Hud'
import { FilterRail } from './components/FilterRail'
import { Legend } from './components/Legend'
import { Ticker } from './components/Ticker'
import { EventDrawer } from './components/EventDrawer'
import { ReportModal } from './components/ReportModal'
import { AuditModal } from './components/AuditModal'
import { VerifyModal } from './components/VerifyModal'
import { AboutModal } from './components/AboutModal'
import { Toasts } from './components/Toasts'
import { PerfHud } from './components/PerfHud'
import { BootScreen } from './components/BootScreen'
import { computeStats } from './state/threatStore'
import { SEVERITY_ORDER } from './domain/sources'

export default function App() {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [engine, setEngine] = useState<GlobeEngine | null>(null)
  const visible = useThreatStore((s) => s.visible)
  const selectedId = useThreatStore((s) => s.selected?.event_id ?? null)
  const select = useThreatStore((s) => s.select)
  const role = useUiStore((s) => s.role)
  const cinematic = useUiStore((s) => s.cinematic)
  const directorMode = useUiStore((s) => s.directorMode)
  const setBooted = useUiStore((s) => s.setBooted)
  const pushToast = useUiStore((s) => s.pushToast)

  // Engine lifecycle
  useEffect(() => {
    if (!canvasRef.current) return
    const eng = new GlobeEngine(canvasRef.current)
    eng.onCritical = (e) => {
      pushToast('critical', `⚡ ${e.severity.toUpperCase()}: ${e.title}`)
      auditLedger.append('demo-user', role, 'globe.event_select', `event:${e.event_id}`, { severity: e.severity, auto: true })
    }
    setEngine(eng)
    const t = window.setTimeout(() => setBooted(true), 700)
    return () => {
      window.clearTimeout(t)
      eng.destroy()
      setEngine(null)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Stream → store
  useEffect(() => {
    const stream = new ThreatStream()
    const handle = stream.start(400)
    const unsub = stream.subscribe((batch) => useThreatStore.getState().ingest(batch))
    return () => {
      unsub()
      handle.close()
    }
  }, [])

  // Visible events → engine
  useEffect(() => {
    engine?.setEvents(visible, selectedId)
  }, [engine, visible, selectedId])

  // UI flags → engine
  useEffect(() => {
    if (!engine) return
    engine.cinematic = cinematic
    engine.directorMode = directorMode
  }, [engine, cinematic, directorMode])

  const stats = computeStats(visible)
  const counts: Record<string, number> = {}
  for (const s of SEVERITY_ORDER) counts[s] = stats.bySeverity[s]

  const onCanvasClick = (ev: React.MouseEvent<HTMLCanvasElement>) => {
    if (!engine) return
    const id = engine.pick(ev.clientX, ev.clientY)
    if (id) {
      select(id)
      auditLedger.append('demo-user', role, 'globe.event_select', `event:${id}`)
    } else {
      select(null)
    }
  }

  return (
    <div id="app-shell">
      <canvas id="globe-canvas" ref={canvasRef} onClick={onCanvasClick}
        aria-label="Interactive 3D threat globe. Use the ticker and panels to browse events." />
      <Hud />
      <FilterRail />
      <Legend counts={counts} />
      <Ticker />
      <EventDrawer />
      <ReportModal />
      <AuditModal />
      <VerifyModal />
      <AboutModal />
      <Toasts />
      <PerfHud engine={engine} />
      <BootScreen />
      <div className="hud-actions" style={{ position: 'absolute', right: 16, top: 76, zIndex: 20 }}>
        <button className="btn btn-ghost" title="Cinematic orbit for SOC walls"
          onClick={() => useUiStore.getState().toggleCinematic()}>
          🎬 {cinematic ? 'Cinematic: on' : 'Cinematic'}
        </button>
        <button className="btn btn-ghost" title="Flash + focus on critical events"
          onClick={() => useUiStore.getState().toggleDirector()}>
          🎥 Director
        </button>
        <button className="btn btn-ghost" onClick={() => useUiStore.getState().togglePerfHud()}>📊 Perf</button>
        <button className="btn btn-ghost" onClick={() => useUiStore.getState().openModal('about')}>ⓘ About</button>
      </div>
    </div>
  )
}
