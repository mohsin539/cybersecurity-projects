import { useCallback, useEffect, useState } from 'react'
import { api, type RescanResult, type RescanStatus } from '../api'

const SEV_STYLE: Record<string, string> = {
  critical: 'text-danger', high: 'text-orange-400',
  medium: 'text-warn', low: 'text-slate-300', info: 'text-slate-500',
}

/** Scheduled re-scan panel: baseline diffing across scans/exe restarts. */
export default function RescanPanel({ canWrite, isAdmin }: {
  canWrite: boolean; isAdmin: boolean
}) {
  const [status, setStatus] = useState<RescanStatus | null>(null)
  const [result, setResult] = useState<RescanResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const [intervalInput, setIntervalInput] = useState('0')

  const loadStatus = useCallback(() => {
    api.rescanStatus().then(s => {
      setStatus(s)
      setIntervalInput(String(s.interval_minutes))
    }).catch(() => {})
  }, [])

  useEffect(() => { loadStatus() }, [loadStatus])

  async function runNow() {
    setBusy(true); setMsg('')
    try {
      setResult(await api.rescanRun())
      loadStatus()
    } catch (e) {
      setMsg(e instanceof Error ? e.message : 'Scan failed')
    } finally { setBusy(false) }
  }

  async function saveInterval() {
    setMsg('')
    try {
      const s = await api.rescanInterval(Math.max(0, Number(intervalInput) || 0))
      setStatus(s)
      setMsg(s.enabled
        ? `Scheduler enabled: every ${s.interval_minutes} min`
        : 'Scheduler disabled')
    } catch (e) {
      setMsg(e instanceof Error ? e.message : 'Update failed')
    }
  }

  async function resetBaseline() {
    setMsg('')
    try {
      await api.rescanReset()
      setResult(null)
      loadStatus()
      setMsg('Baseline cleared — next scan reports everything as new')
    } catch (e) {
      setMsg(e instanceof Error ? e.message : 'Reset failed')
    }
  }

  return (
    <section className="bg-ink-800 border border-ink-700 rounded-xl p-5">
      <div className="flex items-start justify-between gap-4 mb-3">
        <div>
          <h2 className="text-sm font-semibold text-slate-200">Scheduled re-scan</h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Diffs each scan against the persisted baseline (survives restarts).
            {status && (
              <> Last run: <span className="text-slate-400">{status.last_run ?? 'never'}</span>
                {' · '}baseline: <span className="text-slate-400">{status.baseline_findings}</span> findings
                {' · '}scheduler: <span className={status.enabled ? 'text-ok' : 'text-slate-500'}>
                  {status.enabled ? `every ${status.interval_minutes} min` : 'off'}</span></>
            )}
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {isAdmin && (
            <>
              <input value={intervalInput} onChange={e => setIntervalInput(e.target.value)}
                     className="w-16 bg-ink-900 border border-ink-700 rounded-lg px-2 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-accent"
                     title="Interval in minutes (0 = off)" />
              <button onClick={saveInterval}
                      className="text-[11px] border border-ink-700 rounded-lg px-2.5 py-1.5 text-slate-300 hover:border-accent hover:text-accent">Set</button>
              <button onClick={resetBaseline}
                      className="text-[11px] border border-danger/40 rounded-lg px-2.5 py-1.5 text-danger/90 hover:bg-danger/10">Clear baseline</button>
            </>
          )}
          {canWrite && (
            <button onClick={runNow} disabled={busy}
                    className="bg-accent text-ink-950 font-semibold rounded-lg px-4 py-1.5 text-xs hover:bg-accent/90 disabled:opacity-40">
              {busy ? 'Scanning…' : 'Scan now'}
            </button>
          )}
        </div>
      </div>

      {msg && <p className="text-[11px] text-ok mb-2">{msg}</p>}

      {result && (
        <div className="grid md:grid-cols-3 gap-4">
          <div className={`bg-ink-900 border rounded-xl p-4 ${result.counts.new ? 'border-danger/40' : 'border-ink-700'}`}>
            <div className="flex items-baseline justify-between">
              <span className="text-[10px] uppercase tracking-wider text-slate-500">New since last scan</span>
              {result.critical_new > 0 && (
                <span className="text-[10px] font-bold text-danger">{result.critical_new} CRITICAL</span>
              )}
            </div>
            <div className={`text-2xl font-semibold mt-1 ${result.counts.new ? 'text-danger' : 'text-ok'}`}>
              {result.counts.new}
            </div>
            <div className="mt-2 space-y-1 max-h-32 overflow-y-auto">
              {result.new.map(f => (
                <div key={f.id} className="text-[11px]">
                  <span className={SEV_STYLE[f.severity]}>●</span>
                  <span className="text-slate-300 ml-1">{f.id}</span>
                  <span className="text-slate-500"> — {f.title}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-ink-900 border border-ink-700 rounded-xl p-4">
            <div className="text-[10px] uppercase tracking-wider text-slate-500">Resolved</div>
            <div className="text-2xl font-semibold mt-1 text-ok">{result.counts.resolved}</div>
            <div className="mt-2 space-y-1 max-h-32 overflow-y-auto">
              {result.resolved.map(f => (
                <div key={f.id} className="text-[11px]">
                  <span className="text-ok">✓</span>
                  <span className="text-slate-400 ml-1">{f.id}</span>
                  <span className="text-slate-500"> — {f.title}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-ink-900 border border-ink-700 rounded-xl p-4">
            <div className="text-[10px] uppercase tracking-wider text-slate-500">Changed</div>
            <div className="text-2xl font-semibold mt-1 text-warn">{result.counts.changed}</div>
            <div className="mt-2 space-y-1 max-h-32 overflow-y-auto">
              {result.changed.map(c => (
                <div key={c.finding_id} className="text-[11px]">
                  <span className="text-warn">~</span>
                  <span className="text-slate-300 ml-1">{c.finding_id}</span>
                  <span className="text-slate-500">
                    {' '}affected {c.old_affected} → {c.new_affected}
                    {c.old_severity !== c.new_severity &&
                      ` · ${c.old_severity} → ${c.new_severity}`}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </section>
  )
}
