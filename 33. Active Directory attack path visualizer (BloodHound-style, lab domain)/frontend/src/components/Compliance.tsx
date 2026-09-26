import { useEffect, useState } from 'react'
import { api, downloadReport, type CompliancePosture, type FrameworkPosture } from '../api'

const STATUS_STYLE: Record<string, string> = {
  pass: 'bg-ok/15 text-ok border-ok/40',
  partial: 'bg-warn/10 text-warn border-warn/40',
  fail: 'bg-danger/15 text-danger border-danger/40',
}
const STATUS_ICON: Record<string, string> = { pass: '✓', partial: '~', fail: '✕' }

function Ring({ score }: { score: number }) {
  const color = score >= 80 ? '#34d399' : score >= 55 ? '#f59e0b' : '#f43f5e'
  const circ = 2 * Math.PI * 26
  return (
    <svg width="64" height="64" viewBox="0 0 64 64" className="shrink-0">
      <circle cx="32" cy="32" r="26" fill="none" stroke="#1b2437" strokeWidth="6" />
      <circle cx="32" cy="32" r="26" fill="none" stroke={color} strokeWidth="6"
              strokeDasharray={`${(score / 100) * circ} ${circ}`}
              strokeLinecap="round" transform="rotate(-90 32 32)" />
      <text x="32" y="37" textAnchor="middle" fill="#e2e8f0" fontSize="14" fontWeight="600">{Math.round(score)}</text>
    </svg>
  )
}

function FrameworkCard({ id, fw }: { id: string; fw: FrameworkPosture }) {
  const [open, setOpen] = useState(false)
  return (
    <section className="bg-ink-800 border border-ink-700 rounded-xl p-5">
      <div className="flex items-center justify-between gap-4">
        <div className="min-w-0">
          <h2 className="font-semibold text-slate-100">{fw.name}</h2>
          <p className="text-xs text-slate-500 mt-0.5">{id} · {fw.description}</p>
          <div className="mt-2 flex gap-3 text-[11px]">
            <span className="text-ok">{fw.counts.pass} pass</span>
            <span className="text-warn">{fw.counts.partial} partial</span>
            <span className="text-danger">{fw.counts.fail} fail</span>
            <span className="text-slate-500">/ {fw.counts.total} controls</span>
          </div>
        </div>
        <Ring score={fw.score} />
      </div>
      <button onClick={() => setOpen(!open)}
              className="mt-3 text-xs text-accent hover:underline">
        {open ? 'Hide' : 'Show'} control matrix ({fw.controls.length})
      </button>
      {open && (
        <div className="mt-3 space-y-1.5 max-h-96 overflow-y-auto pr-1">
          {fw.controls.map(c => (
            <div key={c.id} className="flex items-start gap-3 bg-ink-900 border border-ink-700 rounded-lg px-3 py-2">
              <span className={`shrink-0 w-5 h-5 grid place-items-center rounded border text-[11px] font-bold ${STATUS_STYLE[c.status]}`}>
                {STATUS_ICON[c.status]}
              </span>
              <div className="min-w-0">
                <div className="text-sm text-slate-200">
                  <span className="text-slate-500 font-mono text-xs mr-2">{c.id}</span>
                  {c.title}
                  {c.criticality === 'key' && <span className="ml-2 text-[9px] uppercase tracking-wider text-vip">key</span>}
                </div>
                <p className="text-[11px] text-slate-500 mt-0.5">{c.statement}</p>
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  )
}

export default function Compliance() {
  const [posture, setPosture] = useState<CompliancePosture | null>(null)
  const [error, setError] = useState('')
  const [exportMsg, setExportMsg] = useState('')
  useEffect(() => { api.compliance().then(setPosture).catch(e => setError(e.message)) }, [])

  async function exportReport(format: 'pdf' | 'csv') {
    setExportMsg('')
    try {
      await downloadReport('compliance', format)
      setExportMsg(`${format.toUpperCase()} downloaded`)
      setTimeout(() => setExportMsg(''), 4000)
    } catch (e) {
      setExportMsg(e instanceof Error ? e.message : 'Export failed')
    }
  }

  if (error) return <div className="p-6 text-danger text-sm">{error}</div>
  if (!posture) return <div className="p-6 text-slate-500 text-sm">Computing compliance posture…</div>

  const frameworks = Object.entries(posture.frameworks)
  const avg = frameworks.reduce((s, [, f]) => s + f.score, 0) / Math.max(1, frameworks.length)

  return (
    <div className="p-6 space-y-4 overflow-y-auto h-full">
      <div className="flex items-center gap-4 bg-ink-800 border border-ink-700 rounded-xl p-5">
        <Ring score={avg} />
        <div className="flex-1">
          <h1 className="font-semibold text-slate-100">Overall compliance posture</h1>
          <p className="text-xs text-slate-500 mt-1">
            Continuously computed from live graph evidence, findings scans, RBAC enforcement and audit trail —
            not a static checklist. Frameworks: OWASP Top 10 2021, ISO/IEC 27001:2022, NIST CSF 2.0,
            NIST 800-53 r5, PCI DSS 4.0, CIS Controls v8.
          </p>
        </div>
        <div className="flex flex-col items-end gap-2">
          <div className="flex gap-2">
            <button onClick={() => exportReport('pdf')}
                    className="text-[11px] border border-ink-700 rounded-lg px-3 py-1.5 text-slate-300 hover:border-accent hover:text-accent">Export PDF</button>
            <button onClick={() => exportReport('csv')}
                    className="text-[11px] border border-ink-700 rounded-lg px-3 py-1.5 text-slate-300 hover:border-accent hover:text-accent">Export CSV</button>
          </div>
          {exportMsg && <span className="text-[11px] text-ok">{exportMsg}</span>}
        </div>
      </div>
      <div className="grid md:grid-cols-2 gap-4">
        {frameworks.map(([id, fw]) => <FrameworkCard key={id} id={id} fw={fw} />)}
      </div>
    </div>
  )
}
