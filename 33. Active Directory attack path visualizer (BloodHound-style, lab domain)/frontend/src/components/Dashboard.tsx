import { useEffect, useState } from 'react'
import { api, downloadReport, downloadTickets, type Finding, type FindingSummary } from '../api'
import WhatIf from './WhatIf'
import RescanPanel from './RescanPanel'

const SEV_COLOR: Record<string, string> = {
  critical: 'text-danger', high: 'text-orange-400', medium: 'text-warn',
  low: 'text-slate-300', info: 'text-slate-500',
}
const SEV_BG: Record<string, string> = {
  critical: 'bg-danger/15 border-danger/40', high: 'bg-orange-400/10 border-orange-400/40',
  medium: 'bg-warn/10 border-warn/40', low: 'bg-slate-500/10 border-slate-500/30',
  info: 'bg-slate-600/10 border-slate-600/30',
}

function Stat({ label, value, tone = 'text-slate-100' }: { label: string; value: string | number; tone?: string }) {
  return (
    <div className="bg-ink-800 border border-ink-700 rounded-xl p-4">
      <div className="text-[11px] uppercase tracking-wider text-slate-500">{label}</div>
      <div className={`text-2xl font-semibold mt-1 ${tone}`}>{value}</div>
    </div>
  )
}

export default function Dashboard({ onOpenFinding }: { onOpenFinding: (f: Finding) => void }) {
  const [findings, setFindings] = useState<Finding[]>([])
  const [summary, setSummary] = useState<FindingSummary | null>(null)
  const [chokes, setChokes] = useState<{ node_id: string; label: string; kind: string; tier0_reachable: number; reach: number; risk: number }[]>([])
  const [summaryData, setSummaryData] = useState<Record<string, unknown> | null>(null)
  const [exportMsg, setExportMsg] = useState('')
  const [role, setRole] = useState<string>('')

  useEffect(() => {
    api.me().then(m => setRole(m.role)).catch(() => {})
  }, [])

  useEffect(() => {
    api.findings().then(d => { setFindings(d.findings); setSummary(d.summary) }).catch(() => {})
    api.chokePoints().then(d => setChokes(d.choke_points)).catch(() => {})
    api.summary().then(setSummaryData).catch(() => {})
  }, [])

  async function exportReport(report: 'findings' | 'compliance', format: 'pdf' | 'csv') {
    setExportMsg('')
    try {
      await downloadReport(report, format)
      setExportMsg(`${report} ${format.toUpperCase()} downloaded`)
      setTimeout(() => setExportMsg(''), 4000)
    } catch (e) {
      setExportMsg(e instanceof Error ? e.message : 'Export failed')
    }
  }

  async function exportTickets(system: 'jira' | 'servicenow') {
    setExportMsg('')
    try {
      await downloadTickets(system)
      setExportMsg(`${system} tickets CSV downloaded`)
      setTimeout(() => setExportMsg(''), 4000)
    } catch (e) {
      setExportMsg(e instanceof Error ? e.message : 'Export failed')
    }
  }

  const tierDist = (summaryData?.tier_distribution ?? {}) as Record<string, number>
  const tier0Exposure = (summaryData?.tier0_exposure ?? []) as { node: string; risk: number; tier0_targets: number }[]

  return (
    <div className="p-6 space-y-6 overflow-y-auto h-full">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Stat label="Risk index" value={summary?.risk_index ?? '—'} tone={((summary?.risk_index ?? 0) > 60 ? 'text-danger' : 'text-warn')} />
        <Stat label="Critical" value={summary?.by_severity.critical ?? 0} tone="text-danger" />
        <Stat label="High" value={summary?.by_severity.high ?? 0} tone="text-orange-400" />
        <Stat label="Total findings" value={summary?.total ?? 0} />
      </div>

      <WhatIf findings={findings} />

      <RescanPanel canWrite={role === 'admin' || role === 'analyst'}
                   isAdmin={role === 'admin'} />

      <div className="grid md:grid-cols-2 gap-6">
        <section className="bg-ink-800 border border-ink-700 rounded-xl p-5">
          <h2 className="text-sm font-semibold text-slate-200 mb-3">Choke points — fix first</h2>
          <div className="space-y-2">
            {chokes.slice(0, 6).map(c => (
              <div key={c.node_id} className="flex items-center justify-between bg-ink-900 border border-ink-700 rounded-lg px-3 py-2">
                <div>
                  <div className="text-sm text-slate-200">{c.label}</div>
                  <div className="text-[11px] text-slate-500">{c.kind} · reaches {c.tier0_reachable} Tier-0 assets · {c.reach} nodes</div>
                </div>
                <span className="text-sm font-semibold text-danger">{c.risk}</span>
              </div>
            ))}
            {chokes.length === 0 && <p className="text-xs text-slate-500">No choke points computed.</p>}
          </div>
        </section>

        <section className="bg-ink-800 border border-ink-700 rounded-xl p-5">
          <h2 className="text-sm font-semibold text-slate-200 mb-3">Tier distribution & exposure</h2>
          <div className="flex gap-2 mb-4">
            {['tier0', 'tier1', 'unclassified'].map(k => (
              <div key={k} className="flex-1 bg-ink-900 border border-ink-700 rounded-lg p-3 text-center">
                <div className="text-lg font-semibold text-slate-100">{tierDist[k] ?? 0}</div>
                <div className="text-[10px] uppercase tracking-wide text-slate-500">{k}</div>
              </div>
            ))}
          </div>
          <div className="space-y-2">
            {tier0Exposure.slice(0, 6).map(e => (
              <div key={e.node} className="flex justify-between text-sm bg-ink-900 border border-ink-700 rounded-lg px-3 py-2">
                <span className="text-slate-300">{e.node}</span>
                <span className="text-slate-500">{e.tier0_targets} targets · risk {e.risk}</span>
              </div>
            ))}
          </div>
        </section>
      </div>

      <section className="bg-ink-800 border border-ink-700 rounded-xl p-5">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-slate-200">Findings</h2>
          <div className="flex gap-2 items-center">
            {exportMsg && <span className="text-[11px] text-ok mr-1">{exportMsg}</span>}
            <button onClick={() => exportReport('findings', 'pdf')}
                    className="text-[11px] border border-ink-700 rounded-lg px-2.5 py-1 text-slate-300 hover:border-accent hover:text-accent">PDF</button>
            <button onClick={() => exportReport('findings', 'csv')}
                    className="text-[11px] border border-ink-700 rounded-lg px-2.5 py-1 text-slate-300 hover:border-accent hover:text-accent">CSV</button>
            <span className="text-ink-700">|</span>
            <span className="text-[10px] uppercase tracking-wider text-slate-500">Tickets</span>
            <button onClick={() => exportTickets('jira')}
                    className="text-[11px] border border-ink-700 rounded-lg px-2.5 py-1 text-slate-300 hover:border-accent hover:text-accent">Jira</button>
            <button onClick={() => exportTickets('servicenow')}
                    className="text-[11px] border border-ink-700 rounded-lg px-2.5 py-1 text-slate-300 hover:border-accent hover:text-accent">ServiceNow</button>
          </div>
        </div>
        <div className="space-y-3">
          {findings.map(f => (
            <button key={f.id} onClick={() => onOpenFinding(f)}
                    className={`w-full text-left border rounded-xl p-4 transition hover:border-accent/60 ${SEV_BG[f.severity]}`}>
              <div className="flex items-center justify-between">
                <span className="font-medium text-slate-100">{f.title}</span>
                <span className={`text-[11px] font-bold uppercase tracking-wide ${SEV_COLOR[f.severity]}`}>{f.severity}</span>
              </div>
              <p className="text-xs text-slate-400 mt-1 line-clamp-2">{f.description}</p>
              <div className="mt-2 flex gap-2 flex-wrap">
                {f.mitre.map(m => <span key={m} className="text-[10px] bg-ink-950 border border-ink-700 rounded px-1.5 py-0.5 text-slate-400">{m}</span>)}
                <span className="text-[10px] text-slate-500">{f.affected.length} affected</span>
              </div>
            </button>
          ))}
        </div>
      </section>
    </div>
  )
}
