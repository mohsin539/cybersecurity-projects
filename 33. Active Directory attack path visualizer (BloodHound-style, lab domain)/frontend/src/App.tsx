import { useCallback, useEffect, useState } from 'react'
import { api, getToken, setToken, type Finding, type Role } from './api'
import Login from './components/Login'
import Dashboard from './components/Dashboard'
import Explorer from './components/Explorer'
import Compliance from './components/Compliance'
import AuditView from './components/AuditView'

type Tab = 'dashboard' | 'explorer' | 'compliance' | 'audit'

const TABS: { id: Tab; label: string; roles: Role[] }[] = [
  { id: 'dashboard', label: 'Dashboard', roles: ['admin', 'analyst', 'auditor'] },
  { id: 'explorer', label: 'Graph Explorer', roles: ['admin', 'analyst', 'auditor'] },
  { id: 'compliance', label: 'Compliance', roles: ['admin', 'analyst', 'auditor'] },
  { id: 'audit', label: 'Audit Trail', roles: ['admin', 'auditor'] },
]

export default function App() {
  const [authed, setAuthed] = useState(!!getToken())
  const [tab, setTab] = useState<Tab>('dashboard')
  const [me, setMe] = useState<{ username: string; role: Role } | null>(null)
  const [finding, setFinding] = useState<Finding | null>(null)

  useEffect(() => {
    if (!authed) return
    api.me().then(setMe).catch(() => { setToken(null); setAuthed(false) })
  }, [authed])

  const logout = useCallback(() => {
    api.logout().catch(() => {})
    setToken(null)
    setAuthed(false)
    setMe(null)
  }, [])

  if (!authed) return <Login onDone={() => setAuthed(true)} />

  return (
    <div className="h-screen flex flex-col bg-ink-950 text-slate-200">
      <header className="flex items-center justify-between px-5 h-14 border-b border-ink-700 bg-ink-900">
        <div className="flex items-center gap-8">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-accent/15 border border-accent/40 grid place-items-center text-accent text-xs font-bold">SG</div>
            <div className="leading-tight">
              <div className="text-sm font-semibold">SentinelGraph</div>
              <div className="text-[10px] text-slate-500">AD Attack Path Visualizer · Lab</div>
            </div>
          </div>
          <nav className="flex gap-1">
            {TABS.filter(t => me && t.roles.includes(me.role)).map(t => (
              <button key={t.id} onClick={() => { setTab(t.id); setFinding(null) }}
                      className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                        tab === t.id ? 'bg-accent/15 text-accent border border-accent/30'
                                     : 'text-slate-400 hover:text-slate-200 border border-transparent'}`}>
                {t.label}
              </button>
            ))}
          </nav>
        </div>
        <div className="flex items-center gap-3 text-xs">
          {me && (
            <span className="text-slate-400">
              {me.username} <span className="ml-1 px-1.5 py-0.5 rounded bg-ink-800 border border-ink-700 text-[10px] uppercase tracking-wide text-slate-400">{me.role}</span>
            </span>
          )}
          <button onClick={logout} className="text-slate-400 hover:text-danger">Sign out</button>
        </div>
      </header>

      <main className="flex-1 min-h-0">
        {tab === 'dashboard' && <Dashboard onOpenFinding={setFinding} />}
        {tab === 'explorer' && <Explorer />}
        {tab === 'compliance' && <Compliance />}
        {tab === 'audit' && <AuditView />}
      </main>

      {finding && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm grid place-items-center z-50" onClick={() => setFinding(null)}>
          <div className="w-full max-w-lg bg-ink-800 border border-ink-700 rounded-2xl p-6 m-4" onClick={e => e.stopPropagation()}>
            <div className="flex items-start justify-between gap-4">
              <h2 className="font-semibold text-slate-100">{finding.title}</h2>
              <button onClick={() => setFinding(null)} className="text-slate-500 hover:text-slate-200">✕</button>
            </div>
            <div className="mt-1 flex gap-2 items-center">
              <span className="text-[10px] font-bold uppercase text-danger">{finding.severity}</span>
              <span className="text-[10px] text-slate-500">· {finding.category}</span>
              {finding.mitre.map(m => <span key={m} className="text-[10px] bg-ink-950 border border-ink-700 rounded px-1.5 py-0.5 text-slate-400">{m}</span>)}
            </div>
            <p className="text-xs text-slate-400 mt-3 leading-relaxed">{finding.description}</p>
            <div className="mt-4">
              <div className="text-[11px] uppercase tracking-wider text-slate-500 mb-1">Affected</div>
              <div className="space-y-1">
                {finding.affected.map(a => (
                  <div key={a.id} className="text-xs bg-ink-900 border border-ink-700 rounded-lg px-3 py-1.5 text-slate-300">
                    {a.label} <span className="text-slate-500">— {a.why}</span>
                  </div>
                ))}
              </div>
            </div>
            <div className="mt-4">
              <div className="text-[11px] uppercase tracking-wider text-slate-500 mb-1">Remediation</div>
              <p className="text-xs text-ok leading-relaxed">{finding.remediation}</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
