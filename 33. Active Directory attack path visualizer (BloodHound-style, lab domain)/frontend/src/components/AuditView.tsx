import { useEffect, useState } from 'react'
import { api, type AuditEvent } from '../api'

const SEV: Record<string, string> = {
  info: 'text-slate-400', warn: 'text-warn', alert: 'text-danger',
}

export default function AuditView() {
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [error, setError] = useState('')

  useEffect(() => {
    api.audit(200).then(d => setEvents(d.events)).catch(e => setError(e.message))
  }, [])

  if (error) return <div className="p-6 text-sm text-danger">{error} (admin or auditor role required)</div>

  return (
    <div className="p-6 overflow-y-auto h-full">
      <h1 className="text-sm font-semibold text-slate-200 mb-3">Audit trail — append-only</h1>
      <div className="bg-ink-800 border border-ink-700 rounded-xl overflow-hidden">
        <table className="w-full text-xs">
          <thead className="bg-ink-900 text-slate-500">
            <tr>
              <th className="text-left px-4 py-2 font-medium">Timestamp</th>
              <th className="text-left px-4 py-2 font-medium">Event</th>
              <th className="text-left px-4 py-2 font-medium">Actor</th>
              <th className="text-left px-4 py-2 font-medium">Outcome</th>
              <th className="text-left px-4 py-2 font-medium">Severity</th>
            </tr>
          </thead>
          <tbody>
            {events.map(e => (
              <tr key={e.id} className="border-t border-ink-700/60 hover:bg-ink-900/60">
                <td className="px-4 py-1.5 text-slate-500 font-mono">{e.ts}</td>
                <td className="px-4 py-1.5 text-slate-200">{e.event}</td>
                <td className="px-4 py-1.5 text-slate-400">{e.actor}</td>
                <td className={`px-4 py-1.5 ${e.outcome === 'success' ? 'text-ok' : 'text-danger'}`}>{e.outcome}</td>
                <td className={`px-4 py-1.5 ${SEV[e.severity] ?? 'text-slate-500'}`}>{e.severity}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {events.length === 0 && (
          <div className="px-4 py-6 text-center text-slate-500 text-xs">No audit events visible for your role.</div>
        )}
      </div>
    </div>
  )
}
