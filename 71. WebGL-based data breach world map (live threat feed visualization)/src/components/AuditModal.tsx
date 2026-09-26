/**
 * AEGIS-SENTINEL — Audit modal (architecture.md §12.4): ledger viewer + verify.
 */
import { useMemo, useState } from 'react'
import { useAuditEntries, auditLedger } from '../state/auditStore'
import { useUiStore } from '../state/uiStore'

export function AuditModal() {
  const modal = useUiStore((s) => s.modal)
  const openModal = useUiStore((s) => s.openModal)
  const role = useUiStore((s) => s.role)
  const entries = useAuditEntries()
  const [query, setQuery] = useState('')
  const [result, setResult] = useState<string | null>(null)

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    const list = [...entries].reverse().slice(0, 200)
    if (!q) return list
    return list.filter((e) =>
      e.action.includes(q) || e.actor.includes(q) || e.resource.toLowerCase().includes(q) || e.role.includes(q))
  }, [entries, query])

  if (modal !== 'audit') return null

  const verify = () => {
    const v = auditLedger.verify()
    const lines = [
      `Chain verification: ${v.ok ? 'VALID ✓' : 'BROKEN ✗'}`,
      `Entries: ${v.length} · Head: ${v.head_hash.slice(0, 40)}…`,
      v.first_broken_seq !== null ? `First broken seq: ${v.first_broken_seq}` : 'No discontinuities detected.',
      '',
      'entry_hash = SHA256(canonical_json(entry \\\\ {entry_hash, prev_hash}) + "|" + prev_hash)',
      'Algorithm: SHA-256 · Anchor: in-tab WORM list (production: HSM + RFC 3161, §12.2)',
    ]
    setResult(lines.join('\n'))
    auditLedger.append('demo-user', role, 'audit.verify', 'ledger', { ok: v.ok, head: v.head_hash.slice(0, 16) })
  }

  const exportLedger = () => {
    const payload = JSON.stringify({ exported_at: new Date().toISOString(), entries: auditLedger.all() }, null, 2)
    const blob = new Blob([payload], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = 'aegis-audit-ledger.json'
    a.click()
    auditLedger.append('demo-user', role, 'audit.export', 'ledger.json', { count: auditLedger.size() })
  }

  return (
    <div className="modal-backdrop" onClick={() => openModal(null)}>
      <section className="modal glass" onClick={(ev) => ev.stopPropagation()} aria-label="Audit ledger" style={{ width: 'min(920px, 94vw)' }}>
        <button className="modal-close" onClick={() => openModal(null)} aria-label="Close">✕</button>
        <div className="panel-title">Audit Ledger</div>
        <h3>{auditLedger.size()} entries · tamper-evident hash chain</h3>
        <p className="modal-sub">Append-only · entry_hash chains each record to its predecessor (§12.2).</p>

        <div style={{ display: 'flex', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}>
          <input className="input" style={{ flex: 1, minWidth: 200 }} placeholder="Filter by action / actor / resource…"
            value={query} onChange={(e) => setQuery(e.target.value)} />
          <button className="btn btn-primary" onClick={verify}>🔐 Verify chain</button>
          <button className="btn" onClick={exportLedger}>⬇ Export JSON</button>
        </div>

        {result && <div className="verify-result">{result}</div>}

        <div style={{ maxHeight: '44vh', overflow: 'auto' }}>
          <table className="audit-table">
            <thead><tr><th>Seq</th><th>Time</th><th>Actor</th><th>Role</th><th>Action</th><th>Resource</th><th>Hash</th></tr></thead>
            <tbody>
              {filtered.map((e) => (
                <tr key={e.seq}>
                  <td>{e.seq}</td>
                  <td>{e.ts.slice(11, 23)}</td>
                  <td>{e.actor}</td>
                  <td>{e.role}</td>
                  <td className="c-cyan">{e.action}</td>
                  <td>{e.resource}</td>
                  <td className="hash-ok">{e.entry_hash.slice(0, 14)}…</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
