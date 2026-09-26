/**
 * AEGIS-SENTINEL — Report modal (architecture.md §11): format picker,
 * generation with SHA-256 digest + Ed25519 signature, download.
 */
import { useState } from 'react'
import { useThreatStore } from '../state/threatStore'
import { useUiStore } from '../state/uiStore'
import { generateReport, downloadBlob, type ReportFormat } from '../reports/generator'
import { auditLedger } from '../security/auditLedger'
import { allow } from '../security/rbac'

const FORMATS: { id: ReportFormat; icon: string; title: string; desc: string }[] = [
  { id: 'html', icon: '📕', title: 'Executive HTML/PDF', desc: 'Branded brief — print to PDF (Ctrl+P)' },
  { id: 'csv', icon: '📃', title: 'CSV', desc: 'RFC 4180 flat export for SIEM/data lakes' },
  { id: 'json', icon: '🧬', title: 'JSON', desc: 'Canonical ThreatEvent[] + provenance' },
  { id: 'stix', icon: '🛡️', title: 'STIX 2.1', desc: 'Bundle for TIP / Splunk ES interop' },
  { id: 'audit-pack', icon: '🧾', title: 'Audit Pack', desc: 'Ledger slice + chain proof + signatures' },
]

export function ReportModal() {
  const visible = useThreatStore((s) => s.visible)
  const filter = useThreatStore((s) => s.filter)
  const modal = useUiStore((s) => s.modal)
  const openModal = useUiStore((s) => s.openModal)
  const role = useUiStore((s) => s.role)
  const pushToast = useUiStore((s) => s.pushToast)
  const [busy, setBusy] = useState<string | null>(null)
  const [lastDigest, setLastDigest] = useState<string | null>(null)

  if (modal !== 'reports') return null

  const generate = async (format: ReportFormat) => {
    if (!allow(role, 'report.download')) {
      pushToast('critical', 'Access denied: report.download requires analyst+ role')
      return
    }
    setBusy(format)
    auditLedger.append('demo-user', role, 'report.request', `report:${format}`, { count: visible.length })
    try {
      const result = await generateReport({
        format,
        events: visible,
        filtersSummary: {
          severities: filter.severities, categories: filter.categories,
          minRisk: filter.minRisk, windowMinutes: filter.windowMinutes,
        },
        actor: 'demo-user',
        role,
        asOf: new Date(),
      })
      downloadBlob(result.blob, result.filename)
      setLastDigest(result.digest)
      auditLedger.append('demo-user', role, 'report.generate', result.filename, {
        digest: result.digest, signature: result.signature.signature_hex.slice(0, 32) + '…',
        alg: result.signature.algorithm, events: visible.length,
      })
      auditLedger.append('demo-user', role, 'report.download', result.filename, { digest: result.digest })
      pushToast('success', `Signed report ready — sha256:${result.digest.slice(0, 16)}…`)
    } catch {
      pushToast('critical', 'Report generation failed — see console')
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="modal-backdrop" onClick={() => openModal(null)}>
      <section className="modal glass" onClick={(ev) => ev.stopPropagation()} aria-label="Reports">
        <button className="modal-close" onClick={() => openModal(null)} aria-label="Close">✕</button>
        <div className="panel-title">Report Downloads</div>
        <h3>Export the current view — {visible.length} events</h3>
        <p className="modal-sub">
          Every export is a point-in-time snapshot, SHA-256 digested, Ed25519 signed and logged to the audit ledger (§11.3).
        </p>
        <div className="report-grid">
          {FORMATS.map((f) => (
            <button key={f.id} className="report-opt" disabled={busy !== null} onClick={() => generate(f.id)}>
              <b>{f.icon} {f.title}</b>
              <span>{busy === f.id ? 'Generating…' : f.desc}</span>
            </button>
          ))}
        </div>
        {lastDigest && (
          <p className="c-muted mono" style={{ fontSize: 10 }}>
            Last digest: sha256:{lastDigest}
          </p>
        )}
        <p className="c-muted" style={{ fontSize: 10 }}>
          HTML/PDF opens as a printable branded report; Audit Pack includes chain verification (§12.4).
        </p>
      </section>
    </div>
  )
}
