/**
 * AEGIS-SENTINEL — Verify modal (architecture.md §11.3 /verify portal analog).
 */
import { useState } from 'react'
import { useUiStore } from '../state/uiStore'
import { auditLedger } from '../security/auditLedger'
import { verifySignature } from '../security/crypto'

export function VerifyModal() {
  const modal = useUiStore((s) => s.modal)
  const openModal = useUiStore((s) => s.openModal)
  const role = useUiStore((s) => s.role)
  const [digest, setDigest] = useState('')
  const [sig, setSig] = useState('')
  const [pub, setPub] = useState('')
  const [result, setResult] = useState<string | null>(null)

  if (modal !== 'verify') return null

  const verify = () => {
    try {
      const provenance = { digest, note: 'manual-verification' }
      const ok = verifySignature(provenance, sig.trim(), pub.trim())
      const header = ok
        ? '✓ SIGNATURE VALID — Ed25519 over canonical digest'
        : '✗ SIGNATURE INVALID — do not trust this export'
      setResult(
        `${header}\n\ndigest:  sha256:${digest || '(none)'}\nsig:     ${sig.slice(0, 48) || '(none)'}…\npubkey:  ${pub.slice(0, 48) || '(none)'}…\n\n` +
        'Offline check: entry_hash = SHA256(canonical_json(payload) + "|" + prev_hash)\n' +
        'Audit chain head (this session): ' + auditLedger.headHash().slice(0, 40) + '…',
      )
      auditLedger.append('demo-user', role, 'report.verify', 'verify-portal', { ok })
    } catch {
      setResult('✗ Malformed input — hex fields required.')
    }
  }

  return (
    <div className="modal-backdrop" onClick={() => openModal(null)}>
      <section className="modal glass" onClick={(ev) => ev.stopPropagation()} aria-label="Verify signature">
        <button className="modal-close" onClick={() => openModal(null)} aria-label="Close">✕</button>
        <div className="panel-title">Verify Export</div>
        <h3>Report signature verification</h3>
        <p className="modal-sub">
          Paste the digest, Ed25519 signature and public key from any report footer (§11.3).
        </p>
        <div style={{ display: 'grid', gap: 8 }}>
          <input className="input" placeholder="Report digest (sha256 hex)" value={digest} onChange={(e) => setDigest(e.target.value)} />
          <input className="input" placeholder="Signature (Ed25519 hex)" value={sig} onChange={(e) => setSig(e.target.value)} />
          <input className="input" placeholder="Public key (Ed25519 hex)" value={pub} onChange={(e) => setPub(e.target.value)} />
          <button className="btn btn-primary" onClick={verify}>🔐 Verify</button>
        </div>
        {result && <div className="verify-result">{result}</div>}
      </section>
    </div>
  )
}
