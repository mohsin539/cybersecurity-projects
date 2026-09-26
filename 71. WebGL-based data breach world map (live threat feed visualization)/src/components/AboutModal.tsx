/**
 * AEGIS-SENTINEL — About modal: framework mapping summary (architecture.md §10, §16).
 */
import { useUiStore } from '../state/uiStore'

export function AboutModal() {
  const modal = useUiStore((s) => s.modal)
  const openModal = useUiStore((s) => s.openModal)
  if (modal !== 'about') return null
  return (
    <div className="modal-backdrop" onClick={() => openModal(null)}>
      <section className="modal glass" onClick={(ev) => ev.stopPropagation()} aria-label="About">
        <button className="modal-close" onClick={() => openModal(null)} aria-label="Close">✕</button>
        <div className="panel-title">About</div>
        <h3>🌍 AEGIS-SENTINEL v1.0.0</h3>
        <p className="modal-sub">WebGL global data-breach &amp; live threat feed visualization — secure by design, auditable by default.</p>
        <dl className="kv">
          <dt>ISO 27001</dt><dd>Annex A mapping — control register (§16.1)</dd>
          <dt>NIST</dt><dd>CSF 2.0 GV/ID/PR/DE/RS/RC · 800-53 families</dd>
          <dt>OWASP</dt><dd>Top 10 mitigations · ASVS L2 (L3 for audit svc)</dd>
          <dt>Reports</dt><dd>CSV · JSON · STIX 2.1 · HTML/PDF · Audit Pack — signed</dd>
          <dt>Audit</dt><dd>SHA-256 hash-chained ledger · verify + export</dd>
          <dt>Privacy</dt><dd>CSP strict · no tracking · data stays in-tab</dd>
        </dl>
        <p className="c-muted" style={{ fontSize: 11 }}>
          Demo build: feeds are a deterministic local simulator. The pipeline contract matches
          the production WSS stream client (architecture.md §9.1).
        </p>
      </section>
    </div>
  )
}
