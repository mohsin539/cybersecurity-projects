/**
 * AEGIS-SENTINEL — Event drill-down drawer (architecture.md §2.2, §4.5)
 */
import { useThreatStore } from '../state/threatStore'
import { useUiStore } from '../state/uiStore'
import { CATEGORY_LABELS, SOURCE_BY_ID } from '../domain/sources'
import { auditLedger } from '../security/auditLedger'
import { allow } from '../security/rbac'

export function EventDrawer() {
  const selected = useThreatStore((s) => s.selected)
  const select = useThreatStore((s) => s.select)
  const role = useUiStore((s) => s.role)
  const pushToast = useUiStore((s) => s.pushToast)

  if (!selected) return null
  const e = selected

  const copyIoc = (value: string) => {
    if (!allow(role, 'ioc.copy')) {
      pushToast('critical', 'Access denied: ioc.copy requires analyst+ role')
      return
    }
    void navigator.clipboard?.writeText(value).catch(() => undefined)
    auditLedger.append('demo-user', role, 'ioc.copy', `ioc:${value.slice(0, 40)}`)
    pushToast('success', 'IOC copied to clipboard')
  }

  return (
    <aside className="drawer glass" aria-label="Event details">
      <button className="modal-close" onClick={() => select(null)} aria-label="Close">✕</button>
      <div className="panel-title">Event Detail</div>
      <h3 style={{ marginTop: 8 }}>{e.title}</h3>
      <span className={'chip chip-' + e.severity}>{e.severity.toUpperCase()} · risk {e.risk_score}</span>

      <dl className="kv">
        <dt>Category</dt><dd>{CATEGORY_LABELS[e.category]}</dd>
        <dt>Event ID</dt><dd>{e.event_id}</dd>
        <dt>STIX ID</dt><dd>{e.stix_id.slice(0, 28)}…</dd>
        <dt>Origin</dt><dd>{e.geo.src.country} ({e.geo.src.lat.toFixed(2)}, {e.geo.src.lon.toFixed(2)}) ASN {e.geo.src.asn}</dd>
        <dt>Target</dt><dd>{e.geo.dst.country} ({e.geo.dst.lat.toFixed(2)}, {e.geo.dst.lon.toFixed(2)})</dd>
        <dt>Records</dt><dd>{e.impact.records.toLocaleString()}</dd>
        <dt>PII classes</dt><dd>{e.impact.pii_classes.join(', ')}</dd>
        <dt>ATT&amp;CK</dt><dd>{e.techniques.join(', ')}</dd>
        <dt>Occurred</dt><dd>{new Date(e.occurred_at).toLocaleString()}</dd>
        <dt>Content hash</dt><dd>{e.content_hash.slice(0, 24)}…</dd>
      </dl>

      <div className="panel-title">Indicators of Compromise</div>
      <div className="ioc-list">
        {e.indicators.map((ioc, i) => (
          <button key={i} className="ioc" onClick={() => copyIoc(ioc.value)} title="Click to copy">
            [{ioc.type}] {ioc.value.length > 34 ? ioc.value.slice(0, 34) + '…' : ioc.value}
          </button>
        ))}
      </div>

      <div className="panel-title">Provenance</div>
      <dl className="kv">
        {e.sources.map((s) => (
          <div key={s.source_id} style={{ display: 'contents' }}>
            <dt>{SOURCE_BY_ID.get(s.source_id)?.name ?? s.source_id}</dt>
            <dd>trust {s.trust_tier} · seen {new Date(s.first_seen).toLocaleTimeString()}</dd>
          </div>
        ))}
      </dl>

      <div className="drawer-actions">
        <button className="btn btn-primary" onClick={() => useUiStore.getState().openModal('reports')}>📄 Export as report</button>
        <button className="btn" onClick={() => pushToast('info', `Trace route to ${e.geo.dst.country} (demo)`)}>🕵️ Trace</button>
      </div>
      <p className="c-muted" style={{ fontSize: 10 }}>
        Viewing this event recorded <code>globe.event_select</code> in the audit ledger.
      </p>
    </aside>
  )
}
