/**
 * AEGIS-SENTINEL — Top HUD (architecture.md §4.4)
 */
import { useThreatStore } from '../state/threatStore'
import { computeStats } from '../state/threatStore'
import { useUiStore } from '../state/uiStore'
import { auditLedger } from '../security/auditLedger'
import { allow } from '../security/rbac'
import type { Role } from '../security/rbac'

const fmt = new Intl.NumberFormat('en', { notation: 'compact', maximumFractionDigits: 1 })

export function Hud() {
  const visible = useThreatStore((s) => s.visible)
  const lastUpdate = useThreatStore((s) => s.lastUpdate)
  const stats = computeStats(visible)
  const role = useUiStore((s) => s.role)
  const setRole = useUiStore((s) => s.setRole)
  const openModal = useUiStore((s) => s.openModal)
  const pushToast = useUiStore((s) => s.pushToast)

  const onRole = (r: Role) => {
    setRole(r)
    auditLedger.append('demo-user', r, 'auth.session_role_switch', `role:${r}`)
  }

  const openReports = () => {
    if (!allow(role, 'report.request')) {
      pushToast('critical', 'Access denied: report.request requires analyst+ role (OPA deny)')
      return
    }
    auditLedger.append('demo-user', role, 'ui.modal_open', 'modal:reports')
    openModal('reports')
  }

  const openAudit = () => {
    if (!allow(role, 'audit.view')) {
      pushToast('critical', 'Access denied: audit.view requires auditor role (OPA deny)')
      return
    }
    auditLedger.append('demo-user', role, 'audit.view', 'ledger')
    openModal('audit')
  }

  return (
    <header className="hud glass">
      <div className="hud-logo">🌍 AEGIS-SENTINEL</div>
      <div className="hud-stats">
        <div className="stat"><b>{fmt.format(stats.total)}</b><span>Events</span></div>
        <div className="stat"><b className="c-critical">{stats.bySeverity.critical + stats.bySeverity['zero-day']}</b><span>Critical</span></div>
        <div className="stat"><b>{fmt.format(stats.records)}</b><span>Records</span></div>
        <div className="stat"><b className="c-cyan">{stats.avgRisk.toFixed(1)}</b><span>Avg risk</span></div>
        <div className="stat"><b>{fmt.format(auditLedger.size())}</b><span>Audit seq</span></div>
      </div>
      <div className="hud-spacer" />
      <span className="conn"><span className="live-dot" /> Live</span>
      <span className="c-muted" style={{ fontSize: 10 }}>
        {lastUpdate ? new Date(lastUpdate).toLocaleTimeString() : '—'}
      </span>
      <select className="select" value={role} onChange={(e) => onRole(e.target.value as Role)} aria-label="Session role">
        <option value="viewer">viewer</option>
        <option value="analyst">analyst</option>
        <option value="auditor">auditor</option>
        <option value="admin">admin</option>
      </select>
      <div className="hud-actions">
        <button className="btn btn-primary" onClick={openReports}>📄 Reports</button>
        <button className="btn" onClick={openAudit}>🧾 Audit</button>
        <button className="btn" onClick={() => openModal('verify')}>🔐 Verify</button>
      </div>
    </header>
  )
}
