import type { SocModule } from '../types';

export const MODULES: { id: SocModule; label: string; short: string; icon: string }[] = [
  { id: 'topology', label: '3D Topology', short: 'TOP', icon: '◉' },
  { id: 'blanket', label: 'Blanket Map', short: 'MAP', icon: '▦' },
  { id: 'alerts', label: 'Alert Triage', short: 'ALR', icon: '⚠' },
  { id: 'incidents', label: 'Incidents', short: 'INC', icon: '⚑' },
  { id: 'query', label: 'Query Studio', short: 'QRY', icon: '⌕' },
  { id: 'intel', label: 'Threat Intel', short: 'INT', icon: '✦' },
  { id: 'compliance', label: 'Compliance', short: 'CMP', icon: '✓' },
];

interface NavRailProps {
  active: SocModule;
  onChange: (m: SocModule) => void;
  alertCount: number;
  incidentCount: number;
}

export function NavRail({ active, onChange, alertCount, incidentCount }: NavRailProps) {
  const badgeFor = (id: SocModule) =>
    id === 'alerts' ? alertCount : id === 'incidents' ? incidentCount : 0;

  return (
    <nav className="nav-rail" aria-label="SOC modules">
      {MODULES.map((m) => {
        const badge = badgeFor(m.id);
        return (
          <button
            key={m.id}
            className={`nav-item ${active === m.id ? 'active' : ''}`}
            onClick={() => onChange(m.id)}
            title={m.label}
            aria-label={m.label}
          >
            <span className="nav-icon">{m.icon}</span>
            <span className="nav-label">{m.short}</span>
            {badge > 0 && <span className="nav-badge">{badge > 99 ? '99+' : badge}</span>}
          </button>
        );
      })}
    </nav>
  );
}