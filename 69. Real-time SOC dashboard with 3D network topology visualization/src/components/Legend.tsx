import type { BHNode, EdgeType, NodeHealth } from '../types';
import { EDGE_TECHNIQUES } from '../lib/algorithms';
import { HEALTH_LABEL } from '../lib/sim/templates';

export const KIND_META: Record<
  BHNode['kind'],
  { label: string; color: string }
> = {
  user: { label: 'User', color: 'var(--c-user)' },
  computer: { label: 'Computer', color: 'var(--c-computer)' },
  group: { label: 'Group', color: 'var(--c-group)' },
  domain: { label: 'Domain', color: 'var(--c-domain)' },
};

const HEALTH_COLORS: Record<NodeHealth, string> = {
  healthy: '#00E676',
  warning: '#FFB300',
  critical: '#FF1744',
  offline: '#9E9E9E',
  investigation: '#2979FF',
  quarantined: '#7E57C2',
};

const HEALTH_ORDER: NodeHealth[] = ['healthy', 'warning', 'critical', 'offline', 'investigation', 'quarantined'];

const EDGE_ORDER: EdgeType[] = [
  'MemberOf',
  'HasSession',
  'AdminTo',
  'GenericAll',
  'GenericWrite',
  'WriteDacl',
  'AllExtendedRights',
  'ForceChangePassword',
  'AddMember',
  'CanRDP',
  'Owns',
];

export function Legend() {
  return (
    <div className="card legend">
      <div className="legend-title">Node types</div>
      <div className="legend-grid">
        {(Object.keys(KIND_META) as BHNode['kind'][]).map((k) => (
          <div className="legend-item" key={k}>
            <span className="legend-swatch swatch-node" style={{ background: KIND_META[k].color }} />
            <span>{KIND_META[k].label}</span>
          </div>
        ))}
        <div className="legend-item">
          <span className="legend-swatch swatch-node" style={{ background: 'var(--c-path)' }} />
          <span>Attack path</span>
        </div>
        <div className="legend-item">
          <span className="legend-swatch swatch-node halo-dot halo-owned" />
          <span>Owned</span>
        </div>
        <div className="legend-item">
          <span className="legend-swatch swatch-node halo-dot halo-hv" />
          <span>High value</span>
        </div>
      </div>
      <div className="legend-title">Live state</div>
      <div className="legend-grid">
        {HEALTH_ORDER.map((h) => (
          <div className="legend-item" key={h}>
            <span className="legend-swatch swatch-node" style={{ background: HEALTH_COLORS[h] }} />
            <span>{HEALTH_LABEL[h]}</span>
          </div>
        ))}
        <div className="legend-item">
          <span className="legend-swatch swatch-edge" style={{ background: '#F7DC6F' }} />
          <span>Live traffic</span>
        </div>
      </div>
      <div className="legend-title">Relationships</div>
      <div className="legend-grid">
        {EDGE_ORDER.map((t) => (
          <div className="legend-item" key={t}>
            <span className="legend-swatch swatch-edge" style={{ background: EDGE_TECHNIQUES[t].color }} />
            <span>{EDGE_TECHNIQUES[t].label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}