import type { BHNode, NodeHealth } from '../types';
import type { AttackPath } from '../types';
import { EDGE_TECHNIQUES } from '../lib/algorithms';
import { HEALTH_LABEL } from '../lib/sim/templates';
import { KIND_META } from './Legend';

interface SidePanelProps {
  node: BHNode | null;
  attackPath: AttackPath | null;
  targetName: string;
  health?: NodeHealth;
  onFocus: (id: string) => void;
  onSelectHop: (id: string) => void;
  onCopyPath: () => void;
  onClear: () => void;
}

const HEALTH_COLOR: Record<NodeHealth, string> = {
  healthy: 'var(--good)',
  warning: 'var(--warn)',
  critical: 'var(--danger)',
  offline: '#9E9E9E',
  investigation: '#2979FF',
  quarantined: '#7E57C2',
};

export function SidePanel({
  node,
  attackPath,
  targetName,
  health,
  onFocus,
  onSelectHop,
  onCopyPath,
  onClear,
}: SidePanelProps) {
  if (!node) {
    return (
      <aside className="card side-panel">
        <div className="panel-head">
          <h2>Attack Surface</h2>
        </div>
        <div className="panel-body empty">
          <p>
            Select any node in the 3D scene or search above to compute the{' '}
            <strong>shortest attack path</strong> toward the high-value target{' '}
            <strong>{targetName}</strong>.
          </p>
          <p className="hint">Drag to orbit · Scroll to zoom · Right-drag to pan</p>
        </div>
      </aside>
    );
  }

  const kind = KIND_META[node.kind];
  const hops = attackPath?.hops ?? [];

  return (
    <aside className="card side-panel">
      <div className="panel-head">
        <div className="node-title-row">
          <span className={`node-kind-icon kind-${node.kind}`}>{kind.label}</span>
          <h2 title={node.name}>{node.label}</h2>
        </div>
        <button className="icon-btn" onClick={onClear} aria-label="Close panel">
          ×
        </button>
      </div>

      <div className="panel-body">
        <div className="badge-row">
          {node.owned && <span className="badge badge-danger">OWNED</span>}
          {node.highValue && <span className="badge badge-warn">HIGH VALUE</span>}
          {health && health !== 'healthy' && (
            <span className="badge-health" style={{ color: HEALTH_COLOR[health], borderColor: HEALTH_COLOR[health] }}>
              {HEALTH_LABEL[health]}
            </span>
          )}
          <span className="badge badge-ghost">{node.domain}</span>
          {node.dept && <span className="badge badge-ghost">{node.dept.toUpperCase()}</span>}
          {node.kind === 'computer' && node.os && (
            <span className="badge badge-ghost">{node.os}</span>
          )}
          {!node.enabled && <span className="badge badge-ghost">DISABLED</span>}
        </div>

        <p className="node-desc">{node.description}</p>

        <div className="section-title">
          Attack path to {targetName}
          <span className="section-title-right">
            {attackPath
              ? hops.length === 0
                ? 'target reached'
                : `${hops.length} hop${hops.length > 1 ? 's' : ''}`
              : 'unreachable'}
          </span>
        </div>

        {attackPath ? (
          <>
            <ol className="hop-list">
              {hops.map((hop, i) => {
                const t = EDGE_TECHNIQUES[hop.edge.type];
                const dir =
                  hop.edge.type === 'HasSession'
                    ? ` ⇄ ${hop.to.name}`
                    : hop.from.name === hop.edge.source
                      ? ` → ${hop.to.name}`
                      : ` ⇠ ${hop.to.name}`;
                return (
                  <li key={hop.edge.id} className="hop">
                    <div className="hop-seq">{i + 1}</div>
                    <div className="hop-body">
                      <div className="hop-line">
                        <span className="hop-from" onClick={() => onFocus(hop.from.id)}>
                          {hop.from.name}
                        </span>
                        <span className="hop-dir">{dir}</span>
                      </div>
                      <span className="edge-badge" style={{ background: t.color }}>
                        {hop.edge.type}
                      </span>
                      <span className="tech-badge">{t.technique}</span>
                      <div className="tooltip-text">{t.usedOn}</div>
                    </div>
                    <button
                      className="hop-focus"
                      onClick={() => onSelectHop(hop.from.id)}
                      aria-label="Focus this hop"
                      title="Focus hop in scene"
                    >
                      ◎
                    </button>
                  </li>
                );
              })}
            </ol>
            <div className="panel-actions">
              <button className="btn btn-primary" onClick={onCopyPath}>
                Copy path
              </button>
              <button className="btn" onClick={() => onFocus(node.id)}>
                Focus node
              </button>
            </div>
          </>
        ) : (
          <div className="no-path">
            <p>
              No path from <strong>{node.name}</strong> to {targetName}.
            </p>
            <button className="btn" onClick={onCopyPath}>
              Copy node
            </button>
          </div>
        )}
      </div>
    </aside>
  );
}