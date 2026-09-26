import { useCallback, useMemo, useRef, useState } from 'react';
import type { AttackPath, BHNode, NodeHealth, PathHop, SocState } from '../../types';
import { generateBloodHoundGraph, TARGET_NODE_ID } from '../../lib/graphData';
import { buildAdjacency, reachabilityAnalysis, shortestPath } from '../../lib/algorithms';
import { SceneCanvas } from '../SceneCanvas';
import { SearchBar } from '../SearchBar';
import { SidePanel } from '../SidePanel';
import { Legend } from '../Legend';
import { StatsBar } from '../StatsBar';
import { HelpOverlay } from '../HelpOverlay';

const model = generateBloodHoundGraph();
const adj = buildAdjacency(model.edges);
const report = reachabilityAnalysis(model, adj, TARGET_NODE_ID);
const nodeById = new Map(model.nodes.map((n) => [n.id, n]));

function buildAttackPath(fromId: string): AttackPath | null {
  const res = shortestPath(adj, fromId, TARGET_NODE_ID);
  if (!res.found) return null;
  const hops: PathHop[] = res.hops.map((h) => {
    const fromNode = nodeById.get(h.fromDir === 'source' ? h.edge.source : h.edge.target)!;
    const toNode = nodeById.get(h.fromDir === 'source' ? h.edge.target : h.edge.source)!;
    return { edge: h.edge, from: fromNode, to: toNode };
  });
  return { hops, totalHops: hops.length, fromOwned: false };
}

function pickDefaultSeed(): string | null {
  let best: { id: string; len: number } | null = null;
  for (const n of report.ownedNodes) {
    const res = shortestPath(adj, n.id, TARGET_NODE_ID);
    if (res.found) {
      const len = res.hops.length;
      if (!best || len < best.len) best = { id: n.id, len };
    }
  }
  return best?.id ?? null;
}

const DEFAULT_SEED = pickDefaultSeed();

function formatPathHops(path: AttackPath | null): string {
  if (!path) return '';
  return path.hops
    .map((h, i) => `${i + 1}. ${h.from.name} --[${h.edge.type}]--> ${h.to.name}`)
    .join('\n');
}

interface TopologyModuleProps {
  state: SocState;
}

const STATS_TARGET = TARGET_NODE_ID.replace('GROUP-', '');

export function TopologyModule({ state }: TopologyModuleProps) {
  const [selectedId, setSelectedId] = useState<string | null>(DEFAULT_SEED);
  const [planMode, setPlanMode] = useState(false);
  const [helpShown, setHelpShown] = useState(false);
  const [feedOpen, setFeedOpen] = useState(true);
  const [focusReq, setFocusReq] = useState<{ id: string; nonce: number } | null>(null);
  const [copied, setCopied] = useState(false);
  const focusReqRef = useRef(focusReq);
  focusReqRef.current = focusReq;

  const selectedNode: BHNode | null = selectedId ? (nodeById.get(selectedId) ?? null) : null;

  const attackPath = useMemo(
    () => (selectedId ? buildAttackPath(selectedId) : null),
    [selectedId],
  );

  const pathEdgeIds = useMemo(() => {
    const s = new Set<string>();
    for (const h of attackPath?.hops ?? []) s.add(h.edge.id);
    return s;
  }, [attackPath]);

  const handleSelect = useCallback((id: string | null) => {
    setSelectedId(id);
  }, []);

  const handleSearchPick = useCallback((id: string) => {
    setSelectedId(id);
    setFocusReq((r) => ({ id, nonce: (r?.nonce ?? 0) + 1 }));
  }, []);

  const handleFocus = useCallback((id: string) => {
    setFocusReq((r) => ({ id, nonce: (r?.nonce ?? 0) + 1 }));
  }, []);

  const handleSelectHop = useCallback((id: string) => {
    handleFocus(id);
  }, [handleFocus]);

  const handleCopyPath = useCallback(async () => {
    const base = selectedNode?.name ?? '';
    const text = selectedNode
      ? `${selectedNode.name} → ${STATS_TARGET}\n${formatPathHops(attackPath)}`
      : base;
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  }, [selectedNode, attackPath]);

  const healthById = state.nodeHealth;

  const topologyFeed = useMemo(() => state.stream.filter((s) => s.module === 'topology').slice(0, 8), [state.stream]);

  const stats = [
    { label: 'Nodes', value: model.nodes.length },
    { label: 'Relationships', value: model.edges.length },
    { label: 'Users', value: model.nodes.filter((n) => n.kind === 'user').length },
    { label: 'Computers', value: model.nodes.filter((n) => n.kind === 'computer').length },
    { label: 'Owned seeds', value: report.ownedNodes.length, tone: 'danger' as const },
    { label: 'Exposed surface', value: report.exposedNodeIds.size, tone: 'warn' as const },
    { label: 'Can reach DA', value: report.canReachTarget.size - 1, tone: 'accent' as const },
    {
      label: 'Watchlist',
      value: Object.values(healthById).filter((h): h is NodeHealth => h !== 'healthy' && h !== undefined).length,
      tone: state.alerts.some((a) => a.severity === 'critical') ? ('danger' as const) : ('warn' as const),
    },
  ];

  return (
    <div className={`topology-module ${planMode ? 'bh-plan' : ''}`}>
      <div className="module-toolbar">
        <SearchBar
          nodes={model.nodes}
          onPick={handleSearchPick}
          onClearSelection={() => setSelectedId(null)}
        />
        <button
          className={`icon-btn wide ${planMode ? 'active' : ''}`}
          onClick={() => setPlanMode((p) => !p)}
          title="Toggle 2D plan view"
        >
          {planMode ? '3D' : '2D'}
        </button>
        <button
          className="icon-btn wide"
          onClick={() => {
            setPlanMode(false);
            setFocusReq((r) => ({ id: '', nonce: (r?.nonce ?? 0) + 1 }));
          }}
          title="Reset camera"
        >
          ⌂
        </button>
        <span className="toolbar-hint">Select a node to trace the shortest attack path toward {STATS_TARGET}</span>
      </div>

      <div className="stats-zone">
        <StatsBar stats={stats} />
      </div>

      <main className="viewport">
        <SceneCanvas
          nodes={model.nodes}
          edges={model.edges}
          positions={model.positions}
          selectedId={selectedId}
          pathEdgeIds={pathEdgeIds}
          planMode={planMode}
          focusReq={focusReq}
          nodeHealth={healthById}
          trafficEdges={state.trafficEdges}
          onSelect={handleSelect}
        />

        <SidePanel
          node={selectedNode}
          attackPath={attackPath}
          targetName={STATS_TARGET}
          health={selectedNode ? healthById[selectedNode.id] : undefined}
          onFocus={handleSelectHop}
          onSelectHop={handleSelectHop}
          onCopyPath={() => void handleCopyPath()}
          onClear={() => setSelectedId(null)}
        />

        {feedOpen && (
          <div className="card live-feed">
            <div className="live-feed-head">
              <span>Live topology events</span>
              <button className="icon-btn tiny" onClick={() => setFeedOpen(false)} aria-label="Close feed">
                ×
              </button>
            </div>
            <div className="live-feed-body">
              {topologyFeed.length === 0 && <div className="live-feed-empty">Waiting for topology events…</div>}
              {topologyFeed.map((line) => (
                <div className="live-feed-item" key={line.id}>
                  <span className="live-feed-time">
                    {new Date(line.ts).toLocaleTimeString('en-GB', { hour12: false })}
                  </span>
                  <span className="live-feed-text">{line.text}</span>
                </div>
              ))}
            </div>
          </div>
        )}
        {!feedOpen && (
          <button className="fab-btn live-feed-reopen" onClick={() => setFeedOpen(true)} title="Open topology feed">
            ◔
          </button>
        )}

        {copied && <div className="toast">Path copied to clipboard</div>}
      </main>

      <Legend />
      <HelpOverlay shown={helpShown} onToggle={() => setHelpShown((s) => !s)} />
    </div>
  );
}