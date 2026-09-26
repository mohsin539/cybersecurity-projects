import { useEffect, useMemo, useState } from 'react';
import { Canvas } from '@react-three/fiber';
import { OrbitControls } from '@react-three/drei';
import { Vector3 } from 'three';

interface GraphNode { id: string; name: string; type: string; tier0?: boolean }
interface GraphEdge { id: string; source: string; target: string; type: string }
interface Subgraph { nodes: GraphNode[]; edges: GraphEdge[] }

const TYPE_COLOR: Record<string, string> = {
  Domain: '#ff4d4f', User: '#36cfc9', Group: '#ffca28', Computer: '#4caf50',
  OU: '#9e9eff', GPO: '#ff7a45', Container: '#8a8a8a',
};

const FALLBACK: Subgraph = {
  nodes: [
    { id: 'root', name: 'DEMO.LOCAL', type: 'Domain', tier0: true },
    { id: 'u1', name: 'ALICE', type: 'User' },
    { id: 'u2', name: 'BOB', type: 'User' },
    { id: 'g1', name: 'HELPDESK', type: 'Group' },
    { id: 'c1', name: 'DC01', type: 'Computer', tier0: true },
  ],
  edges: [
    { id: 'e1', source: 'root', target: 'g1', type: 'Contains' },
    { id: 'e2', source: 'u1', target: 'g1', type: 'MemberOf' },
    { id: 'e3', source: 'u2', target: 'g1', type: 'MemberOf' },
    { id: 'e4', source: 'g1', target: 'c1', type: 'AdminTo' },
  ],
};

function useSubgraph(seed: string): Subgraph {
  const [data, setData] = useState<Subgraph>({ nodes: [], edges: [] });
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const res = await fetch('/api/graphql', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ operation: 'GetSubgraph', variables: { seed, maxDepth: 4 } }),
        });
        const json = (await res.json()) as { data: Subgraph };
        if (!cancelled && json.data) setData(json.data);
        else if (!cancelled) setData(FALLBACK);
      } catch {
        if (!cancelled) setData(FALLBACK);
      }
    })();
    return () => { cancelled = true; };
  }, [seed]);
  return data;
}

function layout(sub: Subgraph): Map<string, Vector3> {
  const pos = new Map<string, Vector3>();
  const n = sub.nodes.length;
  sub.nodes.forEach((node, i) => {
    const golden = Math.PI * (3 - Math.sqrt(5));
    const y = 1 - (i / Math.max(n - 1, 1)) * 2;
    const r = Math.sqrt(Math.max(1 - y * y, 0));
    const th = golden * i;
    pos.set(node.id, new Vector3(Math.cos(th) * r * 6, y * 6, Math.sin(th) * r * 6));
  });
  return pos;
}

function EdgeLine({ edge, a, b }: { edge: GraphEdge; a: Vector3; b: Vector3 }) {
  const color = edge.type === 'AdminTo' || edge.type === 'GenericAll' ? '#ff4d4f' : '#3d5afe';
  return (
    <line>
      <bufferGeometry>
        <bufferAttribute attach="attributes-position" args={[new Float32Array([a.x, a.y, a.z, b.x, b.y, b.z]), 3]} />
      </bufferGeometry>
      <lineBasicMaterial color={color} linewidth={1} />
    </line>
  );
}

export function App() {
  const sub = useSubgraph('node-4004');
  const pos = useMemo(() => layout(sub), [sub]);
  const [picked, setPicked] = useState<GraphNode | null>(null);

  return (
    <div style={{ position: 'relative', width: '100vw', height: '100vh' }}>
      <Canvas camera={{ position: [0, 2, 14], fov: 60 }} dpr={[1, 2]}>
        <ambientLight intensity={0.45} />
        <directionalLight position={[10, 10, 5]} intensity={1.1} />
        <OrbitControls enableDamping makeDefault />
        {sub.edges.map((e) => {
          const a = pos.get(e.source);
          const b = pos.get(e.target);
          if (!a || !b) return null;
          return <EdgeLine key={e.id} edge={e} a={a} b={b} />;
        })}
        {sub.nodes.map((n) => {
          const p = pos.get(n.id);
          if (!p) return null;
          return (
            <mesh key={n.id} position={p} onClick={() => setPicked(n)}>
              <sphereGeometry args={[0.55, 24, 24]} />
              <meshStandardMaterial
                color={n.tier0 ? '#ff4d4f' : (TYPE_COLOR[n.type] ?? '#9aa0b5')}
                emissive={n.tier0 ? '#610b0d' : '#0b1020'}
                emissiveIntensity={n.tier0 ? 1 : 0.25}
              />
            </mesh>
          );
        })}
      </Canvas>
      <div style={{ position: 'absolute', top: 16, left: 16, zIndex: 5, fontSize: 13 }}>
        <strong style={{ color: '#ffca28' }}>PathSphere 3D</strong>{' '}
        <span style={{ color: '#8a93a8' }}>· Interactive attack-path visualizer (demo data)</span>
      </div>
      <div style={{ position: 'absolute', top: 16, right: 16, zIndex: 5, fontSize: 12, color: '#8a93a8' }}>
        nodes {sub.nodes.length} · edges {sub.edges.length} · click a node to inspect
      </div>
      {picked && (
        <div
          style={{
            position: 'absolute', bottom: 16, left: 16, zIndex: 5,
            background: 'rgba(16,22,38,0.92)', border: '1px solid #2a3550',
            padding: '10px 14px', borderRadius: 8, fontSize: 12,
          }}
        >
          <div>
            <strong>{picked.name}</strong>{' '}
            <span style={{ color: TYPE_COLOR[picked.type] ?? '#9aa0b5' }}>{picked.type}</span>
          </div>
          <div style={{ color: '#8a93a8' }}>id: {picked.id} {picked.tier0 ? '· TIER 0' : ''}</div>
        </div>
      )}
    </div>
  );
}