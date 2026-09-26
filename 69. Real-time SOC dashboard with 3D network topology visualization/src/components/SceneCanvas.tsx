import { useEffect, useRef } from 'react';
import type { BHEdge, BHNode, NodeHealth, Vec3 } from '../types';
import { Graph3DEngine } from '../engine/Graph3DEngine';

interface SceneCanvasProps {
  nodes: BHNode[];
  edges: BHEdge[];
  positions: Record<string, Vec3>;
  selectedId: string | null;
  pathEdgeIds: Set<string>;
  planMode: boolean;
  focusReq: { id: string; nonce: number } | null;
  nodeHealth?: Record<string, NodeHealth>;
  trafficEdges?: string[];
  onSelect: (id: string | null) => void;
}

export function SceneCanvas({
  nodes,
  edges,
  positions,
  selectedId,
  pathEdgeIds,
  planMode,
  focusReq,
  nodeHealth = {},
  trafficEdges = [],
  onSelect,
}: SceneCanvasProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const engineRef = useRef<Graph3DEngine | null>(null);
  const onSelectRef = useRef(onSelect);
  onSelectRef.current = onSelect;

  useEffect(() => {
    if (!containerRef.current) return;
    const engine = new Graph3DEngine(
      containerRef.current,
      { nodes, edges, positions },
      { onNodeSelect: (id) => onSelectRef.current(id) },
    );
    engineRef.current = engine;
    if (Object.keys(nodeHealth).length > 0) engine.setNodeStates(nodeHealth);
    return () => {
      engine.dispose();
      engineRef.current = null;
    };
  }, [nodes, edges, positions]);

  useEffect(() => {
    engineRef.current?.setSelection(selectedId, pathEdgeIds);
  }, [selectedId, pathEdgeIds]);

  useEffect(() => {
    engineRef.current?.setPlanMode(planMode);
  }, [planMode]);

  useEffect(() => {
    if (focusReq) {
      if (focusReq.id) {
        engineRef.current?.focusNode(focusReq.id);
        engineRef.current?.setSelection(focusReq.id, pathEdgeIds);
      } else {
        engineRef.current?.resetCamera();
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusReq]);

  useEffect(() => {
    engineRef.current?.setNodeStates(nodeHealth);
  }, [nodeHealth]);

  useEffect(() => {
    if (trafficEdges.length > 0) engineRef.current?.pulseTraffic(trafficEdges);
  }, [trafficEdges]);

  return <div ref={containerRef} className="scene-canvas" />;
}