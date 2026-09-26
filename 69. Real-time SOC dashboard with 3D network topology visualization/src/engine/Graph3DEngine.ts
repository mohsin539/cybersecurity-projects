import * as THREE from 'three';
import { OrbitControls } from 'three/examples/jsm/controls/OrbitControls.js';
import type { BHEdge, BHNode, EdgeType, NodeHealth, Vec3 } from '../types';

export interface EngineCallbacks {
  onNodeSelect: (id: string | null) => void;
}

export interface EngineProps {
  nodes: BHNode[];
  edges: BHEdge[];
  positions: Record<string, Vec3>;
}

interface NodeMeta {
  id: string;
  kind: BHNode['kind'];
  pos: THREE.Vector3;
}

interface KindVisual {
  geometry: THREE.BufferGeometry;
  color: number;
  size: number;
}

export const KIND_COLORS: Record<BHNode['kind'], number> = {
  user: 0x3ec6ff,
  computer: 0x2ee6a8,
  group: 0xffb020,
  domain: 0xff4d6d,
};

export const EDGE_BASE_COLORS: Record<EdgeType, number> = {
  Owns: 0xff5470,
  MemberOf: 0x8a6dff,
  HasSession: 0x2ee6a8,
  AdminTo: 0xffb020,
  GenericAll: 0xff5470,
  GenericWrite: 0xff5470,
  WriteDacl: 0xff5470,
  AllExtendedRights: 0xff5470,
  ForceChangePassword: 0xff5470,
  AddMember: 0xff5470,
  CanRDP: 0x5c7cfa,
};

const PATH_EDGE_COLOR = 0xffe95c;
const SELECTED_COLOR = 0x53f6ff;
export const TRAFFIC_COLOR = 0xf7dc6f;

export const HEALTH_COLORS: Record<NodeHealth, number> = {
  healthy: 0x00e676,
  warning: 0xffb300,
  critical: 0xff1744,
  offline: 0x9e9e9e,
  investigation: 0x2979ff,
  quarantined: 0x7e57c2,
};

function edgeGeometry(edges: BHEdge[], positions: Record<string, Vec3>): THREE.BufferGeometry {
  const verts: number[] = [];
  const colors: number[] = [];
  for (const e of edges) {
    const s = positions[e.source];
    const t = positions[e.target];
    if (!s || !t) continue;
    const c = new THREE.Color(EDGE_BASE_COLORS[e.type]);
    c.multiplyScalar(0.55);
    verts.push(s.x, s.y, s.z, t.x, t.y, t.z);
    colors.push(c.r, c.g, c.b, c.r, c.g, c.b);
  }
  const geo = new THREE.BufferGeometry();
  geo.setAttribute('position', new THREE.Float32BufferAttribute(verts, 3));
  geo.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3));
  return geo;
}

export class Graph3DEngine {
  private container: HTMLElement;
  private props: EngineProps;
  private cbs: EngineCallbacks;

  private renderer: THREE.WebGLRenderer;
  private scene = new THREE.Scene();
  private camera: THREE.PerspectiveCamera;
  private controls: OrbitControls;
  private raycaster = new THREE.Raycaster();
  private pointer = new THREE.Vector2(1e9, 1e9);

  private meshes: Map<BHNode['kind'], THREE.InstancedMesh> = new Map();
  private metas: NodeMeta[] = [];
  private metaByKind: Map<BHNode['kind'], NodeMeta[]> = new Map();
  private baseEdges!: THREE.LineSegments;

  private haloOwned!: THREE.Sprite;
  private haloHighValue!: THREE.Sprite;
  private haloSelected!: THREE.Sprite;

  private pathMeshes: THREE.Object3D[] = [];
  private labelLayer!: HTMLDivElement;
  private labels = new Map<string, HTMLDivElement>();

  private selectedId: string | null = null;
  private pathNodeIds = new Set<string>();

  private nodeStates: Record<string, NodeHealth> = {};
  private trafficLines: { line: THREE.Line; mat: THREE.LineDashedMaterial; ttl: number }[] = [];

  private animId = 0;
  private clock = new THREE.Clock();
  private disposed = false;

  private focusTarget: { pos: THREE.Vector3; done: boolean; t: number } | null = null;
  private planMode = false;
  private planTargetPos: THREE.Vector3 | null = null;
  private planTargetTarget: THREE.Vector3 | null = null;
  private cameraLerp = 6;

  onResize?: () => void;

  constructor(container: HTMLElement, props: EngineProps, cbs: EngineCallbacks) {
    this.container = container;
    this.props = props;
    this.cbs = cbs;

    const w = container.clientWidth || 1;
    const h = container.clientHeight || 1;

    this.renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    this.renderer.setSize(w, h);
    this.renderer.setClearColor(0x070b14, 1);
    container.appendChild(this.renderer.domElement);

    this.camera = new THREE.PerspectiveCamera(55, w / h, 0.1, 2000);
    this.camera.position.set(52, 34, 66);

    this.controls = new OrbitControls(this.camera, this.renderer.domElement);
    this.controls.enableDamping = true;
    this.controls.dampingFactor = 0.08;
    this.controls.minDistance = 4;
    this.controls.maxDistance = 260;
    this.controls.target.set(0, 12, 0);
    this.controls.addEventListener('start', () => this.cbs.onNodeSelect(null));

    this.scene.fog = new THREE.FogExp2(0x070b14, 0.0065);

    // stars
    const starGeo = new THREE.BufferGeometry();
    const n = 600;
    const sa = new Float32Array(n * 3);
    for (let i = 0; i < n; i++) {
      sa[i * 3] = (Math.random() - 0.5) * 600;
      sa[i * 3 + 1] = (Math.random() - 0.5) * 600;
      sa[i * 3 + 2] = (Math.random() - 0.5) * 600;
    }
    starGeo.setAttribute('position', new THREE.BufferAttribute(sa, 3));
    const stars = new THREE.Points(
      starGeo,
      new THREE.PointsMaterial({ color: 0x3b4f77, size: 0.35, transparent: true, opacity: 0.7 }),
    );
    this.scene.add(stars);

    // floor grid
    const grid = new THREE.GridHelper(200, 40, 0x16305e, 0x101a33);
    grid.position.y = 0.1;
    (grid.material as THREE.Material).transparent = true;
    (grid.material as THREE.Material).opacity = 0.5;
    this.scene.add(grid);

    this.buildNodes();
    this.buildEdges();
    this.buildHalos();
    this.buildLabels();

    this.raycaster.far = 500;

    this.bindPointer();
    window.addEventListener('resize', this.handleResize);
    window.addEventListener('keydown', this.handleKey);

    this.loop();
  }

  // ---------------------------------------------------------------- build

  private kindVisual(kind: BHNode['kind']): KindVisual {
    switch (kind) {
      case 'user':
        return {
          geometry: new THREE.SphereGeometry(0.55, 12, 12),
          color: KIND_COLORS.user,
          size: 1,
        };
      case 'computer':
        return {
          geometry: new THREE.BoxGeometry(1.1, 1.1, 1.1),
          color: KIND_COLORS.computer,
          size: 1,
        };
      case 'group':
        return {
          geometry: new THREE.OctahedronGeometry(0.8),
          color: KIND_COLORS.group,
          size: 1.15,
        };
      case 'domain':
        return {
          geometry: new THREE.IcosahedronGeometry(1.6, 0),
          color: KIND_COLORS.domain,
          size: 2.1,
        };
    }
  }

  private buildNodes() {
    const byKind = new Map<BHNode['kind'], BHNode[]>();
    for (const kind of ['user', 'computer', 'group', 'domain'] as BHNode['kind'][]) {
      byKind.set(kind, []);
    }
    for (const n of this.props.nodes) byKind.get(n.kind)?.push(n);

    for (const [kind, nodes] of byKind) {
      if (nodes.length === 0) continue;
      const vis = this.kindVisual(kind);
      const mat = new THREE.MeshStandardMaterial({
        color: vis.color,
        emissive: vis.color,
        emissiveIntensity: 0.45,
        roughness: 0.35,
        metalness: 0.15,
      });
      const mesh = new THREE.InstancedMesh(vis.geometry, mat, nodes.length);
      mesh.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
      this.meshes.set(kind, mesh);
      this.scene.add(mesh);

      const matrix = new THREE.Matrix4();
      const quat = new THREE.Quaternion();
      const scale = new THREE.Vector3();
      const pos = new THREE.Vector3();
      const metas: NodeMeta[] = [];
      nodes.forEach((n, i) => {
        const p = this.props.positions[n.id];
        pos.set(p?.x ?? 0, p?.y ?? 0, p?.z ?? 0);
        quat.setFromEuler(new THREE.Euler(Math.random() * Math.PI, Math.random() * Math.PI, Math.random() * Math.PI));
        scale.setScalar(vis.size);
        matrix.compose(pos, quat, scale);
        mesh.setMatrixAt(i, matrix);
        mesh.setColorAt(i, new THREE.Color(KIND_COLORS[kind]));
        metas.push({ id: n.id, kind, pos: pos.clone() });
      });
      mesh.instanceMatrix.needsUpdate = true;
      if (mesh.instanceColor) mesh.instanceColor.needsUpdate = true;
      this.metaByKind.set(kind, metas);
      this.metas.push(...metas);
    }
  }

  private buildEdges() {
    this.baseEdges = new THREE.LineSegments(
      edgeGeometry(this.props.edges, this.props.positions),
      new THREE.LineBasicMaterial({ vertexColors: true, transparent: true, opacity: 0.62 }),
    );
    this.scene.add(this.baseEdges);
  }

  private makeHalo(texture: THREE.Texture, r: number, g: number, b: number): THREE.Sprite {
    const mat = new THREE.SpriteMaterial({
      map: texture,
      color: new THREE.Color(r, g, b),
      transparent: true,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });
    const spr = new THREE.Sprite(mat);
    spr.scale.setScalar(6);
    spr.visible = false;
    this.scene.add(spr);
    return spr;
  }

  private buildHalos() {
    const canvas = document.createElement('canvas');
    canvas.width = 128;
    canvas.height = 128;
    const ctx = canvas.getContext('2d')!;
    const grad = ctx.createRadialGradient(64, 64, 8, 64, 64, 62);
    grad.addColorStop(0, 'rgba(255,255,255,0.95)');
    grad.addColorStop(0.25, 'rgba(255,255,255,0.45)');
    grad.addColorStop(1, 'rgba(255,255,255,0)');
    ctx.fillStyle = grad;
    ctx.beginPath();
    ctx.arc(64, 64, 62, 0, Math.PI * 2);
    ctx.fill();
    const tex = new THREE.CanvasTexture(canvas);
    this.haloOwned = this.makeHalo(tex, 1, 0.28, 0.4);
    this.haloHighValue = this.makeHalo(tex, 1, 0.75, 0.14);
    this.haloSelected = this.makeHalo(tex, 0.38, 1, 1);
  }

  private buildLabels() {
    this.labelLayer = document.createElement('div');
    this.labelLayer.className = 'bh-label-layer';
    this.labelLayer.style.pointerEvents = 'none';
    this.container.appendChild(this.labelLayer);

    for (const n of this.props.nodes) {
      const div = document.createElement('div');
      div.className = 'bh-label';
      div.dataset.id = n.id;
      div.innerHTML = `<span class="bh-label-icon" data-kind="${n.kind}"></span><span class="bh-label-text">${n.label}</span>`;
      this.labelLayer.appendChild(div);
      this.labels.set(n.id, div);
    }
  }

  // ---------------------------------------------------------------- input

  private bindPointer() {
    const el = this.renderer.domElement;
    el.addEventListener('pointermove', (ev) => {
      const rect = el.getBoundingClientRect();
      this.pointer.set(
        ((ev.clientX - rect.left) / rect.width) * 2 - 1,
        -((ev.clientY - rect.top) / rect.height) * 2 + 1,
      );
    });
    el.addEventListener('pointerdown', (ev) => {
      const rect = el.getBoundingClientRect();
      const x = ((ev.clientX - rect.left) / rect.width) * 2 - 1;
      const y = -((ev.clientY - rect.top) / rect.height) * 2 + 1;
      const hit = this.pick(x, y);
      this.cbs.onNodeSelect(hit ? hit.id : null);
    });
  }

  private pick(x: number, y: number): NodeMeta | null {
    this.raycaster.setFromCamera(new THREE.Vector2(x, y), this.camera);
    let best: { id: string; dist: number } | null = null;
    for (const [kind, mesh] of this.meshes) {
      const hits = this.raycaster.intersectObject(mesh, false);
      if (hits.length === 0) continue;
      const instanceId = hits[0].instanceId;
      if (instanceId == null) continue;
      const meta = (this.metaByKind.get(kind) ?? [])[instanceId];
      if (meta && (!best || hits[0].distance < best.dist)) {
        best = { id: meta.id, dist: hits[0].distance };
      }
    }
    return best ? (this.metas.find((m) => m.id === best!.id) ?? null) : null;
  }

  private handleKey = (ev: KeyboardEvent) => {
    if (ev.key === 'Escape') this.cbs.onNodeSelect(null);
  };

  private handleResize = () => {
    if (this.disposed) return;
    const w = this.container.clientWidth || 1;
    const h = this.container.clientHeight || 1;
    this.camera.aspect = w / h;
    this.camera.updateProjectionMatrix();
    this.renderer.setSize(w, h);
    this.onResize?.();
  };

  // ---------------------------------------------------------------- selection & path

  setSelection(selectedId: string | null, pathEdgeIds: Set<string>) {
    this.selectedId = selectedId;
    this.pathNodeIds.clear();

    if (selectedId) {
      // dim non-selected non-path nodes
      this.recolorNodes();
      this.pathMeshes.forEach((m) => this.scene.remove(m));
      this.pathMeshes = [];
      return;
    }

    // build path highlight
    this.pathMeshes.forEach((m) => this.scene.remove(m));
    this.pathMeshes = [];
    const pathEdges = this.props.edges.filter((e) => pathEdgeIds.has(e.id));
    for (const pe of pathEdges) {
      const s = this.props.positions[pe.source];
      const t = this.props.positions[pe.target];
      if (!s || !t) continue;
      const pts = [s.x, s.y, s.z, t.x, t.y, t.z];
      const geo = new THREE.BufferGeometry();
      geo.setAttribute('position', new THREE.Float32BufferAttribute(pts, 3));
      const mat = new THREE.LineDashedMaterial({
        color: PATH_EDGE_COLOR,
        dashSize: 0.7,
        gapSize: 0.55,
        linewidth: 1,
        transparent: true,
        opacity: 0.95,
      });
      const line = new THREE.Line(geo, mat);
      line.computeLineDistances();
      this.scene.add(line);
      this.pathMeshes.push(line);

      // head arrow marker at target end
      const dir = new THREE.Vector3(t.x - s.x, t.y - s.y, t.z - s.z).normalize();
      const head = new THREE.Mesh(
        new THREE.ConeGeometry(0.16, 0.55, 8),
        new THREE.MeshBasicMaterial({ color: PATH_EDGE_COLOR }),
      );
      head.position.set(t.x, t.y, t.z);
      head.position.addScaledVector(dir, -0.8);
      head.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), dir);
      this.scene.add(head);
      this.pathMeshes.push(head);
    }

    if (pathEdgeIds.size > 0) {
      const involved = new Set<string>();
      for (const pe of pathEdges) {
        involved.add(pe.source);
        involved.add(pe.target);
      }
      this.pathNodeIds = involved;
    }
    this.recolorNodes();
  }

  setNodeStates(states: Record<string, NodeHealth>) {
    this.nodeStates = states;
    this.recolorNodes();
  }

  pulseTraffic(edgeIds: string[]) {
    for (const id of edgeIds) {
      if (this.trafficLines.some((t) => t.line.userData.edgeId === id)) continue;
      const e = this.props.edges.find((ed) => ed.id === id);
      if (!e) continue;
      const s = this.props.positions[e.source];
      const t = this.props.positions[e.target];
      if (!s || !t) continue;
      const geo = new THREE.BufferGeometry();
      geo.setAttribute('position', new THREE.Float32BufferAttribute([s.x, s.y, s.z, t.x, t.y, t.z], 3));
      const mat = new THREE.LineDashedMaterial({
        color: TRAFFIC_COLOR,
        dashSize: 0.5,
        gapSize: 0.6,
        transparent: true,
        opacity: 0.9,
      });
      const line = new THREE.Line(geo, mat);
      line.computeLineDistances();
      line.userData.edgeId = id;
      this.scene.add(line);
      this.trafficLines.push({ line, mat, ttl: 0 });
    }
  }

  private healthColorFor(id: string): number | null {
    const state = this.nodeStates[id];
    if (!state || state === 'healthy') return null;
    return HEALTH_COLORS[state];
  }

  private recolorNodes() {
    for (const [kind, mesh] of this.meshes) {
      const metas = this.metaByKind.get(kind) ?? [];
      metas.forEach((m, i) => {
        let color: number = KIND_COLORS[kind];
        const healthColor = this.healthColorFor(m.id);
        if (m.id === this.selectedId) color = SELECTED_COLOR;
        else if (this.pathNodeIds.has(m.id)) color = PATH_EDGE_COLOR;
        else if (healthColor !== null) color = healthColor;
        mesh.setColorAt(i, new THREE.Color(color));
      });
      if (mesh.instanceColor) mesh.instanceColor.needsUpdate = true;
    }
  }

  // ---------------------------------------------------------------- camera

  focusNode(id: string) {
    const p = this.props.positions[id];
    if (!p) return;
    const target = new THREE.Vector3(p.x, p.y, p.z);
    const dir = this.camera.position.clone().sub(this.controls.target);
    const dist = Math.max(10, dir.length());
    const pos = target.clone().add(dir.normalize().multiplyScalar(dist * 0.55));
    pos.y = Math.max(pos.y, 14);
    this.focusTarget = { pos, done: false, t: 0 };
    this.planTargetPos = pos;
    this.planTargetTarget = target;
  }

  setPlanMode(enabled: boolean) {
    this.planMode = enabled;
    if (enabled) {
      this.planTargetPos = new THREE.Vector3(0, 120, 0.01);
      this.planTargetTarget = new THREE.Vector3(0, 8, 0);
    }
  }

  resetCamera() {
    this.planMode = false;
    this.planTargetPos = new THREE.Vector3(52, 34, 66);
    this.planTargetTarget = new THREE.Vector3(0, 12, 0);
    this.focusTarget = { pos: this.planTargetPos.clone(), done: false, t: 0 };
  }

  // ---------------------------------------------------------------- loop

  private loop = () => {
    if (this.disposed) return;
    this.animId = requestAnimationFrame(this.loop);
    const dt = this.clock.getDelta();
    const t = this.clock.elapsedTime;

    this.controls.update();

    // focus lerp
    if (this.focusTarget && !this.focusTarget.done) {
      this.focusTarget.t += dt * this.cameraLerp;
      const k = Math.min(1, this.focusTarget.t);
      this.camera.position.lerp(this.planTargetPos!, THREE.MathUtils.smoothstep(k, 0, 1));
      this.controls.target.lerp(this.planTargetTarget!, THREE.MathUtils.smoothstep(k, 0, 1));
      if (k >= 1) this.focusTarget.done = true;
    } else if (this.planMode && this.planTargetPos) {
      this.camera.position.lerp(this.planTargetPos, dt * 3);
      this.controls.target.lerp(this.planTargetTarget!, dt * 3);
    }

    // instanced rotation
    for (const [kind, mesh] of this.meshes) {
      const rot = kind === 'group' || kind === 'domain' ? t * 0.18 : 0;
      const metas = this.metaByKind.get(kind) ?? [];
      metas.forEach((m, i) => {
        const mx = new THREE.Matrix4();
        mx.makeRotationY(rot + m.pos.x * 0.01);
        const base = kind === 'user' ? 1 : kind === 'computer' ? 1 : kind === 'group' ? 1.15 : 2.1;
        const pulse =
          this.healthColorFor(m.id) === HEALTH_COLORS.critical ||
          this.healthColorFor(m.id) === HEALTH_COLORS.quarantined ||
          this.nodeStates[m.id] === 'investigation'
            ? 1 + Math.sin(t * 5 + m.pos.x) * 0.16
            : 1;
        const scale = base * pulse;
        mx.scale(new THREE.Vector3(scale, scale, scale));
        mx.setPosition(m.pos);
        mesh.setMatrixAt(i, mx);
      });
      mesh.instanceMatrix.needsUpdate = true;
    }

    // pulse path edges
    let dashShift = 0;
    for (const m of this.pathMeshes) {
      const mat = (m as THREE.Line).material as unknown as { dashSize?: number; dashOffset: number };
      if (mat?.dashSize !== undefined) {
        dashShift += dt * 0.9;
        mat.dashOffset = -dashShift;
      }
    }

    // live traffic lines (decay + corpse removal)
    for (const tl of this.trafficLines) {
      tl.ttl += dt;
      (tl.mat as unknown as { dashOffset: number }).dashOffset = -tl.ttl * 1.6;
      tl.mat.opacity = Math.max(0, 0.9 * (1 - tl.ttl / 2.4));
    }
    if (this.trafficLines.length > 0) {
      const alive: typeof this.trafficLines = [];
      for (const tl of this.trafficLines) {
        if (tl.ttl < 2.4) {
          alive.push(tl);
        } else {
          this.scene.remove(tl.line);
          tl.line.geometry.dispose();
          tl.mat.dispose();
        }
      }
      this.trafficLines = alive;
    }

    // halos
    this.positionHalo(this.haloSelected, this.selectedId, 4.4 + Math.sin(t * 4) * 0.6);
    this.positionHalo(this.haloHighValue, this.primaryHighValueId(), 3.6 + Math.sin(t * 3) * 0.5);
    this.positionHalo(this.haloOwned, this.selectedId ?? this.primaryOwnedId(), 4.1 + Math.sin(t * 5) * 0.7);

    // hover highlight on meshes via emissive not supported per-instance; skip

    this.updateLabelLOD(t);
    this.renderer.render(this.scene, this.camera);
  };

  private positionHalo(sprite: THREE.Sprite, id: string | null, scale: number) {
    if (!id) {
      sprite.visible = false;
      return;
    }
    const p = this.props.positions[id];
    if (!p) {
      sprite.visible = false;
      return;
    }
    sprite.visible = true;
    sprite.position.set(p.x, p.y, p.z);
    sprite.scale.setScalar(scale);
  }

  private primaryHighValueId(): string | null {
    return this.props.nodes.find((n) => n.highValue)?.id ?? null;
  }

  private primaryOwnedId(): string | null {
    return this.props.nodes.find((n) => n.owned)?.id ?? null;
  }

  private updateLabelLOD(t: number) {
    const showAll = this.container.closest('.bh-plan') !== null;
    const sel = this.selectedId;
    for (const n of this.props.nodes) {
      const div = this.labels.get(n.id);
      if (!div) continue;
      const p = this.props.positions[n.id];
      if (!p) {
        div.style.display = 'none';
        continue;
      }
      const v = new THREE.Vector3(p.x, p.y, p.z);
      const dist = this.camera.position.distanceTo(v);
      const isPath = this.pathNodeIds.has(n.id);
      const isSelected = n.id === sel;
      const visible = showAll || isPath || isSelected || dist < 22;
      div.style.display = visible ? 'flex' : 'none';
      if (!visible) continue;
      v.project(this.camera);
      if (v.z > 1) {
        div.style.display = 'none';
        continue;
      }
      const w = this.renderer.domElement.clientWidth;
      const h = this.renderer.domElement.clientHeight;
      const x = (v.x * 0.5 + 0.5) * w;
      const y = (-v.y * 0.5 + 0.5) * h;
      const pulse = isSelected || isPath ? 1 + Math.sin(t * 6) * 0.1 : 1;
      div.style.transform = `translate(-50%, -130%) scale(${pulse})`;
      div.style.left = `${x}px`;
      div.style.top = `${y}px`;
      div.classList.toggle('bh-label-path', isPath || isSelected);
    }
  }

  dispose() {
    this.disposed = true;
    cancelAnimationFrame(this.animId);
    window.removeEventListener('resize', this.handleResize);
    window.removeEventListener('keydown', this.handleKey);
    for (const tl of this.trafficLines) {
      this.scene.remove(tl.line);
      tl.line.geometry.dispose();
      tl.mat.dispose();
    }
    this.trafficLines = [];
    this.renderer.dispose();
    this.labelLayer.remove();
    this.renderer.domElement.remove();
  }
}