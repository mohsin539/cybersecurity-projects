/**
 * AEGIS-SENTINEL — Threat arcs (architecture.md §5.2): bezier tubes with
 * animated dash flow, severity gradient, additive blending, selection boost.
 */
import * as THREE from 'three'
import { SEVERITY_COLORS } from '../domain/sources'
import { latLonToVec3, GLOBE_RADIUS } from './latLon'
import type { Severity } from '../domain/types'

const VERT = [
  'varying vec2 vUv;',
  'void main() {',
  '  vUv = uv;',
  '  gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);',
  '}',
].join('\n')

const FRAG = [
  'uniform vec3 uColorA;',
  'uniform vec3 uColorB;',
  'uniform float uTime;',
  'uniform float uBoost;',
  'varying vec2 vUv;',
  'void main() {',
  '  float flow = fract(vUv.x * 24.0 - uTime * 2.2);',
  '  float dash = smoothstep(0.0, 0.35, flow) * smoothstep(1.0, 0.65, flow);',
  '  float feather = smoothstep(0.0, 0.12, vUv.x) * (1.0 - smoothstep(0.88, 1.0, vUv.x));',
  '  vec3 col = mix(uColorA, uColorB, vUv.x);',
  '  float alpha = (0.25 + 0.75 * dash) * feather * uBoost;',
  '  gl_FragColor = vec4(col * (1.0 + uBoost * 0.8), alpha);',
  '}',
].join('\n')

export interface ArcHandle {
  event_id: string
  mesh: THREE.Mesh
  material: THREE.ShaderMaterial
  severity: Severity
}

export function createArc(
  eventId: string,
  src: { lat: number; lon: number },
  dst: { lat: number; lon: number },
  severity: Severity,
  selected: boolean,
): ArcHandle {
  const a = latLonToVec3(src.lat, src.lon, GLOBE_RADIUS * 1.01)
  const b = latLonToVec3(dst.lat, dst.lon, GLOBE_RADIUS * 1.01)
  const mid = a.clone().add(b).multiplyScalar(0.5)
  const lift = 1 + a.distanceTo(b) * 0.35
  mid.normalize().multiplyScalar(GLOBE_RADIUS * lift)

  const curve = new THREE.QuadraticBezierCurve3(a, mid, b)
  const geo = new THREE.TubeGeometry(curve, 32, 0.0045, 6, false)

  const sevColor = new THREE.Color(SEVERITY_COLORS[severity] ?? '#ff1e56')
  const material = new THREE.ShaderMaterial({
    vertexShader: VERT,
    fragmentShader: FRAG,
    transparent: true,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
    uniforms: {
      uColorA: { value: new THREE.Color('#00f0ff') },
      uColorB: { value: sevColor },
      uTime: { value: Math.random() * 10 },
      uBoost: { value: selected ? 1.6 : 1.0 },
    },
  })

  const mesh = new THREE.Mesh(geo, material)
  return { event_id: eventId, mesh, material, severity }
}

export function disposeArc(handle: ArcHandle): void {
  handle.mesh.geometry.dispose()
  handle.material.dispose()
}
