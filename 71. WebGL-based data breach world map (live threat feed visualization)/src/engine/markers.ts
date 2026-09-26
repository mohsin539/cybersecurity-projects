/**
 * AEGIS-SENTINEL — Impact markers & shockwaves (architecture.md §4.4):
 * severity-colored glow sprites + expanding shockwave rings at impact point.
 */
import * as THREE from 'three'
import { SEVERITY_COLORS } from '../domain/sources'
import { latLonToVec3, GLOBE_RADIUS } from './latLon'
import type { Severity } from '../domain/types'

export interface MarkerHandle {
  event_id: string
  sprite: THREE.Sprite
  material: THREE.SpriteMaterial
  baseScale: number
}

function glowTexture(color: string): THREE.Texture {
  const size = 64
  const canvas = document.createElement('canvas')
  canvas.width = size
  canvas.height = size
  const ctx = canvas.getContext('2d')!
  const grad = ctx.createRadialGradient(32, 32, 0, 32, 32, 32)
  grad.addColorStop(0, 'rgba(255,255,255,1)')
  grad.addColorStop(0.25, color)
  grad.addColorStop(1, 'rgba(0,0,0,0)')
  ctx.fillStyle = grad
  ctx.fillRect(0, 0, size, size)
  const tex = new THREE.CanvasTexture(canvas)
  return tex
}

const SEV_SCALE: Record<Severity, number> = {
  low: 0.03, medium: 0.04, high: 0.05, critical: 0.07, 'zero-day': 0.075,
}

export function createMarker(eventId: string, lat: number, lon: number, severity: Severity): MarkerHandle {
  const color = SEVERITY_COLORS[severity] ?? '#ff1e56'
  const material = new THREE.SpriteMaterial({
    map: glowTexture(color),
    transparent: true,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
  })
  const sprite = new THREE.Sprite(material)
  const pos = latLonToVec3(lat, lon, GLOBE_RADIUS * 1.005)
  sprite.position.copy(pos)
  const baseScale = SEV_SCALE[severity] ?? 0.04
  sprite.scale.setScalar(baseScale)
  sprite.userData.event_id = eventId
  return { event_id: eventId, sprite, material, baseScale }
}

export function disposeMarker(handle: MarkerHandle): void {
  handle.material.map?.dispose()
  handle.material.dispose()
}

// ---------- Shockwaves ----------

export interface ShockwaveHandle {
  mesh: THREE.Mesh
  material: THREE.MeshBasicMaterial
  age: number
  ttl: number
}

const RING_VERT = 'void main() { gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0); }'
const RING_FRAG = [
  'uniform vec3 uColor;',
  'uniform float uOpacity;',
  'void main() { gl_FragColor = vec4(uColor, uOpacity); }',
].join('\n')

export function createShockwave(lat: number, lon: number, severity: Severity): ShockwaveHandle {
  const geo = new THREE.RingGeometry(0.02, 0.028, 32)
  const color = SEVERITY_COLORS[severity] ?? '#ff1e56'
  const material = new THREE.MeshBasicMaterial({
    color,
    transparent: true,
    opacity: 0.85,
    side: THREE.DoubleSide,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
    vertexShader: RING_VERT,
    fragmentShader: RING_FRAG,
  } as THREE.MeshBasicMaterialParameters)
  const mesh = new THREE.Mesh(geo, material)
  const pos = latLonToVec3(lat, lon, GLOBE_RADIUS * 1.002)
  mesh.position.copy(pos)
  mesh.lookAt(pos.clone().multiplyScalar(2))
  const ttl = severity === 'critical' || severity === 'zero-day' ? 2.4 : 1.6
  return { mesh, material, age: 0, ttl }
}

export function disposeShockwave(handle: ShockwaveHandle): void {
  handle.mesh.geometry.dispose()
  handle.material.dispose()
}
