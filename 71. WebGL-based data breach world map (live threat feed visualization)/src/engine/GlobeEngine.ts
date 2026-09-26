/**
 * AEGIS-SENTINEL — GlobeEngine (architecture.md §5): render loop orchestration,
 * event diffing, raycast picking, cinematic/director modes, perf metrics.
 */
import * as THREE from 'three'
import { EffectComposer } from 'three/examples/jsm/postprocessing/EffectComposer.js'
import { RenderPass } from 'three/examples/jsm/postprocessing/RenderPass.js'
import { UnrealBloomPass } from 'three/examples/jsm/postprocessing/UnrealBloomPass.js'
import { buildGlobe, buildAtmosphere, buildStars, buildLandDotsPoints } from './globe'
import { createArc, disposeArc, type ArcHandle } from './arcs'
import { createMarker, disposeMarker, createShockwave, disposeShockwave, type MarkerHandle, type ShockwaveHandle } from './markers'
import type { ThreatEvent } from '../domain/types'

const MAX_ARCS = 250
const MAX_SHOCKWAVES = 60

export interface PerfSample {
  fps: number
  frameMs: number
  drawCalls: number
  arcs: number
}

export class GlobeEngine {
  cinematic = false
  directorMode = false
  onCritical: ((e: ThreatEvent) => void) | null = null

  private renderer: THREE.WebGLRenderer
  private scene = new THREE.Scene()
  private camera: THREE.PerspectiveCamera
  private composer: EffectComposer
  private bloom: UnrealBloomPass
  private arcGroup = new THREE.Group()
  private markerGroup = new THREE.Group()
  private waveGroup = new THREE.Group()
  private globeGroup = new THREE.Group()
  private arcs = new Map<string, ArcHandle>()
  private markers = new Map<string, MarkerHandle[]>()
  private waves: ShockwaveHandle[] = []
  private raycaster = new THREE.Raycaster()
  private clock = new THREE.Clock()
  private raf = 0
  private resizeObs: ResizeObserver
  private frames = 0
  private fpsTime = 0
  private lastPerf: PerfSample = { fps: 0, frameMs: 0, drawCalls: 0, arcs: 0 }

  constructor(private canvas: HTMLCanvasElement) {
    this.renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: false })
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    this.renderer.setClearColor(0x050716)
    this.camera = new THREE.PerspectiveCamera(42, 1, 0.1, 200)
    this.camera.position.set(0, 0.6, 2.6)

    this.scene.add(new THREE.AmbientLight(0x404a6b, 1.1))
    const key = new THREE.DirectionalLight(0x8899ff, 1.2)
    key.position.set(3, 2, 4)
    this.scene.add(key)

    this.globeGroup.add(buildGlobe())
    this.globeGroup.add(buildAtmosphere())
    this.globeGroup.add(buildLandDotsPoints())
    this.scene.add(this.globeGroup)
    this.scene.add(buildStars())
    this.scene.add(this.arcGroup, this.markerGroup, this.waveGroup)

    this.composer = new EffectComposer(this.renderer)
    this.composer.addPass(new RenderPass(this.scene, this.camera))
    this.bloom = new UnrealBloomPass(new THREE.Vector2(1, 1), 0.9, 0.55, 0.18)
    this.composer.addPass(this.bloom)

    this.resizeObs = new ResizeObserver(() => this.resize())
    this.resizeObs.observe(canvas.parentElement ?? canvas)
    this.resize()
    this.loop()
  }

  private resize(): void {
    const el = this.canvas.parentElement ?? this.canvas
    const w = el.clientWidth || 1
    const h = el.clientHeight || 1
    this.camera.aspect = w / h
    this.camera.updateProjectionMatrix()
    this.renderer.setSize(w, h, false)
    this.composer.setSize(w, h)
  }

  setEvents(events: ThreatEvent[], selectedId: string | null): void {
    const seen = new Set<string>()
    for (const e of events) {
      seen.add(e.event_id)
      if (!this.arcs.has(e.event_id)) this.addEvent(e)
    }
    for (const [id, arc] of this.arcs) {
      if (!seen.has(id)) {
        this.arcGroup.remove(arc.mesh)
        disposeArc(arc)
        const ms = this.markers.get(id)
        if (ms) {
          for (const m of ms) {
            this.markerGroup.remove(m.sprite)
            disposeMarker(m)
          }
          this.markers.delete(id)
        }
        this.arcs.delete(id)
      }
    }
    for (const [id, arc] of this.arcs) {
      arc.material.uniforms.uBoost.value = id === selectedId ? 1.8 : 1.0
    }
  }

  private addEvent(e: ThreatEvent): void {
    if (this.arcs.size >= MAX_ARCS) this.evictLowest()
    try {
      const arc = createArc(e.event_id, e.geo.src, e.geo.dst, e.severity, false)
      this.arcs.set(e.event_id, arc)
      this.arcGroup.add(arc.mesh)
      const ms = [
        createMarker(e.event_id, e.geo.src.lat, e.geo.src.lon, e.severity),
        createMarker(e.event_id, e.geo.dst.lat, e.geo.dst.lon, e.severity),
      ]
      this.markers.set(e.event_id, ms)
      for (const m of ms) this.markerGroup.add(m.sprite)
      if (e.severity === 'critical' || e.severity === 'zero-day') {
        if (this.waves.length < MAX_SHOCKWAVES) {
          const w = createShockwave(e.geo.dst.lat, e.geo.dst.lon, e.severity)
          this.waves.push(w)
          this.waveGroup.add(w.mesh)
        }
        this.onCritical?.(e)
      }
    } catch {
      // Skip malformed geometry — one bad event never kills the frame loop
    }
  }

  private evictLowest(): void {
    const rank: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3, 'zero-day': 4 }
    let worstId: string | null = null
    let worstRank = 99
    for (const [id, arc] of this.arcs) {
      const r = rank[arc.severity] ?? 0
      if (r < worstRank) {
        worstRank = r
        worstId = id
      }
    }
    if (worstId) {
      const arc = this.arcs.get(worstId)!
      this.arcGroup.remove(arc.mesh)
      disposeArc(arc)
      const ms = this.markers.get(worstId)
      if (ms) for (const m of ms) { this.markerGroup.remove(m.sprite); disposeMarker(m) }
      this.markers.delete(worstId)
      this.arcs.delete(worstId)
    }
  }

  /** Screen-space pick → event_id (architecture.md §4.5 hover/click). */
  pick(clientX: number, clientY: number): string | null {
    const rect = this.canvas.getBoundingClientRect()
    const ndc = new THREE.Vector2(
      ((clientX - rect.left) / rect.width) * 2 - 1,
      -((clientY - rect.top) / rect.height) * 2 + 1,
    )
    this.raycaster.setFromCamera(ndc, this.camera)
    const sprites: THREE.Object3D[] = []
    for (const ms of this.markers.values()) for (const m of ms) sprites.push(m.sprite)
    const hits = this.raycaster.intersectObjects(sprites, false)
    if (hits.length > 0) {
      const id = hits[0].object.userData.event_id as string
      return id ?? null
    }
    return null
  }

  getPerf(): PerfSample {
    return { ...this.lastPerf }
  }

  private loop = (): void => {
    this.raf = requestAnimationFrame(this.loop)
    const t0 = performance.now()
    const dt = Math.min(this.clock.getDelta(), 0.1)

    for (const arc of this.arcs.values()) {
      arc.material.uniforms.uTime.value += dt
    }

    for (let i = this.waves.length - 1; i >= 0; i--) {
      const w = this.waves[i]
      w.age += dt
      const p = w.age / w.ttl
      const s = 1 + p * 5
      w.mesh.scale.set(s, s, s)
      w.material.opacity = 0.85 * (1 - p)
      if (w.age >= w.ttl) {
        this.waveGroup.remove(w.mesh)
        disposeShockwave(w)
        this.waves.splice(i, 1)
      }
    }

    for (const ms of this.markers.values()) {
      const now = performance.now() / 1000
      for (const m of ms) m.sprite.scale.setScalar(m.baseScale * (1 + 0.18 * Math.sin(now * 3)))
    }

    if (this.cinematic) {
      this.globeGroup.rotation.y += dt * 0.12
    }

    this.composer.render()

    const frameMs = performance.now() - t0
    this.frames++
    if (t0 - this.fpsTime > 500) {
      const fps = Math.round((this.frames * 1000) / (t0 - this.fpsTime))
      this.lastPerf = { fps, frameMs: Math.round(frameMs * 10) / 10, drawCalls: this.renderer.info.render.calls, arcs: this.arcs.size }
      this.frames = 0
      this.fpsTime = t0
    }
  }

  destroy(): void {
    cancelAnimationFrame(this.raf)
    this.resizeObs.disconnect()
    for (const arc of this.arcs.values()) disposeArc(arc)
    for (const ms of this.markers.values()) for (const m of ms) disposeMarker(m)
    for (const w of this.waves) disposeShockwave(w)
    this.renderer.dispose()
  }
}
