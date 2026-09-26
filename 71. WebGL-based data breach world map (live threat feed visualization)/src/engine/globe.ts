/**
 * AEGIS-SENTINEL — Globe scene: ocean sphere, fresnel atmosphere, starfield,
 * point-cloud continents (architecture.md §5.2).
 */
import * as THREE from 'three'
import { buildLandDots, mulberry32 } from '../domain/geo'
import { latLonToVec3, GLOBE_RADIUS } from './latLon'

export function buildGlobe(): THREE.Mesh {
  const geo = new THREE.SphereGeometry(GLOBE_RADIUS, 64, 64)
  const mat = new THREE.MeshPhongMaterial({
    color: 0x1b2735,
    emissive: 0x0a1428,
    shininess: 18,
    specular: new THREE.Color(0x2c5364),
  })
  return new THREE.Mesh(geo, mat)
}

export function buildAtmosphere(): THREE.Mesh {
  const geo = new THREE.SphereGeometry(GLOBE_RADIUS * 1.12, 48, 48)
  const mat = new THREE.ShaderMaterial({
    transparent: true,
    side: THREE.BackSide,
    blending: THREE.AdditiveBlending,
    depthWrite: false,
    vertexShader: [
      'varying vec3 vNormal;',
      'varying vec3 vView;',
      'void main() {',
      '  vNormal = normalize(normalMatrix * normal);',
      '  vec4 mv = modelViewMatrix * vec4(position, 1.0);',
      '  vView = normalize(-mv.xyz);',
      '  gl_Position = projectionMatrix * mv;',
      '}',
    ].join('\n'),
    fragmentShader: [
      'varying vec3 vNormal;',
      'varying vec3 vView;',
      'void main() {',
      '  float rim = pow(1.0 - abs(dot(vNormal, vView)), 3.0);',
      '  vec3 c = vec3(0.0, 0.941, 1.0) * rim;',
      '  gl_FragColor = vec4(c, rim * 0.9);',
      '}',
    ].join('\n'),
  })
  return new THREE.Mesh(geo, mat)
}

export function buildStars(): THREE.Points {
  const rnd = mulberry32(42)
  const N = 5000
  const pos = new Float32Array(N * 3)
  for (let i = 0; i < N; i++) {
    const r = 40 + rnd() * 60
    const t = Math.acos(2 * rnd() - 1)
    const p = rnd() * Math.PI * 2
    pos[i * 3] = r * Math.sin(t) * Math.cos(p)
    pos[i * 3 + 1] = r * Math.cos(t)
    pos[i * 3 + 2] = r * Math.sin(t) * Math.sin(p)
  }
  const geo = new THREE.BufferGeometry()
  geo.setAttribute('position', new THREE.BufferAttribute(pos, 3))
  const mat = new THREE.PointsMaterial({ color: 0x9fd8ff, size: 0.12, sizeAttenuation: true, transparent: true, opacity: 0.8 })
  return new THREE.Points(geo, mat)
}

export function buildLandDotsPoints(): THREE.Points {
  const dots = buildLandDots()
  const n = dots.length
  const pos = new Float32Array(n * 3)
  const col = new Float32Array(n * 3)
  const low = new THREE.Color('#2ba84a')
  const high = new THREE.Color('#a3ff7a')
  const tmp = new THREE.Color()
  for (let i = 0; i < n; i++) {
    const v = latLonToVec3(dots[i].lat, dots[i].lon, GLOBE_RADIUS * 1.001)
    pos[i * 3] = v.x
    pos[i * 3 + 1] = v.y
    pos[i * 3 + 2] = v.z
    const t = Math.min(1, Math.abs(dots[i].lat) / 60)
    tmp.copy(low).lerp(high, t)
    col[i * 3] = tmp.r
    col[i * 3 + 1] = tmp.g
    col[i * 3 + 2] = tmp.b
  }
  const geo = new THREE.BufferGeometry()
  geo.setAttribute('position', new THREE.BufferAttribute(pos, 3))
  geo.setAttribute('color', new THREE.BufferAttribute(col, 3))
  const mat = new THREE.PointsMaterial({ size: 0.012, vertexColors: true, sizeAttenuation: true })
  return new THREE.Points(geo, mat)
}
