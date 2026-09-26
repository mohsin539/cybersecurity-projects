/**
 * AEGIS-SENTINEL — WebGL engine (architecture.md §5)
 */
import * as THREE from 'three'

export const GLOBE_RADIUS = 1

export function latLonToVec3(lat: number, lon: number, r = GLOBE_RADIUS): THREE.Vector3 {
  const phi = (90 - lat) * (Math.PI / 180)
  const theta = (lon + 180) * (Math.PI / 180)
  return new THREE.Vector3(
    -r * Math.sin(phi) * Math.cos(theta),
    r * Math.cos(phi),
    r * Math.sin(phi) * Math.sin(theta),
  )
}
