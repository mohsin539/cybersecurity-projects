/**
 * AEGIS-SENTINEL — Crypto service (security.md §7, architecture.md §11.3)
 * SHA-256 digests + Ed25519 signatures via @noble v2 (pure JS, audited libs).
 */
import * as ed from '@noble/ed25519'
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex } from '@noble/hashes/utils'

let privateKey: Uint8Array | null = null
let publicKey: Uint8Array | null = null

/** Generate (once per session) the report-signing key pair. */
export function ensureKeyPair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
  if (!privateKey || !publicKey) {
    privateKey = ed.utils.randomPrivateKey()
    publicKey = ed.getPublicKey(privateKey)
  }
  return { publicKey, privateKey }
}

export function sha256Hex(input: string): string {
  const bytes = new TextEncoder().encode(input)
  return bytesToHex(sha256(bytes))
}

/**
 * Deterministic JSON canonicalization (security.md §7.4).
 * Stable key ordering so digests are reproducible across sessions.
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalJson).join(',') + ']'
  }
  const obj = value as Record<string, unknown>
  const keys = Object.keys(obj).sort()
  const parts = keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(obj[k]))
  return '{' + parts.join(',') + '}'
}

export interface SignatureResult {
  signature_hex: string
  public_key_hex: string
  algorithm: 'Ed25519'
  signed_at: string
}

export function signPayload(payload: unknown): SignatureResult {
  const { publicKey, privateKey } = ensureKeyPair()
  const message = new TextEncoder().encode(canonicalJson(payload))
  const sig = ed.sign(message, privateKey)
  return {
    signature_hex: bytesToHex(sig),
    public_key_hex: bytesToHex(publicKey),
    algorithm: 'Ed25519',
    signed_at: new Date().toISOString(),
  }
}

export function verifySignature(
  payload: unknown,
  signature_hex: string,
  public_key_hex: string,
): boolean {
  try {
    const message = new TextEncoder().encode(canonicalJson(payload))
    return ed.verify(hexToBytes(signature_hex), message, hexToBytes(public_key_hex))
  } catch {
    return false
  }
}

export function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(Math.floor(hex.length / 2))
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}
