/**
 * AEGIS-SENTINEL — Hash-chained audit ledger (architecture.md §12, security.md §8)
 *
 * Tamper-evident, append-only chain:
 *   entry_hash[n] = SHA256(canonical(entry n without hashes) + prev_hash)
 * A single flipped bit anywhere in history breaks every subsequent link and
 * is detectable via verify().
 *
 * The production service mirrors this contract (Rust audit-service §7.1)
 * with an HSM signer and RFC 3161 anchoring; the client ledger is the same
 * data structure so the verify UX is identical.
 */
import { canonicalJson, sha256Hex } from './crypto'

export type AuditAction =
  | 'auth.session_role_switch'
  | 'globe.event_select'
  | 'ioc.copy'
  | 'report.request'
  | 'report.generate'
  | 'report.download'
  | 'report.verify'
  | 'audit.view'
  | 'audit.export'
  | 'audit.verify'
  | 'filter.apply'
  | 'ui.modal_open'

export interface AuditEntry {
  seq: number
  ts: string
  actor: string
  role: string
  action: AuditAction
  resource: string
  details?: Record<string, unknown>
  prev_hash: string
  entry_hash: string
}

export interface VerifyResult {
  ok: boolean
  length: number
  first_broken_seq: number | null
  head_hash: string
}

const GENESIS = 'sha256:genesis'

type Listener = (entries: readonly AuditEntry[]) => void

export class AuditLedger {
  private entries: AuditEntry[] = []
  private seq = 0
  private head = GENESIS
  private listeners = new Set<Listener>()

  append(
    actor: string,
    role: string,
    action: AuditAction,
    resource: string,
    details?: Record<string, unknown>,
  ): AuditEntry {
    this.seq += 1
    const base = {
      seq: this.seq,
      ts: new Date().toISOString(),
      actor,
      role,
      action,
      resource,
      details,
    }
    const prev = this.head
    const material = `${canonicalJson(base)}|${prev}`
    const entry_hash = sha256Hex(material)

    const entry: AuditEntry = {
      ...base,
      prev_hash: prev,
      entry_hash,
    }

    this.entries.push(entry)
    this.head = entry_hash
    this.emit()
    return entry
  }

  slice(fromSeq: number, toSeq: number): AuditEntry[] {
    return this.entries.filter((e) => e.seq >= fromSeq && e.seq <= toSeq)
  }

  all(): readonly AuditEntry[] {
    return this.entries
  }

  size(): number {
    return this.entries.length
  }

  headHash(): string {
    return this.head
  }

  /** Recompute the full chain and locate the first break, if any. */
  verify(): VerifyResult {
    let prev = GENESIS
    for (const e of this.entries) {
      const base = { ...e } as Partial<AuditEntry>
      delete base.entry_hash
      delete base.prev_hash
      const material = `${canonicalJson(base)}|${prev}`
      const expected = sha256Hex(material)
      if (expected !== e.entry_hash || e.prev_hash !== prev) {
        return {
          ok: false,
          length: this.entries.length,
          first_broken_seq: e.seq,
          head_hash: this.head,
        }
      }
      prev = e.entry_hash
    }
    return {
      ok: true,
      length: this.entries.length,
      first_broken_seq: null,
      head_hash: this.head,
    }
  }

  subscribe(fn: Listener): () => void {
    this.listeners.add(fn)
    return () => {
      this.listeners.delete(fn)
    }
  }

  private emit(): void {
    for (const fn of this.listeners) {
      try {
        fn(this.entries)
      } catch {
        // listeners must never break the ledger
      }
    }
  }
}

/** Tab-wide ledger instance. */
export const auditLedger = new AuditLedger()
