/**
 * AEGIS-SENTINEL — Audit store (state.md §5): React binding for the ledger.
 */
import { useSyncExternalStore } from 'react'
import { auditLedger } from '../security/auditLedger'
import type { AuditEntry } from '../security/auditLedger'

let cachedAll: readonly AuditEntry[] = []
let cachedSnapshot: readonly AuditEntry[] = cachedAll

function getSnapshot(): readonly AuditEntry[] {
  const entries = auditLedger.all()
  if (entries !== cachedAll) {
    cachedAll = entries
    cachedSnapshot = [...entries]
  }
  return cachedSnapshot
}

export function useAuditEntries(): readonly AuditEntry[] {
  useSyncExternalStore(
    (cb) => auditLedger.subscribe(cb),
    getSnapshot,
  )
  return getSnapshot()
}

export function useAuditSize(): number {
  return useAuditEntries().length
}

export { auditLedger }
