import { describe, it, expect } from 'vitest'
import { AuditLedger } from '../src/security/auditLedger'

describe('AuditLedger hash chain', () => {
  it('appends entries with chained hashes', () => {
    const ledger = new AuditLedger()
    const a = ledger.append('alice', 'analyst', 'report.request', 'r1')
    const b = ledger.append('bob', 'auditor', 'audit.view', 'r2')
    expect(a.prev_hash).toBe('sha256:genesis')
    expect(b.prev_hash).toBe(a.entry_hash)
    expect(ledger.size()).toBe(2)
  })

  it('verifies an untampered chain as ok', () => {
    const ledger = new AuditLedger()
    ledger.append('u', 'analyst', 'report.request', 'r1')
    ledger.append('u', 'analyst', 'ioc.copy', 'r2')
    ledger.append('u', 'analyst', 'report.generate', 'r3')
    const v = ledger.verify()
    expect(v.ok).toBe(true)
    expect(v.first_broken_seq).toBeNull()
    expect(v.length).toBe(3)
  })

  it('detects tampering at the exact entry', () => {
    const ledger = new AuditLedger()
    ledger.append('u', 'analyst', 'report.request', 'r1')
    const second = ledger.append('u', 'analyst', 'ioc.copy', 'r2')
    ledger.append('u', 'analyst', 'report.generate', 'r3')
    // Simulate tampering: mutate an entry after the fact
    ;(second as { resource: string }).resource = 'TAMPERED'
    const v = ledger.verify()
    expect(v.ok).toBe(false)
    expect(v.first_broken_seq).toBe(2)
  })
})
