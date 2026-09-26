# 💾 AEGIS-SENTINEL — Memory, Persistence & Data Lifecycle

> Companion to [`architecture.md`](./architecture.md) (§8.3 Retention & Lifecycle)
> and [`state.md`](./state.md) (in-session state).
> "Memory" here spans three tiers: **GPU/render memory**, **session (tab) memory**, and
> **exported artifacts** — with the production server tiers defined for completeness.

---

## 1. The Three-Tier Memory Model

```
┌─────────────────────────────────────────────────────────────────┐
│ T1 · GPU / Render memory      (engine-owned, dispose-on-evict)  │
│   arc geometries & shader materials · marker sprite textures    │
│   shockwave rings · starfield & land-dot buffers                │
├─────────────────────────────────────────────────────────────────┤
│ T2 · Session / tab memory     (JS heap, cleared on unload)      │
│   threatStore ring buffer (3000) · uiStore · auditLedger chain  │
│   stream buffer (4000) · signing key pair (per session)         │
├─────────────────────────────────────────────────────────────────┤
│ T3 · Exported artifacts       (user disk, user-controlled)      │
│   signed reports (HTML/CSV/JSON/STIX) · audit-pack · ledger JSON│
└─────────────────────────────────────────────────────────────────┘
Production adds: T4 server tiers (TimescaleDB · S3-WORM · ClickHouse)
mirroring the same lifecycle rules — architecture.md §8.3.
```

---

## 2. T1 — GPU/Render Memory Discipline

WebGL memory is **manual**: nothing is garbage-collected until explicitly disposed.

| Object | Created | Disposed | Cap |
|---|---|---|---|
| Threat arc (TubeGeometry + ShaderMaterial) | on new event | when evicted or filtered out | 250 arcs |
| Marker sprite (CanvasTexture + SpriteMaterial) | with arc | with its arc | 2 per arc |
| Shockwave ring (RingGeometry + BasicMaterial) | critical event only | TTL expiry (1.6–2.4 s) | 60 live |
| Land dots / stars / globe | once at boot | `destroy()` on unmount | static |

**Eviction policy — severity-weighted (architecture.md §5.4):** when the arc cap is hit, the
lowest-severity arc is evicted first (`low → medium → high → critical/zero-day` protected).
A flooding attack of low-severity events cannot starve critical ones of render capacity.

**Leak-proofing:** every dispose path (`setEvents` diff, `evictLowest`, shockwave TTL,
`destroy()`) pairs geometry + material + texture disposal. The 60 fps budget (§5.3) implicitly
guards memory — GC pauses or unbounded buffers show up immediately in the perf HUD.

---

## 3. T2 — Session Memory

| Structure | Max | Rationale |
|---|---|---|
| `threatStore.events` | 3,000 | ~15 min of dense feed; filter/aggregate work stays O(n) cheap |
| `ThreatStream.buffer` | 4,000 | Raw intake ahead of store caps; splice-trimmed FIFO |
| `auditLedger.entries` | unbounded (session) | Audit completeness is a security property; typical demo session ≈ hundreds of entries (few MB worst case) |
| Signing key pair | 1 pair | Per-session report signing; zeroed implicitly on tab close (production: HSM) |

**Why the ledger is never trimmed in-session:** a trimmed chain can no longer prove
continuity — `verify()` would be meaningless. Retention is the tamper-evidence strategy.
(Production scales this via WORM snapshots + Merkle proofs rather than unbounded heap.)

### 3.1 Lifecycle hooks

- `React.StrictMode` double-mount safe: engine `destroy()` + stream `handle.close()` fully
  unwind rAF loops, timers, and GPU buffers.
- `beforeunload`: nothing to flush — the demo persists nothing by design (see §5).

---

## 4. What Is (Not) Persisted

| Data | Persisted? | Where it would live in production |
|---|---|---|
| Threat events | ❌ session only | TimescaleDB hot 90 d → compressed 13 mo → ClickHouse 5 y |
| Audit ledger | ❌ session only (exportable) | PG + S3 Object-Lock, 7 y, legal-hold aware |
| Role selection | ❌ resets each load | IdP session (OIDC claims) |
| UI prefs (perf HUD, cinematic) | ❌ | localStorage tier — intentionally omitted in demo for zero-footprint privacy |
| Reports | ❌ (downloaded to user disk) | S3-WORM 30 d hot / 13 mo / on-request |

**Zero-footprint guarantee (demo):** no cookies, no localStorage, no telemetry beacons, no
third-party requests (CSP-enforced). Memory dies with the tab unless the user exports.

---

## 5. T3 — Exported Artifacts Lifecycle

Every export is **self-describing and independently verifiable** after the session is gone:

```
aegis-report_<format>_<ISO-stamp>.<ext>
  ├─ payload body (CSV/JSON/STIX/HTML)
  ├─ digest        sha256(canonical(provenance) + "|" + body)
  ├─ signature     Ed25519 over {digest, provenance}
  └─ public key    session signing key (in footer / provenance block)
```

- **Point-in-time semantics:** the payload is a snapshot; it never mutates as the live stream
  advances. A report from 14:32 stays a 14:32 document forever.
- **Verification without the app:** recompute the digest per security.md §7.3 and check the
  Ed25519 signature with any Ed25519 implementation. The in-app 🔐 Verify modal mirrors this.
- **Audit Pack:** additionally embeds the ledger slice + chain status + head hash — the evidence
  bundle for ISO/NIST auditors (architecture.md §12.4).

### 5.1 Recommended holder practices (documented for consumers)

| Artifact | Handle as | Retention suggestion |
|---|---|---|
| Executive HTML/PDF | Business record | Per org policy (1–7 y) |
| CSV/JSON/STIX feeds | Technical evidence | Version-pinned to incident ID |
| Audit Pack | Compliance evidence | With the audit file for the certified period |
| Ledger JSON export | Forensic snapshot | WORM-copy; note head hash in case file |

---

## 6. Production Memory Tiers (contract parity)

The client tiers mirror the server blueprint so behavior is predictable when the backend lands:

| Tier | Store | Hot | Warm | Cold | Disposal |
|---|---|---|---|---|---|
| Scored events | TimescaleDB | 90 d | 13 mo compressed | ClickHouse 5 y | Crypto-shred per tenant key |
| Raw STIX | S3 | — | — | 365 d WORM | Object-Lock expiry |
| Audit ledger | PG + S3 | 90 d | 7 y | 7 y | Never (legal hold aware) |
| Reports | S3 WORM | 30 d | 13 mo | On-request | Tenant-initiated, audited |
| GPU session | browser | session | — | — | Explicit dispose (§2) |

GDPR alignment: minimization at ingest (geo-precision caps), tenant-key crypto-shredding for
the right-to-erasure, and DPIA notes in architecture.md §10.5.

---

## 7. Integrity of Memory Across Restarts

- **Reproducible demos:** the mock feed uses a fixed seed (mulberry32) — the same backfill
  sequence every load, which makes visual regressions and screenshots comparable.
- **Chain continuity across restarts (production):** the ledger head is anchored hourly via
  RFC 3161 timestamps; a new session verifies the previous head before appending
  (architecture.md §12.2). The demo restarts at `sha256:genesis` by design — documented, not hidden.
- **Recovery:** any session can be reconstructed evidence-first — export the ledger JSON +
  Audit Pack, and the chain verifies offline regardless of app state.
