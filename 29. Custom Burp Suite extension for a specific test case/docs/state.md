# State — BurpTester

**Purpose:** define the application *state model* (runtime lifecycle + persisted/build
state) so maintainers and auditors can reason about behavior and irreproducible bugs.
**Companions:** [Architecture](01-architecture.md) · [Threat Model](03-threat-model.md) · [Security Guide](security.md)

State is tracked at two levels:

1. **Runtime state** — the in-memory state machine inside the `.exe` and the extension.
2. **Artifact state** — persisted files, build outputs, and the audit chain.

---

## 1. Runtime state machine (launcher + engine)

```
                 start BurpTester.exe
                          │
            READY ◄──────► PAIRING_CHECK (loopback file present?)
             │  apply profile / edit config
             ▼
        CONFIGURED ──► RUN_COMMAND (user clicks Run)
                          │  sandbox gate (dryRun, budget, delay)
                 ┌────────▼────────┐
        Direct mode               Loopback (Burp ext) mode
                 │        │                       │
                 │        ▼                       ▼
                 │  STREAMING: findings ▸ SessionState ▸ Dashboard table
                 │                     + audit records appended (chainHash)
                 ▼
             COMPLETE       (auditChainHash final) ──► REPORTS tab export
             │         or
             ▼
             FAILED        (statusLabel shows reason; session kept for triage)
```

**Transitions & guards:**

| From | To | Trigger | Guard |
|---|---|---|---|
| READY | CONFIGURED | Profile loaded/edited or fields changed | Schema-valid values only |
| CONFIGURED | STREAMING | Run started | `maxRequests>0`, URL/token present, case selected |
| STREAMING | COMPLETE | `done` received / direct run finished | Findings flushed to `SessionState`, counters updated |
| any | FAILED | exception / extension error | Session data preserved; progress reset |

## 2. SessionState (per-run mutable state)

Held by `com.acs.launcher.core.SessionState`, shared by the Dashboard and Reports tabs:

| Field | Type | Meaning |
|---|---|---|
| `findings` | `List<Finding>` | Normalized findings of the current/last run |
| `secrets` | `List<String>` | Tokens used this session — kept **only** for export redaction (`[REDACTED]`) |
| `auditChainHash` | `String` | Tail hash of the hash-chained audit log (anchor = build anchor) |

Lifecycle: `clear()` at run start → mutated on FX thread only → snapshot for export.
Items are `List.copyOf` snapshots so ReportPanel never sees live mutation mid-write.

## 3. Pairing state (loopback link to Burp)

| State | Condition | GUI indicator |
|---|---|---|
| NOT_PAIRED | `~/.burptester/pairing.json` absent | "Not paired - load the extension in Burp Suite first" |
| PAIRED | file present, port+token readable | "Paired: 127.0.0.1:<port> (token masked)" |
| STALE | file present but server unreachable | run returns "Loopback failure" |

The token is **re-randomized on every Burp extension start** — token state never
survives a restart by design (ADR-4).

## 4. Config state (profile artifact)

`ConfigEditorPanel` maintains an in-UI profile; only its **token-stripped** projection
is ever written (`Profiles.toMap` minus `tokens`).

| State | Meaning |
|---|---|
| DIRTY | Fields changed since last load/save (SHA shown live) |
| SAVED | Written to disk; `profile.json` + SHA-256 digest |
| APPLIED | Pushed to Dashboard run controls via `applyProfile()` |

Schema drift (unknown keys / missing fields) is **rejected** at load (`Profiles.fromJson`
throws → statusField shows reason): fail-closed.

## 5. Audit chain state

`AuditLog` starts from `BUILD_ANCHOR` (build-time constant). Each record:
`chainHash = SHA256(chainPrev | ts | payload)`. The GUI surfaces the final
`auditChainHash` on the Dashboard and in every HTML report footer.
State = the chain tail; any edit to a prior record invalidates all successors (AU-3/AU-11).

## 6. Persisted/artifact state inventory

| Path | Purpose | Current state (v1.0.0) |
|---|---|---|
| `gui-launcher/build/portable/BurpTester/BurpTester.exe` | Portable launcher (jpackage app-image) | rebuilt on `:gui-launcher:packagePortable` |
| `gui-launcher/build/libs/gui-launcher-1.0.0-all.jar` | Uber jar (JavaFX + engine) | produced by `uberJar` |
| `burp-extension/build/libs/burp-extension-1.0.0.jar` | In-Burp extension jar | produced by `:burp-extension:jar` |
| `dist/BurpTester-<ver>-portable.zip` + `SHA256SUMS.txt` | Distributable | built by `scripts/build-portable.ps1` |
| `~/.burptester/pairing.json` | Ephemeral loopback pairing | rewritten each Burp start; not committed |
| `findings.ndjson / report.html / evidence.csv / audit.ndjson` | Export targets (operator-chosen) | written only via Reports tab |
| `docs/` | Compliance + knowledge docs | see README index |

## 7. Concurrency contract

- JavaFX **must not** touch `SessionState`/table rows off the FX thread; all mutations
  from worker threads go through `Platform.runLater`.
- Worker threads used: direct-run thread, loopback client thread. Both are short-lived
  and daemon-like; the GUI owns no long-lived executors.
- `SessionState` methods are `synchronized`; UI reads take `snapshot()`/`secrets()` copies.

## 8. Failure states & recovery

| Failure | Observation | Recovery |
|---|---|---|
| Pairing file missing | dashboard status text | Load extension in Burp, re-run |
| Extension IPC token mismatch | "bad token" error | Restart Burp extension, re-pair |
| Target unreachable | `FacadeResponse(0,...)`, run completes with transport finding | Re-check URL/network; still exported |
| Profile parse error | load rejected with message | Fix schema fields; SHA-256 updates live |
| Disk full / no permission on export | export failure shown in Reports summary | Choose another path; evidence stays in memory |