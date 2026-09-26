# State.md — State Model & Persistence Contract

**Project:** Mobile MDM-lite Device Compliance Checker
**Status:** Reserved — the authoritative description of `state.json`.

---

## 1. Overview

All durable state lives in a **single portable JSON file**:

| Mode | Path | Notes |
|---|---|---|
| Source (dev) | `<repo>/mdm-lite-state.json` | |
| Portable `.exe` | `dist/mdm-lite-state.json` (beside the exe) | Created on first run |
| Custom | `--data <path>` | Override via CLI |

Schema version is `1.0.0` (`state.schemaVersion`). Writes are atomic and
thread-safe (RLock). Schema is forward-normalized on load: unknown fields are
preserved, required fields are defaulted, malformed devices are skipped.

## 2. Top-level shape

```jsonc
{
  "schemaVersion": "1.0.0",
  "meta": {                       // instance bookkeeping
    "createdAt": "ISO-8601",
    "updatedAt": "ISO-8601",
    "instanceId": "inst-<12hex>",
    "totalScans": 0
  },
  "policy": { ... },              // consolidated Policy document (v5)
  "devices": [ ... ],             // Device documents (v6)
  "securityLog": [ ... ],         // AuditLog entries (v7)
  "settings": {                   // runtime knobs
    "alertOnNonCompliant": true,
    "maxLogEntries": 500
  }
}
```

## 3. Policy document

```jsonc
{
  "name": "MDM-Lite Baseline Policy",
  "version": "1.0.0",
  "threshold": 0.80,
  "updatedAt": "ISO-8601",
  "rules": [ /* Rule */ ]
}
```

### Rule
```jsonc
{
  "id": "android.security.root",
  "group": "security",            // os | apps | security | settings
  "platform": "android",          // android | ios | both
  "label": "Root / jailbreak detection",
  "description": "Device runtime must not be rooted.",
  "severity": "critical",         // low | medium | high | critical
  "kind": "boolean",              // version_gte | boolean | allowlist | denylist | list_contains
  "expected": false,
  "remediation": "Unroot the device or re-flash stock firmware..."
}
```

**Behavioral rule:** a validated policy is the **only** path into the store
(`validate_device_policy` in `policy.py`). Invalid rules raise and abort the write.

## 4. Device document

```jsonc
{
  "id": "dev-<12hex>",
  "name": "Florence-Android",
  "platform": "android",          // android | ios
  "model": "Pixel 7",
  "owner": "",
  "department": "BYOD",
  "enrolledAt": "ISO-8601",
  "lastSeen": "ISO-8601",         // empty until first scan
  "telemetry": { /* Telemetry document */ },
  "scan": { /* ScanResult */ } | null,
  "history": [ /* up to 20 previous ScanResult */ ]
}
```

**Serialization invariant:** every device dict returned by the store includes a
**derived** `"status"` field (`COMPLIANT | NON_COMPLIANT | PENDING | ERROR`),
computed from `scan.status` (PENDING when never scanned). The raw field is never
persisted — it is always recomputed.

### Telemetry document
```jsonc
{
  "os":      { "version": "13.0", "sdk": 33, "build": "TQ3A.230901.001" },
  "hardware":{ "brand": "Google", "model": "Pixel 7", "serial": "" },
  "apps":    { "installed": ["com.google.android.gms", "..."], "running": [] },
  "security":{
    "rooted": false, "unknown_sources": false, "encryption": true,
    "screen_lock": true, "play_protect": true, "side_loading": false,
    "biometric": true, "verifier_status": "ENABLED"
  },
  "network": { "vpn": false, "geofenced": true },
  "agent":   { "version": "1.0.0", "uptime_sec": 0 }
}
```

### ScanResult

```jsonc
{
  "at": "ISO-8601",
  "mode": "demo",                 // demo | adb | manual
  "status": "COMPLIANT",          // COMPLIANT | NON_COMPLIANT
  "score": 87.5,                  // weighted pass ratio (%)
  "pass_count": 12, "fail_count": 1, "na_count": 1,
  "results": [                    // per-rule
    { "rule_id": "...", "group": "...", "label": "...", "description": "...",
      "severity": "high", "verdict": "PASS|FAIL|NA",
      "actual": ..., "expected": ..., "remediation": "..." }
  ]
}
```

Verdict semantics: `PASS`/`FAIL`/`NA` (not applicable to platform).

## 5. AuditLog entry

```jsonc
{
  "at": "ISO-8601",
  "level": "info",                // info | warn | critical
  "event": "device_scan",         // 12+ event types
  "message": "Florence-Android scan -> COMPLIANT (score 87.5%...)",
  "deviceId": "dev-..."           // optional
}
```

Ring buffer capped at `settings.maxLogEntries` (500). Read API returns newest-first.

## 6. State transitions

```
enroll ──► PENDING ──scan──► COMPLIANT      ──re-scan──► re-evaluated
                     └─────► NON_COMPLIANT  ──policy change──► invalidated → PENDING
                                                    (all devices)
```

| Event | Effect |
|---|---|
| `add_device` | New device, `PENDING`, audit `device_enroll` |
| `apply_scan` | Fills `scan`, pushes previous into `history` (≤20), bumps `totalScans`, audits `device_scan` |
| `set_policy` / `reset_policy` | Replaces rule set, **nulls every `scan`** (honesty), audits `policy_update/reset` |
| `remove_device` | Deletes device doc, audits `device_remove` |
| `clear_logs` | Empties `securityLog` |

## 7. Persistence protocol (atomicity & recovery)

1. **Save:** `state.json.tmp` (full JSON, indent=2, `default=str`) → `os.replace` → target.
2. **Load+validate:** JSON parse; any parse/allocation failure →
   - copy current file to `state.json.corrupt-<epoch>` (quarantine),
   - log `state_load_corrupt` at `critical`,
   - rebuild a fresh baseline store.
3. **Normalize:** devices rehydrated via `device_from_dict`; malformed ones skipped;
   logs trimmed to ceiling; meta defaults injected.

## 8. Read semantics (snapshot contract)

- `/api/state`, `/api/devices`, `/api/report/*` never return live references:
  `snapshot()` / `export_report()` deep-copy via JSON round-trip.
- `scan_device` returns a **normalized** device (`.to_dict()`, status included).
- Counters (`_counts`) are server-derived so the UI always sees consistent aggregates.

## 9. Backup / restore (recommended UX)

- **Backup:** copy `mdm-lite-state.json` (plain file) while the app is stopped.
- **Restore:** place the copy at the same path; the store normalizes on next boot.
- A future reservation: auto-versioned backups (`state.json.bak-<ts>`) on save.

## 10. Reservations / next steps

- [ ] Optional passphrase-AES for the state file (see `security.md`)
- [ ] Autosave concurrency stress test (multithreaded scan storm)
- [ ] State migration framework for schema-version bumps
- [ ] Export of state diffs (audit-friendly history JSON Lines)