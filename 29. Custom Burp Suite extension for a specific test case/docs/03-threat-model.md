# 03 — Threat Model (STRIDE)

**Method:** STRIDE per component, with asset trust boundaries. Re-evaluated at every
release (NIST RA-3, ISO A.8.28).

```
 Trust boundaries
 ┌──────────────────────┐   ┌─────────────────────┐   ┌──────────────────────┐
 │ Analyst workstation   │   │ Burp Suite process  │   │ Target application   │
 │  .exe, profiles, logs │──►│ extension in-process│──►│ (under test, label: │
 └──────────────────────┘   └─────────────────────┘   │       TRUSTED)        │
                                                       └──────────────────────┘
```

## 1. Asset inventory

| Asset | Sensitivity | Owner |
|---|---|---|
| `profile.json` (targets, scopes) | Med — reveals test surface | Analyst |
| Token pool (in-memory test JWTs) | High — live session material | Analyst/security team |
| Findings + evidence (requests/responses) | High — may contain secrets | Analyst |
| Audit log | Med — integrity critical | Compliance |
| Signed `.exe` + SBOM | High — integrity critical | Release mgr |
| jlink runtime image | Med | CI |

## 2. STRIDE analysis

### T-1: Tampering — audit log forgery *(C10: AuditLog)*
- **Threat:** attacker alters findings/audit trail to hide a compromise.
- **Mitigations:** hash-chained append-only records, anchor sealed at build; local file
  ACLs; write-once media option (USB write-protect).
- **Controls:** ISO A.8.15, NIST AU-3/AU-11.

### T-2: Spoofing — rogue `.exe` masquerading as BurpTester *(Release pipeline)*
- **Threat:** analyst installs tampered distributable; it steals tokens.
- **Mitigations:** code signing (signtool / Windows GSG), Authenticode, publication of
  SHA-256 manifest, SBOM attestation, publisher name pinned in UI.
- **Controls:** ISO A.8.8/A.8.28, NIST SA-4/SA-10.

### T-3: Repudiation — operator denies tests ran *(C6, C10)*
- **Threat:** no accountability for mutations sent to a production-adjacent app.
- **Mitigations:** every mutation → audit record `{step, requestFingerprint, timestamp,
  operator}`; findings carry request hash chains for independent reproduction.
- **Controls:** ISO A.8.15, NIST AU-3/AU-6.

### T-4: Info disclosure — tokens/evidence exfiltration *(C1, C7)*
- **Threat:** malicious payload response triggers tooling to copy secrets.
- **Mitigations:** loopback-only IPC (never 0.0.0.0), per-run random token, response
  redaction filters for `Authorization`/`Set-Cookie` before display/export, no cloud
  egress, opt-in encrypted evidence export.
- **Controls:** ISO A.8.12, NIST SC-7/SC-8.

### T-5: DoS — payload cascades against target *(C9 sandbox)*
- **Threat:** unbounded test loop knocks out an app.
- **Mitigations:** request budget, inter-request delay CLI-defaults, dry-run gate,
  hard run-time cap; engine refuses to exceed `maxRate` from `profile.json`.
- **Controls:** ISO A.8.23, NIST SI-2.

### T-6: Elevation — "param injection" from app response *(C7 check adapters)*
- **Threat:** crafted response (header/JSON) exploits brittle parser inside extension.
- **Mitigations:** bounded parsers (no eval), read-only `HttpTransport`, input budgets,
  fail-closed on unknown content; SpotBugs SAST in CI.
- **Controls:** ISO A.8.28, NIST SI-10.

### T-7: Spoofing — malicious `profile.json` *(C3)*
- **Threat:** weaponized config (path payloads, tokens) imported from untrusted source.
- **Mitigations:** JSON Schema validation, signature support for profiles, schema version
  pin, unknown-keys rejected.
- **Controls:** ISO A.8.9, NIST CM-6.

### T-8: Info disclosure — UI leftovers / memory dumps *(C2)*
- **Threat:** tokens in GUI memory after task completes or crash dump.
- **Mitigations:** ephemeral token flag → zeroization after run; crash-dump scrubbing
  prompt; GUI no longer shows raw `Authorization` values (masked).

## 3. Residual risks (accepted & documented)

| Risk | Rationale for acceptance | Owner |
|---|---|---|
| Analyst re-routes sensitive app traffic through tool (data at rest on workstation) | Tool never transmits; local encryption optional; policy covers this | Security team |
| Burp itself is market CA/a third-party binary on .exe host | Explicitly outside this tool's TCB; documented dependency | CISO |
| False negatives on exotic JWT curves | Reference module covers documented scope (docs/05) | Product owner |

## 4. Verification of mitigations

| Mitigation | Verifying test |
|---|---|
| Loopback-only bind | Integration test asserts listener socket family/IP |
| Audit integrity | Unit test: modifying one record breaks chain validation |
| Payload budget | E2E: run against `vuln-app` with limit → engine stops at N |
| Signing gate | CI step fails if `.exe` Authenticode invalid |