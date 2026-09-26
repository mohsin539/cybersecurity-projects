# Security Guide — BurpTester

**Owner:** Application Security Engineering | **Review cadence:** every release (NIST RA-3, ISO A.8.28)
**Companions:** [Architecture](01-architecture.md) · [Threat Model](03-threat-model.md) · [Compliance Mapping](02-compliance-mapping.md) · [Portable .EXE & Release](04-portable-exe-release.md)

This is the **security engineering guide** for the BurpTester GUI portable `.exe`
solution. It is the developer/auditor entry point for *how* the tool stays safe
by default. Read this before touching cryptography, IPC, secrets, or the build.

---

## 1. Security posture (the five commitments)

| # | Commitment | Where enforced |
|---|---|---|
| 1 | **Fail closed**: never alters traffic except inside the operator-chosen Burp proxy | `SafeExecutionSandbox`, `Runner.run` policy gate |
| 2 | **Loopback only**: no listener except `127.0.0.1`, no cloud egress | `LoopbackControlServer` binds loopback, per-run random token |
| 3 | **No secret persistence**: credentials and test JWTs never written to disk | `ConfigEditorPanel` strips tokens before save; `ephemeral` tokens zeroized in-memory at run end |
| 4 | **Tamper-evident audit**: append-only, hash-chained records anchored at build | `AuditLog` (`chainHash`, `chainPrev`) |
| 5 | **Provenance**: signed binary, SBOM, SHA-256 manifest on every release | docs/04 pipeline + `scripts/build-portable.ps1` |

---

## 2. Cryptography and key material

- **Hashing:** SHA-256 via `Hashes.sha256` (JDK `MessageDigest`). Used for finding
  fingerprints, audit chain, profile artifact hashes, and release manifests.
- **Randomness:** `SecureRandom` for loopback tokens (`Hashes.randomToken`, 32 bytes,
  base64url). Never `Random`.
- **TLS:** the tool performs no end-to-end VPN/TLS of its own. Any transport the
  analyst opts into (evidence export to SIEM, PAW sync) **must** be TLS 1.2+.
  Direct test runs inherit the target's TLS via `java.net.http` and **never** downgrade.
- **Secrets in profiles:** `profile.json` is a *signable* artifact. The GUI's Config
  Editor computes its SHA-256 and deliberately excludes token values from the saved
  file (secrets never persist). Signing key material lives in the HSM / Key Vault
  (docs/04), never in this repo.

## 3. IPC security (the launcher <-> Burp link)

- Both processes run on the same host. `LoopbackControlServer` binds
  `InetAddress.getLoopbackAddress()` (never `0.0.0.0`).
- Each Burp process start generates a **fresh random token** stored in
  `~/.burptester/pairing.json` (0600 intent) and written atomically via a `.tmp` +
  `ATOMIC_MOVE`.
- Every JSON message is authenticated against that token; unknown tokens → `error`,
  connection closed. No persistent cross-run trust.
- GUI shows only `127.0.0.1:<port> (token masked)`, matching Threat model T-4.

## 4. Mutation safety (SafeExecutionSandbox)

| Control | Default | Config key |
|---|---|---|
| Dry-run gate for active payloads | **on** | `dryRun` |
| Request budget per run | 20 | `maxRequests` |
| Inter-request delay | 250 ms | `interRequestDelayMillis` |
| Timeout per send | 15 s | in `DirectHttpFacade` |

`sent=false` findings are **drafted** mutations that never reached the wire. Any
code path that increases `sent` must pass the sandbox gate.

## 5. Secrets in the GUI

- Token fields are `PasswordField` (masked, Threat model T-8).
- Tokens entered for a run are recorded in `SessionState` only for *redaction* at
  export time: `Redactor` replaces occurrences with `[REDACTED]` in HTML/CSV/audit/ZIP.
- Export paths are operator-initiated via `FileChooser`; nothing is written without
  an explicit action.
- The evidence ZIP contains `SHA256SUMS.txt` so an auditor can verify unharmed copies.

## 6. Secure build & release gates (do not skip)

```
build        -> tests (JUnit)            gate: all green
sast         -> SpotBugs high             gate: no high findings
sbom         -> CycloneDX + OSV scan      gate: no known-vulnerable, license allowlist
e2e          -> vuln-app fixture          gate: alg=none flags HIGH, dry-run never sends
sign         -> signtool / HSM            gate: Authenticode + timestamp
release      -> SHA256SUMS + SBOM attach  gate: attestation present
```

Developer guidance:
- Never sign on a dev box. Signing is HSM-only (SA-10).
- Run `.\\scripts\\build-portable.ps1 -Version <v>` for unsigned, add `-Sign -KeyVaultName ...` for EV-signed.
- Never commit `pairing.json`, `*.ndjson`, or profile files containing tokens.

## 7. Incident / audit checklist

- [ ] Audit log chain validated tail-to-head? (`chainHash` recompute)
- [ ] Any `sent=true` finding has a matching audit record with timestamp and request hash?
- [ ] Pairing file still single host, loopback only?
- [ ] `dist\\SHA256SUMS.txt` matches the shipped `BurpTester.exe` exactly?