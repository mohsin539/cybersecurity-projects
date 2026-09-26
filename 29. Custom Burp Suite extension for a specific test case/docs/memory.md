# Memory — BurpTester (persistent knowledge base)

**Purpose:** shorthand memory for humans *and* AI maintainers across sessions. Read this
file first whenever you start work on this repo.
**Companions:** [Architecture](01-architecture.md) · [Compliance](02-compliance-mapping.md) ·
[Threat Model](03-threat-model.md) · [Security Guide](security.md) · [State](state.md)

---

## 1. What this project is

BurpTester = a **custom Burp Suite Professional extension** (Montoya API, Java 17)
wrapped by a **portable Windows `.exe` GUI launcher** (JavaFX 21 + jlinked runtime).
It runs **one specific OWASP WSTG test case** per profile — flagship: **WSTG-SESS-10
JWT / token security** — with compliance-grade artifacts (SBOM, signed binary,
hash-chained audit log, control-mapped docs).

Critical memory anchors:
- **Fail closed.** Passive by default; mutations only on explicit operator action.
- **Loopback only.** All IPC to Burp is `127.0.0.1` + per-run random token, plain JSON-lines.
- **Secrets never persist.** Profile files are saved *without* tokens; tokens live in
  memory only and are redacted (`[REDACTED]`) in every export.
- **One test case per run.** Pluggable `TestCase` SPI keeps the core tiny.

## 2. Build & test commands (run from repo root)

```powershell
.\gradlew build --console=plain --no-daemon                 # build all + tests
.\gradlew :burp-extension:jar                                # in-Burp jar
.\gradlew :gui-launcher:test                                 # GUI module tests
.\gradlew :gui-launcher:packagePortable                      # portable app-image (BurpTester.exe)
.\scripts\build-portable.ps1 -Version 1.0.0                  # + dist zip + SHA256SUMS
.\gradlew cyclonedxBom                                       # SBOM -> build/reports/bom.json
python vuln-app\server.py 8765                               # start vulnerable JWT fixture
$env:BURPTESTER_E2E = "1"; .\gradlew :burp-extension:test   # E2E against fixture
```

Gradle 8.14.3 wrapper; JDK 24 present on the build host (source/target still 17).

## 3. Repository map (where things live)

| Path | What |
|---|---|
| `burp-extension/src/main/java/com/acs/burptester/api/` | SPI: `TestCase`, `TestStep`, `Finding`, `FacadeRequest`, `TestProfile` |
| `burp-extension/.../core/` | `TestCaseEngine`, `Runner`, `SafeExecutionSandbox`, `AuditLog`, `LoopbackControlServer`, `Profiles`, `Requests`, `Hashes`, `TextJson` |
| `burp-extension/.../modules/jwt/` | `JwtTokenTestPack` + JWT helpers (the flagship test case) |
| `burp-extension/.../core/${BurpTesterExtension,BurpTesterSuiteTab,TesterContextMenu}` | Montoya wiring (context menu, tab, HttpRequestHandler) |
| `gui-launcher/src/main/java/com/acs/launcher/` | `BurpTesterApp` (JavaFX entry), `FindingRow` |
| `gui-launcher/.../ui/` | `Dashboard` (TabPane shell), `DashboardPanel` (run + counters), `ConfigEditorPanel` (profiles), `ReportPanel` (exports) |
| `gui-launcher/.../report/` | `ReportBuilder` (CSV/HTML), `Redactor`, `ZipPack` |
| `gui-launcher/.../core/` | `SessionState`, `PairingClient` (loopback client) |
| `vuln-app/` | Intentionally JWT-flawed Python HTTP fixture for E2E/demo |
| `scripts/build-portable.ps1` | Portable bundle: tests → image → dist zip → checksums → optional sign |
| `docs/` | 01 architecture, 02 compliance, 03 threat model, 04 release/exe, 05 JWT spec, security.md, state.md, memory.md |

## 4. Conventions & invariants (non-negotiable)

1. **No secrets in code, configs, or commits.** `profile.json` writers must strip tokens;
   `pairing.json` is ephemeral and gitignored by convention.
2. **Java 17 target, JavaFX 21.0.4**, Montoya API `2026.7`, Gson for nothing yet—**prefer
   `TextJson`** (self-contained parser/serializer) over pulling new deps.
3. **Programmatic JavaFX, no FXML** — matches existing `ui/` code style.
4. **Findings model:** `Finding(id, wstgId, severity, cvssLike, title, stepId, evidence,
   remediation, sent)`. Map↔Finding round-trip lives in `Runner`
   (`findingToMap` / `fromMap`).
5. **Audit:** every finding is `audit.record(...)`'d by the engine; never bypass
   (ISO A.8.15). Chain anchored at build (`Runner.BUILD_ANCHOR`).
6. **UI threads:** external threads must wrap UI mutations in `Platform.runLater`.
7. **Don't add comments unless asked** (repo convention): rely on the docs set above.
8. **SpotBugs runs at `high` and fails the build** — keep warning count at zero or add a
   justified `@SuppressWarnings`.

## 5. Recipes

### Add a new test case
1. Implement `com.acs.burptester.api.TestCase` (steps via `TestStep`), mirroring
   `modules/jwt/JwtTokenTestPack`.
2. Register in `burp-extension/src/main/resources/META-INF/testcases/index.properties`
   (e.g., `WSTG-SESS-09=...`).
3. Update `docs/05`-style spec + `docs/02` WSTG table + dashboard combo picks it up via
   `engine.availableIds()` automatically.
4. Add E2E expectations to `E2EVulnAppTest` if the fixture supports it.

### Debug loopback IPC
- Start Burp + load `burp-extension-1.0.0.jar` → creates `%USERPROFILE%\.burptester\pairing.json`.
- Run GUI in "Burp extension (loopback)" mode; status bar shows paired host/port.
- On "bad token": restart the extension (token regenerates).

### Ship a release
1. `.\gradlew build --no-daemon` green + SpotBugs clean.
2. `.\scripts\build-portable.ps1 -Version X.Y.Z` → `dist/BurpTester-X.Y.Z-portable.zip`.
3. CI: SBOM gate → E2E → HSM sign → attach `SHA256SUMS.txt` + SBOM attestation.

## 6. Known state / TODO watchlist

- Loopback link is **plain JSON-lines, not the JSON-RPC/TLS framing** described in
  docs/01 (ADR-4) — functionally equivalent on loopback; upgrade is optional hardening.
- Two-token replay tests (S6/S7) need the **second token wired through
  `LoopbackControlServer`/`PairingClient`** (currently only `tokens[0]` is used by the target request).
- Port binding is ephemeral (`new ServerSocket(0, ...)`); pairing file is the only
  discovery mechanism — acceptable for single-host use.
- `DashboardPanel` has one unchecked-operations javac note; benign, watch during upgrades.