# BurpTester — SBOM (Software Bill of Materials)

Compliance controls: **ISO 27001 A.8.8 / A.8.28**, **NIST SI-2/SA-10**, **OWASP Top 10 A06/A08**.

## Policy

Every release MUST ship a CycloneDX SBOM covering all modules (extension + launcher)
and every transitive dependency with `purl` coordinates. The SBOM is **attested** in CI
and published beside the signed executable.

## Generation

CycloneDX publishes an official Gradle plugin. Enable it on the root project:

```groovy
plugins {
    id 'org.cyclonedx.bom' version '1.10.0'
}
```

Then generate the aggregated BOM for the whole product (both modules):

```bash
.\gradlew cyclonedxBom
# Output: build\reports\bom.json  (aggregates burp-extension + gui-launcher)
```

`scripts/build-portable.ps1` collects the BOM into `dist/sbom/`.

## Vulnerability & license gates (CI)

The `sbom` stage in the CI pipeline (see `.github/workflows/ci.yml`) runs:

| Tool | Purpose |
|---|---|
| **OSV Scanner** (`osv-scanner`) | Any dependency in a known vulnerability feed → FAIL |
| **License allowlist** (`mqlc`/`cyclonedx-cli` policies) | Only Apache-2.0, MIT, BSD, EPL, LGPL accepted |
| **Dependency lockfile** | `gradle` version catalogs + lockfiles must be in sync |
| **Attestation** | BOM hash recorded in the release manifest |

## This folder

| File | Status |
|---|---|
| `template-bom.sample.json` | Hand-editable template placeholder, replaced by generated BOMs in CI |
| `README.md` | This guide |

## Data model note

BurpTester itself ships **no server-side components**; the SBOM covers only:
`montoya-api` (compileOnly, provided by Burp), JavaFX 21, Gson, JUnit (test-only),
Gradle wrapper/plugins (build-time). We also record the **Burp Suite runtime contract**
(the Montoya API version the extension is compiled against) as a `manifest.conf` note in
the BOM metadata, so a consumer can verify Burp-side compatibility at deploy time.