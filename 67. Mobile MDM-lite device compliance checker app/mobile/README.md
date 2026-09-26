# Mobile deliverables — MDM-Lite Compliance Checker

This folder contains the **on-device companions** for the MDM-Lite compliance
checker desktop app (the portable `.exe`). They collect the exact telemetry JSON
the desktop engine evaluates, and can push it straight to a running checker
(loopback / phone-to-PC over your LAN).

```
mobile/
├── android-agent/                 # Android agent project (Java, no Gradle needed)
│   ├── AndroidManifest.xml
│   ├── res/                       # strings, colors, theme, adaptive launcher icon
│   ├── java/com/mdmlite/agent/    # MainActivity, TelemetryCollector,
│   │                              # ComplianceEngine (mirror), BaselinePolicy, Sender
│   └── build.ps1                  # full build + sign pipeline (aapt2/javac/d8/...)
├── ios/
│   ├── MDM-Lite-Enrollment.mobileconfig   # installable iOS restrictions profile
│   ├── MDM-LiteAgent/                      # Swift package (Source + Tests) → IPA source
│   └── README (this file)
└── README.md
```

## 📱 Android — install & use

**Delivered artifact:** `release/android/MDM-Lite-Agent.apk` (signed, `com.mdmlite.agent`, minSdk 26 · targetSdk 34).

1. Copy `release/android/MDM-Lite-Agent.apk` to the phone (USB / Drive / direct transfer).
2. On the phone enable **Install unknown apps** for the file manager you use.
3. Tap the APK → **Install** → **Open**.
4. In the app:
   - **Rescan** collects telemetry and shows the on-device verdict (PASS/FAIL per rule + score).
   - **Send to checker** posts the telemetry to your desktop checker. Set the URL to
     `http://<PC-LAN-IP>:<port>` where the desktop app is running
     (the exe prints its URL; the phone and PC must be on the same network).
     The checker enrolls the device and evaluates it in **agent** mode automatically.
   - **Copy JSON** copies the report to the clipboard.

### Rebuilding the APK

```powershell
# pre-reqs: JDK 17+, Android SDK (build-tools 34 + platforms;android-34)
$env:ANDROID_HOME = "C:\Android\Sdk"
powershell -ExecutionPolicy Bypass -File mobile\android-agent\build.ps1
# -> release/android/MDM-Lite-Agent.apk
```

The script runs `aapt2 compile/link → javac → d8 → zip → zipalign → apksigner`
with **zero Gradle** dependencies. Signing key: `release/android/signing/mdmlite-release.keystore`
(alias `mdmlite`, storepass `mdmlite2026`) — keep it safe for every rebuild so your
fleet can update in place.

> The agent asks only for `INTERNET` + `QUERY_ALL_PACKAGES` (package inventory for
> allowlist/denylist rules). No intrusive privileges.

## 🍎 iOS — install & use

### 1. Install the compliance profile (works today, no code required)

`mobile/ios/MDM-Lite-Enrollment.mobileconfig` is an **unsigned** configuration
profile installable directly from an iPhone:

1. Get the file onto the iPhone (AirDrop / Files / host it on a LAN web server).
2. Open it in **Settings** (or use **Settings → General → VPN & Device Management → Download Profile**).
3. **Install Profile**, enter the passcode, confirm.
4. Verify under **Settings → General → VPN & Device Management → MDM-Lite**.

It enforces on-device: **6-digit passcode**, auto-lock 5 min, 6-failure limit,
history 4, plus managed-restriction flags (camera-allowed, backup-allowed,
diagnostics-off). These are surfaced by the agent as the `security` telemetry block.

### 2. Agent app → IPA (requires a Mac)

A real installable `MDM-Lite-Agent.ipa` must be compiled and signed on **macOS with
Xcode 15+** (Apple developer/signing requirements). The complete Swift package is
provided:

```bash
# on macOS:
open mobile/ios/MDM-LiteAgent/Package.swift            # in Xcode
xcodebuild -scheme MDM-LiteAgent -destination 'generic/platform=iOS' build
# then Archive → Distribute App → export .ipa (or dev-sign to your device)
```

The package mirrors the desktop engine (`ComplianceEngine.swift`), collects
telemetry (`TelemetryCollector.swift`), and ships a SwiftUI agent UI
(`AgentApp.swift`) with collect → evaluate → send-to-checker → share.

```bash
# run the shared test suite anywhere (Linux/macOS with Swift toolchain):
cd mobile/ios/MDM-LiteAgent && swift test
```

> Apple restricts enumerating all installed apps (privacy). The iOS agent reads
> **managed app configuration** from MDM payloads instead — see `collectApps()`
> in `TelemetryCollector.swift`.

## 🔗 Agent ↔ checker contract

| Field | Value |
|---|---|
| Endpoint | `POST http://<host>:<port>/api/devices` |
| Body | `{ "name", "platform", "model", "department", "owner", "telemetry": {...} }` |
| Effect | Enrolls the device, stores telemetry, evaluates as **`mode=agent`** |
| Telemetry shape | `{ os, hardware, apps, security, network, agent }` — matches desktop model |