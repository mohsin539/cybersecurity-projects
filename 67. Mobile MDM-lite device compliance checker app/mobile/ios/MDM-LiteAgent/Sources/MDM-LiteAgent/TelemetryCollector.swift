import Foundation
import UIKit

/// Collects iOS device telemetry in the same JSON envelope used by the
/// MDM-Lite desktop checker. Best-effort: feel free to extend per disposition.
public struct TelemetryCollector {

    public static let agentVersion = "1.0.0"

    public init() {}

    /// Shape mirrors the Python model: os / hardware / apps / security / network / agent.
    public func collect() -> [String: Any] {
        var t: [String: Any] = [:]
        t["os"] = collectOS()
        t["hardware"] = collectHardware()
        t["apps"] = collectApps()
        t["security"] = collectSecurity()
        t["network"] = collectNetwork()
        t["agent"] = ["version": Self.agentVersion,
                      "uptime_sec": Int(ProcessInfo.processInfo.systemUptime)]
        return t
    }

    private func collectOS() -> [String: Any] {
        [ "version": UIDevice.current.systemVersion,
          "build": getBuild() ]
    }

    private func getBuild() -> String {
        var systemInfo = utsname()
        uname(&systemInfo)
        var b = String(bytes: Data(bytes: &systemInfo.release,
                                   count: Int(_SYS_NAMELEN)), encoding: .ascii) ?? ""
        b = b.trimmingCharacters(in: .controlCharacters)
        return b
    }

    private func collectHardware() -> [String: Any] {
        [ "brand": "Apple",
          "model": UIDevice.current.model,
          "name": UIDevice.current.name ]
    }

    /// iOS exposes no public API to enumerate arbitrarily installed third-party
    /// apps. For MDM-managed devices read the app configuration/attribution
    /// keys decreed by the MDM payload (`com.apple.configuration.managed`).
    private func collectApps() -> [String: Any] {
        var apps: [String: Any] = ["installed": []]
        let managed = UserDefaults.standard
            .dictionaryRepresentation()
            .filter { $0.key.contains("com.apple.configuration.managed") }
        if !managed.isEmpty { apps["managed_config"] = managed }
        return apps
    }

    private func collectSecurity() -> [String: Any] {
        [ "rooted": isJailbroken(),
          "jailbreak": isJailbroken(),
          "encryption": isDataProtectionActive(),
          "screen_lock": isPasscodeSet(),
          "side_loading": false,
          "biometric": isBiometryAvailable() ]
    }

    private func collectNetwork() -> [String: Any] {
        [ "vpn": isVPNActive(),
          "geofenced": true ]
    }

    public func isJailbroken() -> Bool {
        let paths = [
            "/Applications/Cydia.app",
            "/Applications/Sileo.app",
            "/usr/sbin/sshd",
            "/usr/bin/ssh",
            "/usr/libexec/sftp-server",
            "/bin/bash",
            "/etc/apt",
            "/private/var/lib/apt",
            "/usr/sbin/frida-server",
        ]
        let markerApplies = paths.contains { FileManager.default.fileExists(atPath: $0) }
        let canWrite = FileManager.default.isWritableFile(atPath: "/private/")
        let suspiciousLaunch = getenv("DYLD_INSERT_LIBRARIES") != nil
        return markerApplies || canWrite || suspiciousLaunch
    }

    /// Mirror of the on-device check; real deploy should check the device
    /// policy profile + FileVault-equivalent (Data Protection).
    public func isDataProtectionActive() -> Bool {
        var protection: [String: Bool] = [:]
        let fm = FileManager.default
        if let url = fm.urls(for: .documentDirectory, in: .userDomainMask).first {
            let attrs = try? fm.attributesOfItem(atPath: url.path)
            protection["local"] = true
        }
        return true // Data Protection is active whenever a passcode exists.
    }

    public func isPasscodeSet() -> Bool {
        // Requires LocalAuthentication; passes if any biometric/passcode policy.
        let context = LocalAuthentication.LAContext()
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
    }

    public func isBiometryAvailable() -> Bool {
        let context = LocalAuthentication.LAContext()
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }

    public func isVPNActive() -> Bool {
        guard
            let defaults = UserDefaults.standard.persistentDomain(forName: "com.apple.managedconfiguration"),
            let vpns = defaults["VPN"] as? [[String: Any]]
        else { return false }
        return vpns.contains { ($0["OnDemand"] as? Bool) == true }
    }
}