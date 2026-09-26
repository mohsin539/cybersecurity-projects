import Foundation
import LocalAuthentication

/// iOS pipeline: collect telemetry -> evaluate against the baseline policy ->
/// produce a COMPLIANT / NON_COMPLIANT verdict (mirror of the desktop engine).
public struct ComplianceEngine {

    public struct Rule {
        public let id: String
        public let group: String
        public let label: String
        public let severity: String
        public let kind: String
        public let expected: Any
    }

    public static let threshold = 0.80

    // Mirror of "MDM-Lite Baseline Policy" (iOS subset + shared checks).
    public static let baseline: [Rule] = [
        Rule(id: "ios.os.version", group: "os", label: "iOS version",
             severity: "high", kind: "version_gte", expected: "15.0"),
        Rule(id: "ios.security.jailbreak", group: "security",
             label: "Jailbreak detection",
             severity: "critical", kind: "boolean", expected: false),
        Rule(id: "ios.security.encryption", group: "security",
             label: "Data protection",
             severity: "high", kind: "boolean", expected: true),
        Rule(id: "ios.security.passcode", group: "security",
             label: "Passcode enforced",
             severity: "high", kind: "boolean", expected: true),
        Rule(id: "ios.security.allowUntrusted", group: "security",
             label: "Untrusted certificates blocked",
             severity: "medium", kind: "boolean", expected: false),
    ]

    /// Returns a dict with status / score / counts / per-rule results.
    public func evaluate(telemetry: [String: Any]) -> [String: Any] {
        var results: [[String: Any]] = []
        var totalW = 0, passW = 0, pass = 0, fail = 0
        var criticalFail = false

        let os = (telemetry["os"] as? [String: Any]) ?? [:]
        let sec = (telemetry["security"] as? [String: Any]) ?? [:]

        for rule in Self.baseline {
            let verdict = evaluate(rule: rule, os: os, security: sec)
            let weight = Self.weight(of: rule.severity)
            switch verdict {
            case "PASS":
                totalW += weight; passW += weight; pass += 1
            case "FAIL":
                totalW += weight; fail += 1
                if rule.severity == "critical" { criticalFail = true }
            default:
                break
            }
            results.append([
                "rule_id": rule.id, "group": rule.group, "label": rule.label,
                "severity": rule.severity, "verdict": verdict,
                "expected": rule.expected, "actual": actualValue(rule, os: os, security: sec),
            ])
        }

        let ratio = totalW == 0 ? 0.0 : Double(passW) / Double(totalW)
        let compliant = !criticalFail && ratio >= Self.threshold
        return [
            "status": compliant ? "COMPLIANT" : "NON_COMPLIANT",
            "score": Int((ratio * 1000).rounded()) / 10,
            "pass_count": pass, "fail_count": fail,
            "na_count": Self.baseline.count - pass - fail,
            "threshold": Int(Self.threshold * 100),
            "results": results,
        ]
    }

    private func evaluate(rule: Rule, os: [String: Any], security: [String: Any]) -> String {
        switch rule.kind {
        case "version_gte":
            let actual = (os["version"] as? String) ?? "0.0"
            return version(actual) >= version(rule.expected as? String ?? "0.0") ? "PASS" : "FAIL"
        case "boolean":
            guard let key = securityKey(for: rule.id) else { return "NA" }
            let actual = (security[key] as? Bool) ?? false
            let expected = (rule.expected as? Bool) ?? false
            return actual == expected ? "PASS" : "FAIL"
        default:
            return "NA"
        }
    }

    private func actualValue(_ rule: Rule, os: [String: Any], security: [String: Any]) -> Any? {
        switch rule.kind {
        case "version_gte": return os["version"]
        case "boolean":
            guard let key = securityKey(for: rule.id) else { return nil }
            return security[key]
        default: return nil
        }
    }

    private func securityKey(for ruleId: String) -> String? {
        switch ruleId {
        case "ios.security.jailbreak": return "jailbreak"
        case "ios.security.encryption": return "encryption"
        case "ios.security.passcode": return "screen_lock"
        case "ios.security.allowUntrusted": return "side_loading"
        default: return nil
        }
    }

    private func version(_ v: String) -> [Int] {
        let digits = v.filter { $0.isNumber || $0 == "." }
        var out = digits.split(separator: ".").prefix(3).map { Int($0) ?? 0 }
        while out.count < 3 { out.append(0) }
        return out
    }

    private static func weight(of severity: String) -> Int {
        switch severity {
        case "low": return 1
        case "medium": return 2
        case "high": return 3
        case "critical": return 4
        default: return 1
        }
    }
}