import XCTest
@testable import MDM_LiteAgent

final class ComplianceEngineTests: XCTestCase {

    func testCleanIphoneIsCompliant() {
        let tel: [String: Any] = [
            "os": ["version": "17.0"],
            "security": ["jailbreak": false, "encryption": true,
                         "screen_lock": true, "side_loading": false],
        ]
        let r = ComplianceEngine().evaluate(telemetry: tel)
        XCTAssertEqual(r["status"] as? String, "COMPLIANT")
        XCTAssertGreaterThanOrEqual(r["score"] as? Int ?? 0, 80)
    }

    func testJailbrokenDeviceFailsEvenAtHighScore() {
        let tel: [String: Any] = [
            "os": ["version": "17.0"],
            "security": ["jailbreak": true, "encryption": true,
                         "screen_lock": true, "side_loading": false],
        ]
        let r = ComplianceEngine().evaluate(telemetry: tel)
        XCTAssertEqual(r["status"] as? String, "NON_COMPLIANT")
    }

    func testOldOSFails() {
        let tel: [String: Any] = [
            "os": ["version": "14.8"],
            "security": ["jailbreak": false, "encryption": true,
                         "screen_lock": true, "side_loading": false],
        ]
        let r = ComplianceEngine().evaluate(telemetry: tel)
        XCTAssertEqual(r["status"] as? String, "NON_COMPLIANT")
    }
}