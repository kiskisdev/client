import XCTest
@testable import Kiskis

final class BypassHeaderTests: XCTestCase {
    // The contract the server's bypass gate enforces (delivery authenticateRequest):
    // X-Bypass-Token + X-Team-Id + X-Bundle-Id present AND X-Environment == "sandbox".
    // An absent X-Environment defaults to "production" server-side, which the gate
    // rejects — the exact bug that silently broke simulator support. This test pins
    // the full header set so the contract can't drift again on either side.
    func testBypassRequestCarriesTheExactServerContract() {
        let base = URLRequest(url: URL(string: "https://api.kiskis.dev/config?key=default&version=1.0")!)
        let req = KiskisClient.applyBypassHeaders(
            to: base, secret: "test-secret-123", teamId: "37D3WYGPDW", bundleId: "com.example.app")

        XCTAssertEqual(req.value(forHTTPHeaderField: "X-Bypass-Token"), "test-secret-123")
        XCTAssertEqual(req.value(forHTTPHeaderField: "X-Team-Id"), "37D3WYGPDW")
        XCTAssertEqual(req.value(forHTTPHeaderField: "X-Bundle-Id"), "com.example.app")
        // THE regression guard: bypass is sandbox by definition; missing => server
        // defaults to production => gate rejects => simulator 401s.
        XCTAssertEqual(req.value(forHTTPHeaderField: "X-Environment"), "sandbox")
        // Bypass requests must NOT carry attestation headers — the server treats their
        // presence + bypass as suspicious, and the SDK has no assertion to offer here.
        XCTAssertNil(req.value(forHTTPHeaderField: "X-Assertion"))
        XCTAssertNil(req.value(forHTTPHeaderField: "X-Key-Id"))
    }
}
