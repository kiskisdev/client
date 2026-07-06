import XCTest
@testable import Kiskis

final class ConfigAuthRecoveryTests: XCTestCase {
    // The regression this locks: a 401/403 on a signed config request must retry the SAME key
    // first. Re-attesting on a transient 403 mints a new Secure Enclave key and registers a
    // duplicate device ("Sign #1" rows accumulate). Re-attest is the LAST resort only.
    func testRetriesSameKeyBeforeReattesting() {
        XCTAssertEqual(KiskisClient.configAuthRecovery(retriesDone: 0, maxSameKeyRetries: 2), .retrySameKey)
        XCTAssertEqual(KiskisClient.configAuthRecovery(retriesDone: 1, maxSameKeyRetries: 2), .retrySameKey)
    }

    func testReattestsOnlyAfterRetriesExhausted() {
        XCTAssertEqual(KiskisClient.configAuthRecovery(retriesDone: 2, maxSameKeyRetries: 2), .reattest)
        XCTAssertEqual(KiskisClient.configAuthRecovery(retriesDone: 3, maxSameKeyRetries: 2), .reattest)
    }

    func testZeroRetryPolicyReattestsImmediately() {
        // Documents the boundary: with no retries budgeted, the first 403 re-attests (old behavior).
        XCTAssertEqual(KiskisClient.configAuthRecovery(retriesDone: 0, maxSameKeyRetries: 0), .reattest)
    }
}
