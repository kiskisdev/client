import XCTest
import Foundation
@testable import Kiskis

// After an app is deleted and reinstalled, the Secure Enclave App Attest key is gone but the
// keyId persists in the Keychain. generateAssertion then throws DCError.invalidKey
// (com.apple.devicecheck.error code 2). The SDK must recognize exactly that error so it can
// clear the dead keyId and re-attest, instead of failing every fetchConfig forever.
// The full recovery needs a real Secure Enclave; this pins the classifier the recovery keys on.
final class StaleKeyRecoveryTests: XCTestCase {
    func testInvalidKeyErrorIsRecognized() {
        let err = NSError(domain: "com.apple.devicecheck.error", code: 2, userInfo: nil)
        XCTAssertTrue(AttestationManager.isStaleAppAttestKeyError(err))
    }

    func testOtherDeviceCheckErrorsAreNotTreatedAsStale() {
        // e.g. serverUnavailable (4) — a transient failure, NOT a dead key. Must not re-attest.
        let serverUnavailable = NSError(domain: "com.apple.devicecheck.error", code: 4, userInfo: nil)
        XCTAssertFalse(AttestationManager.isStaleAppAttestKeyError(serverUnavailable))
    }

    func testUnrelatedErrorsAreNotStale() {
        let network = NSError(domain: NSURLErrorDomain, code: -1009, userInfo: nil)
        XCTAssertFalse(AttestationManager.isStaleAppAttestKeyError(network))
        XCTAssertFalse(AttestationManager.isStaleAppAttestKeyError(KiskisError.attestationUnavailable))
    }
}
