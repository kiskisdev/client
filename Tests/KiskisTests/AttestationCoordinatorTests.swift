import XCTest
@testable import Kiskis

// The bug this prevents: an app with several clients (one per config key) init concurrently,
// all need to attest, and each generates a Secure Enclave key + registers a duplicate device
// (four showed up in the dashboard). The coordinator must run the attestation ONCE for
// concurrent callers and hand them all the same keyId.
private actor CallCounter {
    private(set) var count = 0
    func bump() { count += 1 }
}

final class AttestationCoordinatorTests: XCTestCase {
    func testConcurrentCallersShareOneAttestation() async throws {
        let coordinator = AttestationCoordinator()
        let counter = CallCounter()

        let results = try await withThrowingTaskGroup(of: String.self) { group -> [String] in
            for _ in 0..<10 {
                group.addTask {
                    try await coordinator.attest {
                        await counter.bump()
                        try await Task.sleep(nanoseconds: 40_000_000) // keep the callers overlapping
                        return "keyId-shared"
                    }
                }
            }
            var out: [String] = []
            for try await r in group { out.append(r) }
            return out
        }

        XCTAssertEqual(results, Array(repeating: "keyId-shared", count: 10), "all callers get the same keyId")
        let ran = await counter.count
        XCTAssertEqual(ran, 1, "the attestation op runs exactly once for concurrent callers")
    }

    // The reuse decision that caused the second device: a sibling client re-attests, and a
    // slightly-later client must REUSE that fresh key rather than re-attesting again — but
    // only if it's replacing the OLD failed key, not the fresh one.
    func testShouldReuseStoredKey() {
        // No stored key → must attest.
        XCTAssertFalse(KiskisClient.shouldReuseStoredKey(nil, replacing: nil))
        XCTAssertFalse(KiskisClient.shouldReuseStoredKey(nil, replacing: "X"))
        // A sibling minted a fresh key (Y) different from the stale one (X) → reuse it.
        XCTAssertTrue(KiskisClient.shouldReuseStoredKey("Y", replacing: "X"))
        // First launch: a sibling minted Y while we had nothing → reuse it.
        XCTAssertTrue(KiskisClient.shouldReuseStoredKey("Y", replacing: nil))
        // Stored IS the stale key we're replacing → must re-attest (the bug was reusing here).
        XCTAssertFalse(KiskisClient.shouldReuseStoredKey("X", replacing: "X"))
        // Never reuse a DeviceCheck fallback key.
        XCTAssertFalse(KiskisClient.shouldReuseStoredKey("dc-abc", replacing: "X"))
    }

    // Which keyId stale-key recovery must replace. The value captured before the request wins,
    // because by recovery time a sibling may have replaced the stored one — reusing that late
    // read is what spawned duplicate devices.
    func testStaleKeyForRecovery() {
        // Steady state: a key existed up front, so that's the one that signed and failed —
        // even though a sibling has since stored Y.
        XCTAssertEqual(
            KiskisClient.staleKeyForRecovery(capturedBeforeRequest: "X", storedAfterRequest: "Y"), "X")
        // First launch: nothing up front, so the request itself minted K — K is what failed.
        XCTAssertEqual(
            KiskisClient.staleKeyForRecovery(capturedBeforeRequest: nil, storedAfterRequest: "K"), "K")
        // No key on either side (e.g. the simulator bypass path never mints one).
        XCTAssertNil(
            KiskisClient.staleKeyForRecovery(capturedBeforeRequest: nil, storedAfterRequest: nil))
    }

    // The first-launch bug, at the level where it actually bit: the two helpers composed.
    // No key existed, the request minted K, the server rejected K — and the un-resolved nil made
    // the documented "last resort" re-attestation reuse K, so it could never recover.
    func testFirstLaunchRecoveryDoesNotReuseRejectedKey() {
        // The old path: nil flowed straight through, and K looked reusable.
        XCTAssertTrue(KiskisClient.shouldReuseStoredKey("K", replacing: nil))
        // Fixed: resolve the stale key first, and K is correctly refused → a new key is minted.
        let stale = KiskisClient.staleKeyForRecovery(capturedBeforeRequest: nil, storedAfterRequest: "K")
        XCTAssertFalse(KiskisClient.shouldReuseStoredKey("K", replacing: stale))
    }

    func testSequentialCallersReattest() async throws {
        // Once an attestation completes, a later (non-overlapping) call attests again — the
        // caller decides via the fast path whether a fresh attestation is actually needed.
        let coordinator = AttestationCoordinator()
        let counter = CallCounter()
        _ = try await coordinator.attest { await counter.bump(); return "k1" }
        _ = try await coordinator.attest { await counter.bump(); return "k2" }
        let ran = await counter.count
        XCTAssertEqual(ran, 2)
    }
}
