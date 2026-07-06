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
