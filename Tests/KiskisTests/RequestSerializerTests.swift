import XCTest
@testable import Kiskis

private actor ConcurrencyTracker {
    private var active = 0
    private(set) var maxActive = 0
    func enter() { active += 1; maxActive = max(maxActive, active) }
    func exit() { active -= 1 }
}

final class RequestSerializerTests: XCTestCase {
    // The whole point: overlapping signed requests must NOT run at the same time, so their
    // assertions reach the server in signCount order (out-of-order counts get 403'd as replays).
    func testRunsOneAtATime() async throws {
        let serializer = RequestSerializer()
        let tracker = ConcurrencyTracker()
        try await withThrowingTaskGroup(of: Void.self) { group in
            for _ in 0..<8 {
                group.addTask {
                    try await serializer.run {
                        await tracker.enter()
                        try await Task.sleep(nanoseconds: 15_000_000) // overlap window if not serialized
                        await tracker.exit()
                    }
                }
            }
            for try await _ in group {}
        }
        let maxActive = await tracker.maxActive
        XCTAssertEqual(maxActive, 1, "signed requests must run one at a time per app")
    }

    // A failed request must not wedge the queue for everything after it.
    func testFailingOperationDoesNotBlockQueue() async throws {
        struct Boom: Error {}
        let serializer = RequestSerializer()
        do { _ = try await serializer.run { throw Boom() }; XCTFail("should have thrown") } catch {}
        let value = try await serializer.run { 42 }
        XCTAssertEqual(value, 42)
    }
}
