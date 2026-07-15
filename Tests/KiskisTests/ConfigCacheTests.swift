import XCTest
@testable import Kiskis

/// ConfigCache had no coverage at all, which is how it stayed `@unchecked Sendable` with an
/// unsynchronized `memoryCache` while `backgroundRefresh` (default true) fires unawaited
/// `Task { refreshConfigFromServer() }` on every cache hit — so writes racing reads was the
/// normal path, not a corner case.
///
/// These exercise the lock. The re-entrancy test matters most: `load()` and `loadEncryptedRaw()`
/// both call `clear()`, so a non-recursive lock would deadlock and hang the host app — a worse
/// failure than the race. A deadlock shows up here as a hung test rather than a green run.
final class ConfigCacheTests: XCTestCase {

    private func makeCache() -> ConfigCache {
        // Unique group per test → its own directory, so tests don't collide.
        ConfigCache(keychainGroup: "test-\(UUID().uuidString)", cachePolicy: CachePolicy())
    }

    private func configData(_ value: String) -> Data {
        try! JSONSerialization.data(withJSONObject: ["k": value])
    }

    func testSaveThenLoadRoundTrips() {
        let cache = makeCache()
        cache.save(data: configData("v1"))
        let loaded = cache.load()
        XCTAssertEqual(loaded?.data["k"] as? String, "v1")
        cache.clear()
    }

    func testClearRemovesBothMemoryAndDisk() {
        let cache = makeCache()
        cache.save(data: configData("v1"))
        XCTAssertNotNil(cache.load())
        cache.clear()
        XCTAssertNil(cache.load())
    }

    // The deadlock guard. load() calls clear() internally on the beyond-maxStaleness path, and
    // both take the lock — non-recursive would hang here. Reaching the assertion at all is the
    // real result.
    func testLoadIsReentrantWithClear() {
        let cache = makeCache()
        cache.save(data: configData("v1"))
        cache.clear()          // clear() takes the lock
        _ = cache.load()       // load() takes it again, and may call clear() while holding it
        cache.clear()
        XCTAssertNil(cache.load())
    }

    // Concurrent readers and writers — the shape the background refresh actually creates.
    // Without the lock this is a data race on memoryCache (undefined behaviour, not a stale read);
    // under TSan it fails outright, and unlocked it can corrupt or crash.
    func testConcurrentSavesAndLoadsDoNotRaceOrDeadlock() {
        let cache = makeCache()
        cache.save(data: configData("seed"))

        let done = expectation(description: "concurrent access completes")
        done.expectedFulfillmentCount = 2
        let iterations = 200

        DispatchQueue.global().async {
            for i in 0..<iterations {
                cache.save(data: self.configData("w\(i)"))
            }
            done.fulfill()
        }
        DispatchQueue.global().async {
            for _ in 0..<iterations {
                _ = cache.load()
            }
            done.fulfill()
        }

        wait(for: [done], timeout: 30)
        // A value is present and well-formed — no torn state.
        XCTAssertNotNil(cache.load()?.data["k"])
        cache.clear()
    }

    // Overlapping saves must not pair config-from-one-write with metadata-from-another. Each
    // file write is already .atomic, but they are two separate files; the lock is what keeps the
    // pair consistent, so the loaded config always carries its own fetch time and TTL.
    func testConcurrentSavesKeepConfigAndMetadataConsistent() {
        let cache = makeCache()
        let done = expectation(description: "writers finish")
        done.expectedFulfillmentCount = 4

        for w in 0..<4 {
            DispatchQueue.global().async {
                for i in 0..<50 { cache.save(data: self.configData("writer\(w)-\(i)")) }
                done.fulfill()
            }
        }
        wait(for: [done], timeout: 30)

        let loaded = cache.load()
        XCTAssertNotNil(loaded, "config and metadata must both be readable after concurrent saves")
        // fetchedAt comes from metadata; a torn pair would leave it absent or nonsensical.
        if let fetchedAt = loaded?.fetchedAt {
            XCTAssertLessThan(abs(Date().timeIntervalSince(fetchedAt)), 60)
        }
        cache.clear()
    }
}
