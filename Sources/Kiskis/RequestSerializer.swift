import Foundation

/// Serializes signed requests per app (teamId+bundleId).
///
/// All of an app's KiskisClients share ONE App Attest key, whose signCount is monotonic —
/// a fundamentally sequential resource. Firing signed requests concurrently makes their
/// assertions (signCount 1,2,3…) arrive at the server out of order, and the server's strict
/// replay check rejects the later-arriving lower counts. This runs signed requests one at a
/// time per app: generate assertion → send → await response → next, so counts arrive in
/// order. Only overlapping requests pay any latency; a naturally-sequential caller is
/// unaffected. Different apps (different keys) don't serialize against each other.
actor RequestSerializer {
    private static let registry = Registry()

    /// The shared serializer for an app key ("teamId.bundleId").
    static func forApp(_ appKey: String) -> RequestSerializer {
        registry.serializer(appKey)
    }

    // The tail of the queue: each new operation awaits this before running, then becomes it.
    private var previous: Task<Void, Never> = Task {}

    /// Run `operation` after all previously-enqueued operations for this app have finished.
    func run<T>(_ operation: @escaping @Sendable () async throws -> T) async throws -> T {
        let prev = previous
        let task = Task { () async throws -> T in
            _ = await prev.value          // wait for the previous operation to complete
            return try await operation()
        }
        // The next caller waits for this operation, whether it succeeds or throws.
        previous = Task { _ = try? await task.value }
        return try await task.value
    }

    private final class Registry: @unchecked Sendable {
        private var serializers: [String: RequestSerializer] = [:]
        private let lock = NSLock()
        func serializer(_ key: String) -> RequestSerializer {
            lock.lock(); defer { lock.unlock() }
            if let existing = serializers[key] { return existing }
            let created = RequestSerializer()
            serializers[key] = created
            return created
        }
    }
}
