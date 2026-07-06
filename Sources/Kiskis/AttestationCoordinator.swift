import Foundation

/// Ensures only ONE App Attest attestation runs at a time per app (teamId+bundleId).
///
/// An app commonly creates several KiskisClients — one per config key (e.g. `challenges`,
/// `news`, `packs`). They share a keyId (stored per app in the Keychain), but when they
/// init concurrently and all need to attest (first launch, or all hitting the same stale
/// key after a reinstall), each would generate its own Secure Enclave key and register a
/// duplicate device — and Apple rate-limits key generation. This coordinator dedupes: the
/// first caller performs the attestation; concurrent callers await that same result.
actor AttestationCoordinator {
    private static let registry = Registry()

    /// The shared coordinator for an app key ("teamId.bundleId").
    static func forApp(_ appKey: String) -> AttestationCoordinator {
        registry.coordinator(appKey)
    }

    private var inFlight: Task<String, Error>?

    /// Run `attest` unless an attestation for this app is already in flight — in which case
    /// await the in-flight one and return its keyId. `attest` performs the full ceremony
    /// (and stores the keyId); a passed-in fast-path may short-circuit when a keyId already
    /// exists.
    func attest(_ attest: @Sendable @escaping () async throws -> String) async throws -> String {
        if let inFlight {
            return try await inFlight.value
        }
        let task = Task { try await attest() }
        inFlight = task
        defer { inFlight = nil }
        return try await task.value
    }

    // Thread-safe registry of per-app coordinators.
    private final class Registry: @unchecked Sendable {
        private var coordinators: [String: AttestationCoordinator] = [:]
        private let lock = NSLock()
        func coordinator(_ key: String) -> AttestationCoordinator {
            lock.lock(); defer { lock.unlock() }
            if let existing = coordinators[key] { return existing }
            let created = AttestationCoordinator()
            coordinators[key] = created
            return created
        }
    }
}
