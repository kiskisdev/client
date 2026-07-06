import Foundation

/// What to do when a signed config request comes back 401/403.
///
/// A signed request that reached the server proves the assertion was generated successfully,
/// so the local App Attest key is valid — a genuinely stale key (app reinstalled: keyId in
/// Keychain but the Secure Enclave key wiped) throws `KiskisError.assertionKeyInvalid` locally,
/// BEFORE any HTTP call (handled in `signedRequest`). Therefore a server 401/403 is almost
/// always transient: the server hasn't yet observed the just-written registration (DynamoDB
/// read-after-write / eventually-consistent read), or a signCount arrived out of order. Retry
/// the SAME key first — a fresh assertion carries a higher signCount and a new timestamp, which
/// clears both. Only re-attest — which mints a NEW device — once retries are exhausted (the real
/// last-resort case: the device was revoked server-side). Re-attesting on a first transient 403
/// is what accumulated duplicate "Sign #1" device rows.
enum ConfigAuthRecovery: Equatable {
    case retrySameKey
    case reattest
}

extension KiskisClient {
    /// Decide recovery for a 401/403 on a signed config request.
    /// - Parameter retriesDone: same-key retries already performed (0 on the first 401/403).
    /// - Parameter maxSameKeyRetries: how many same-key retries to make before re-attesting.
    static func configAuthRecovery(retriesDone: Int, maxSameKeyRetries: Int) -> ConfigAuthRecovery {
        retriesDone < maxSameKeyRetries ? .retrySameKey : .reattest
    }
}
