import Foundation
import DeviceCheck
import CryptoKit

/// Manages App Attest key generation, attestation, and assertion signing.
/// Falls back to DeviceCheck on devices without App Attest support.
final class AttestationManager: @unchecked Sendable {
    private let teamId: String
    private let bundleId: String
    private let keychainKeyIdKey: String
    private lazy var deviceCheckFallback = DeviceCheckFallback(teamId: teamId, bundleId: bundleId)

    /// Whether this device uses App Attest (strong) or DeviceCheck fallback (weaker).
    var usesAppAttest: Bool { isSupported }

    init(teamId: String, bundleId: String) {
        self.teamId = teamId
        self.bundleId = bundleId
        self.keychainKeyIdKey = "kiskis.keyId.\(teamId).\(bundleId)"
    }

    /// The stored App Attest key ID (nil if not yet attested).
    var storedKeyId: String? {
        return KeychainHelper.load(key: keychainKeyIdKey)
    }

    /// Save the key ID after successful attestation.
    /// Throws `KiskisError.keychainWriteFailed` if the Keychain write fails.
    /// The most likely cause in production is errSecInteractionNotAllowed (-25308):
    /// the device was locked between attestation completing and this write.
    func saveKeyId(_ keyId: String) throws {
        let status = KeychainHelper.save(key: keychainKeyIdKey, value: keyId)
        if status != errSecSuccess {
            throw KiskisError.keychainWriteFailed(status)
        }
    }

    /// Check if App Attest is supported on this device.
    var isSupported: Bool {
        if #available(iOS 14.0, *) {
            return DCAppAttestService.shared.isSupported
        }
        return false
    }

    /// Generate a new App Attest key and perform the attestation ceremony.
    ///
    /// - Parameter challenge: The nonce from the server.
    /// - Returns: Tuple of (keyId, base64-encoded attestation object).
    func attestKey(challenge: String) async throws -> (keyId: String, attestationObject: String) {
        guard #available(iOS 14.0, *) else {
            // iOS <14: fall back to DeviceCheck (weaker but functional)
            return try await attestViaDeviceCheck(challenge: challenge)
        }

        let service = DCAppAttestService.shared

        guard service.isSupported else {
            // Device without Secure Enclave: fall back to DeviceCheck
            return try await attestViaDeviceCheck(challenge: challenge)
        }

        // 1. Generate a new key pair in the Secure Enclave
        KiskisLog.info(.attestation, "attesting: generating Secure Enclave key")
        let keyId: String
        do {
            keyId = try await service.generateKey()
        } catch {
            KiskisLog.error(.attestation, "generateKey failed: \(error.localizedDescription)")
            throw KiskisError.attestationFailed("Key generation failed: \(error.localizedDescription)")
        }
        KiskisLog.info(.attestation, "generated keyId=\(kiskisShortKey(keyId)); attesting with Apple")

        // 2. Create the client data hash from the challenge
        let challengeData = Data(challenge.utf8)
        let clientDataHash = Data(SHA256.hash(data: challengeData))

        // 3. Attest the key with Apple's servers
        let attestationObject: Data
        do {
            attestationObject = try await service.attestKey(keyId, clientDataHash: clientDataHash)
        } catch {
            // Check for Apple server outage
            let nsError = error as NSError
            if nsError.domain == "com.apple.devicecheck.error" {
                throw KiskisError.attestationFailed("Apple attestation service error: \(error.localizedDescription)")
            }
            throw KiskisError.attestationFailed("Attestation failed: \(error.localizedDescription)")
        }

        return (keyId, attestationObject.base64EncodedString())
    }

    /// Sign a request payload using the App Attest assertion mechanism.
    ///
    /// - Parameters:
    ///   - payload: The data to sign (typically a hash of the request).
    ///   - keyId: The App Attest key ID.
    /// - Returns: Base64-encoded assertion object.
    func generateAssertion(payload: Data, keyId: String) async throws -> String {
        // Why: dc- keys are synthetic identifiers created during DeviceCheck fallback —
        // there is no corresponding App Attest key in the Secure Enclave.
        // DCAppAttestService.generateAssertion would throw an opaque error; surface the
        // real cause immediately so callers see a meaningful diagnostic.
        if keyId.hasPrefix("dc-") {
            throw KiskisError.attestationFailed(
                "DeviceCheck keys cannot sign assertions — no App Attest key exists for this device. " +
                "Use AttestationPolicy.requireAppAttest to refuse weaker devices at init time."
            )
        }

        guard #available(iOS 14.0, *) else {
            throw KiskisError.attestationUnavailable
        }

        let service = DCAppAttestService.shared
        let clientDataHash = Data(SHA256.hash(data: payload))

        let assertionObject: Data
        do {
            assertionObject = try await service.generateAssertion(keyId, clientDataHash: clientDataHash)
        } catch {
            // A stale key (app deleted + reinstalled: the Secure Enclave key is gone but the
            // keyId persisted in the Keychain) throws DCError.invalidKey. Signal that distinctly
            // so signedRequest can clear the dead keyId and re-attest instead of hard-failing.
            if Self.isStaleAppAttestKeyError(error) {
                throw KiskisError.assertionKeyInvalid
            }
            throw KiskisError.attestationFailed("Assertion failed: \(error.localizedDescription)")
        }

        return assertionObject.base64EncodedString()
    }

    /// True if the error is DCError.invalidKey (`com.apple.devicecheck.error` code 2) — the
    /// stored keyId has no Secure Enclave key. Matched by domain+code so it also holds for the
    /// bridged NSError form (and stays testable without a real Secure Enclave).
    static func isStaleAppAttestKeyError(_ error: Error) -> Bool {
        let ns = error as NSError
        return ns.domain == "com.apple.devicecheck.error" && ns.code == 2 // DCError.Code.invalidKey
    }

    /// Delete the stored key ID (for re-attestation after device migration).
    func clearKeyId() {
        KeychainHelper.delete(key: keychainKeyIdKey)
    }

    /// Fallback attestation for devices without App Attest support.
    /// Uses DeviceCheck (weaker — proves real device but not app integrity).
    private func attestViaDeviceCheck(challenge: String) async throws -> (keyId: String, attestationObject: String) {
        guard deviceCheckFallback.isSupported else {
            throw KiskisError.attestationUnavailable
        }

        // Generate a DeviceCheck token (proves real Apple device)
        let token = try await deviceCheckFallback.generateToken()

        // Create a synthetic keyId for DeviceCheck devices
        // Prefix with "dc-" so the server knows this is DeviceCheck, not App Attest
        let keyId = "dc-\(UUID().uuidString)"

        // The "attestation object" for DeviceCheck is just the token
        // The server will handle this differently from App Attest attestation
        let attestationData: [String: Any] = [
            "type": "devicecheck",
            "token": token,
            "challenge": challenge,
            "fingerprint": deviceCheckFallback.deviceFingerprint(),
        ]

        guard let jsonData = try? JSONSerialization.data(withJSONObject: attestationData) else {
            throw KiskisError.attestationFailed("Failed to encode DeviceCheck attestation")
        }

        return (keyId, jsonData.base64EncodedString())
    }
}
