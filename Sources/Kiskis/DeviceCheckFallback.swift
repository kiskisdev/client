import Foundation
import DeviceCheck
#if canImport(UIKit)
import UIKit
#endif

/// Fallback authentication for devices that don't support App Attest (iOS <14
/// or devices without Secure Enclave). Uses DeviceCheck for basic device validation
/// combined with a device fingerprint.
///
/// Security note: DeviceCheck is weaker than App Attest — it verifies the device
/// is real but cannot prove the app binary hasn't been modified. Use App Attest
/// whenever available.
final class DeviceCheckFallback: @unchecked Sendable {
    private let teamId: String
    private let bundleId: String

    init(teamId: String, bundleId: String) {
        self.teamId = teamId
        self.bundleId = bundleId
    }

    /// Whether DeviceCheck is supported (available on most devices, even without Secure Enclave).
    var isSupported: Bool {
        return DCDevice.current.isSupported
    }

    /// Generate a DeviceCheck token that proves this is a real Apple device.
    /// The token is single-use and must be verified server-side with Apple.
    func generateToken() async throws -> String {
        guard DCDevice.current.isSupported else {
            throw KiskisError.attestationUnavailable
        }

        let token: Data
        do {
            token = try await DCDevice.current.generateToken()
        } catch {
            throw KiskisError.attestationFailed(
                "DeviceCheck token generation failed: \(error.localizedDescription)"
            )
        }

        return token.base64EncodedString()
    }

    /// Create a device fingerprint from available (non-PII) device properties.
    /// This is NOT a unique identifier — it's a composite signal for anomaly detection.
    func deviceFingerprint() -> [String: String] {
        var fingerprint: [String: String] = [
            "team_id": teamId,
            "bundle_id": bundleId,
            "auth_method": "devicecheck", // Server knows this is the weaker path
        ]

        #if canImport(UIKit)
        fingerprint["device_model"] = UIDevice.current.model
        fingerprint["system_version"] = UIDevice.current.systemVersion
        fingerprint["system_name"] = UIDevice.current.systemName
        #endif

        return fingerprint
    }
}
