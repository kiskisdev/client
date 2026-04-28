import Foundation
import CryptoKit
#if canImport(UIKit)
import UIKit
#endif

// MARK: - Feature Flag API
//
// Convention: create a client bound to the "flags" key, and look up flags
// directly at the top level of that document:
//
//     let flags = KiskisClient(teamId: "A1B2C3", key: "flags")
//     try await flags.fetchConfig()
//     if flags.isEnabled("dark_mode") { ... }
//
// The config document for the "flags" key looks like:
//
//     {
//       "dark_mode": true,
//       "checkout_flow": "express",
//       "rollouts": { "new_search": 25 }
//     }
//
// There's no `features.` prefix because the whole document is flags —
// that's the point of having a separate key. If you mix flags into a
// broader config (e.g., under `"features"` in your base config), use
// `KiskisConfig.bool("features.dark_mode")` directly.

public extension KiskisClient {

    /// Check if a boolean feature flag is enabled.
    ///
    /// Reads the top-level `<flag>` value from this client's cached config.
    /// Returns `defaultValue` if no config is cached yet (first launch offline,
    /// no fallback bundle) or if the key is missing / not a boolean.
    ///
    /// Intended for clients bound to a flags key:
    ///     let flags = KiskisClient(teamId: "...", key: "flags")
    ///     if flags.isEnabled("dark_mode") { ... }
    func isEnabled(_ flag: String, default defaultValue: Bool = false) -> Bool {
        guard let config = currentConfig() else { return defaultValue }
        return config.bool(flag) ?? defaultValue
    }

    /// Get a string variant for a flag (for A/B tests or multi-way splits).
    /// Returns `defaultValue` if no config is cached or the key is missing / not a string.
    func variant(_ flag: String, default defaultValue: String = "") -> String {
        guard let config = currentConfig() else { return defaultValue }
        return config.string(flag) ?? defaultValue
    }

    /// Check if this device is in a given percentage rollout.
    ///
    /// Deterministic: the same device always gets the same answer for the
    /// same flag name. Bucket derived from SHA-256 of
    /// `"<flag>:<identifierForVendor>"`. Devices with no vendor ID (rare)
    /// are assigned bucket 0.
    ///
    /// Rolling out without shipping a new app:
    /// ```swift
    /// // Put the percentage in your flags config, ramp from the dashboard
    /// let pct = flags.currentConfig()?.int("rollouts.new_search") ?? 0
    /// if flags.isInRollout("new_search", percentage: pct) { ... }
    /// ```
    func isInRollout(_ flag: String, percentage: Int) -> Bool {
        let pct = max(0, min(100, percentage))
        if pct >= 100 { return true }
        if pct <= 0 { return false }

        let deviceId = Self.stableDeviceId()
        let bucket = Self.bucket(for: flag, deviceId: deviceId)
        return bucket < pct
    }

    // MARK: - Internal helpers

    /// A stable per-install identifier used to bucket this device into rollouts.
    /// `identifierForVendor` is stable across launches for the same vendor
    /// (resets on uninstall). Same device → same bucket → same answer.
    internal static func stableDeviceId() -> String {
        #if canImport(UIKit)
        if let id = UIDevice.current.identifierForVendor?.uuidString {
            return id
        }
        #endif
        return ""
    }

    /// Map (flag, deviceId) to a bucket 0–99. Deterministic.
    internal static func bucket(for flag: String, deviceId: String) -> Int {
        let input = "\(flag):\(deviceId)"
        guard let data = input.data(using: .utf8) else { return 0 }
        let digest = SHA256.hash(data: data)
        // First 4 bytes as uint32, mod 100. Plenty of entropy for 100 buckets.
        let bytes = Array(digest.prefix(4))
        let value = (UInt32(bytes[0]) << 24)
                  | (UInt32(bytes[1]) << 16)
                  | (UInt32(bytes[2]) << 8)
                  |  UInt32(bytes[3])
        return Int(value % 100)
    }
}

// MARK: - KiskisConfig convenience

public extension KiskisConfig {
    /// Check a flag directly on a fetched config snapshot, bypassing the client cache.
    /// Looks up the top-level flag name (no prefix).
    func isEnabled(_ flag: String, default defaultValue: Bool = false) -> Bool {
        return bool(flag) ?? defaultValue
    }

    /// String variant lookup on a fetched config snapshot.
    func variant(_ flag: String, default defaultValue: String = "") -> String {
        return string(flag) ?? defaultValue
    }
}
