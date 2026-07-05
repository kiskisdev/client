import Foundation
import CryptoKit

// MARK: - Configuration Types

/// Cache staleness policy when offline.
public enum StaleConfigPolicy: Sendable {
    case warnAndUse
    case failHard
    case useSilently
}

/// File-system protection class for the on-disk config cache.
///
/// iOS encrypts cached config files using the class you choose here.
/// The two relevant levels are:
///
/// - `.complete` (default): file is **unreadable while the device is locked**.
///   Background fetch tasks and locked-state code cannot access the disk cache —
///   they either perform a full network fetch or find no cache at all.
///   Choose this when your config contains secrets and you want the strongest
///   at-rest protection, and you accept that `backgroundRefresh` will always
///   perform a network round-trip rather than serving a cached value.
///
/// - `.untilFirstUserAuthentication`: file is encrypted only until the first
///   unlock after each boot. After that first unlock it remains readable even
///   when the device re-locks. Background fetch and locked-state reads hit the
///   disk cache normally. Choose this when `backgroundRefresh: true` should
///   actually serve cached values, or when your config contains no plaintext
///   secrets (e.g. you are using Zero-Knowledge mode).
public enum CacheFileProtection: Sendable {
    /// NSFileProtectionComplete — unreadable while locked. Strongest at-rest protection;
    /// incompatible with background cache reads.
    case complete

    /// NSFileProtectionCompleteUntilFirstUserAuthentication — readable after first
    /// boot unlock even when subsequently locked. Required for background refresh
    /// to benefit from the disk cache.
    case untilFirstUserAuthentication
}

/// Configuration for cache behavior.
public struct CachePolicy: Sendable {
    public var maxStaleness: TimeInterval
    /// Enable automatic background config refresh.
    ///
    /// - Note: If `fileProtection` is `.complete` (the default), background refreshes
    ///   while the device is locked cannot read the disk cache and will perform a full
    ///   network fetch instead. Set `fileProtection` to `.untilFirstUserAuthentication`
    ///   if you need background tasks to serve cached values.
    public var backgroundRefresh: Bool
    public var onStaleConfig: StaleConfigPolicy
    /// File-system encryption class for the on-disk config cache.
    /// See `CacheFileProtection` for the trade-off between at-rest security and
    /// background-readable access.
    public var fileProtection: CacheFileProtection

    public init(
        maxStaleness: TimeInterval = 7 * 24 * 3600,
        backgroundRefresh: Bool = true,
        onStaleConfig: StaleConfigPolicy = .warnAndUse,
        fileProtection: CacheFileProtection = .complete
    ) {
        self.maxStaleness = maxStaleness
        self.backgroundRefresh = backgroundRefresh
        self.onStaleConfig = onStaleConfig
        self.fileProtection = fileProtection
    }
}

/// Zero-knowledge mode configuration.
///
/// ZK mode encrypts the config before it leaves your build machine — the Kiskis server stores
/// and returns only ciphertext. Combined with response signing, secrets' integrity and
/// confidentiality are independent of TLS.
///
/// **What ZK protects:** server-side breach; response interception by a TLS proxy or
/// custom trust anchor. The server never holds your decryption key.
///
/// **What ZK does NOT protect:** static analysis of your app binary. Any `VaultKeyComponent`
/// value (bundleId, buildNumber, teamId, custom string) is recoverable from the IPA.
/// An attacker with the binary can reconstruct the key and decrypt. On iOS, no client-side
/// scheme prevents this — the key must live in the binary. Use ZK for server-side
/// confidentiality, not binary analysis resistance.
///
/// For the strongest on-device key, use `.enabled(key:)` with a randomly generated
/// high-entropy constant, but understand that binary extraction still ultimately applies.
public enum ZeroKnowledgeMode: Sendable {
    case disabled
    case enabled(key: String)
    @available(*, deprecated, message: "All VaultKeyComponent values are recoverable from the app binary via static analysis. Use ZeroKnowledgeMode.enabled(key:) with a high-entropy value instead.")
    case derived(components: [VaultKeyComponent])

    var resolvedKey: String? {
        switch self {
        case .disabled: return nil
        case .enabled(let key): return key
        case .derived(let components): return VaultKeyComponent.derive(from: components)
        }
    }
}

/// Components for deriving a vault key.
/// - Warning: All component values are recoverable from the app binary via static analysis.
///   Used only with the deprecated `ZeroKnowledgeMode.derived` case.
public enum VaultKeyComponent: Sendable {
    case bundleId
    case buildNumber
    case appVersion
    case teamId(String)
    case custom(String)

    var stringValue: String {
        switch self {
        case .bundleId: return Bundle.main.bundleIdentifier ?? "unknown"
        case .buildNumber: return Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "0"
        case .appVersion: return Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0.0"
        case .teamId(let id): return id
        case .custom(let value): return value
        }
    }

    static func derive(from components: [VaultKeyComponent]) -> String {
        components.map { $0.stringValue }.joined(separator: "\u{001F}")
    }
}

// MARK: - Config Result

/// A blob reference found in the config (fields with `_type: "blob"`).
public struct BlobReference: Sendable {
    /// Key path where this blob was found (e.g., "assets.ml_model")
    public let keyPath: String
    /// The S3 blob key (e.g., "model-v3.bin")
    public let key: String
    /// Optional SHA-256 hash for integrity verification
    public let sha256: String?
    /// Optional size hint in bytes
    public let sizeBytes: Int?
}

/// The result of a config fetch.
public struct KiskisConfig: @unchecked Sendable {
    public let data: [String: Any]
    public let isCached: Bool
    public let isStale: Bool
    public let fetchedAt: Date

    public func string(_ keyPath: String) -> String? { value(at: keyPath) as? String }
    public func bool(_ keyPath: String) -> Bool? { value(at: keyPath) as? Bool }
    public func int(_ keyPath: String) -> Int? { value(at: keyPath) as? Int }
    public func double(_ keyPath: String) -> Double? { value(at: keyPath) as? Double }
    public func array(_ keyPath: String) -> [Any]? { value(at: keyPath) as? [Any] }
    public func dict(_ keyPath: String) -> [String: Any]? { value(at: keyPath) as? [String: Any] }

    /// Find all blob references in the config (fields with `_type: "blob"`).
    public func blobs() -> [BlobReference] {
        var results: [BlobReference] = []
        findBlobs(in: data, path: "", results: &results)
        return results
    }

    private func findBlobs(in dict: [String: Any], path: String, results: inout [BlobReference]) {
        for (key, value) in dict {
            let currentPath = path.isEmpty ? key : "\(path).\(key)"
            if let nested = value as? [String: Any] {
                if let type = nested["_type"] as? String, type == "blob",
                   let blobKey = nested["key"] as? String {
                    results.append(BlobReference(
                        keyPath: currentPath,
                        key: blobKey,
                        sha256: nested["sha256"] as? String,
                        sizeBytes: nested["size_bytes"] as? Int
                    ))
                } else {
                    findBlobs(in: nested, path: currentPath, results: &results)
                }
            }
        }
    }

    private func value(at keyPath: String) -> Any? {
        let keys = keyPath.split(separator: ".").map(String.init)
        var current: Any = data
        for key in keys {
            guard let dict = current as? [String: Any], let next = dict[key] else { return nil }
            current = next
        }
        return current
    }
}

// MARK: - DeviceInfo

/// Returned by `KiskisClient.deviceInfo()` — when this device first attested,
/// and when it last made a request. Use for trial logic, tenure rewards, etc.
public struct DeviceInfo: Sendable {
    /// First attestation for this App Attest install. Resets on uninstall/reinstall.
    public let firstSeen: Date
    /// Most recent successful assertion from this device.
    public let lastSeen: Date
}

// MARK: - Errors

public enum KiskisError: Error, Sendable {
    case attestationFailed(String)
    case attestationUnavailable
    case networkError(String)
    case serverError(Int, String)
    case configNotFound
    case staleConfigRejected
    case zeroKnowledgeDecryptionFailed
    case blobDownloadFailed(String)
    case blobIntegrityFailed(String)
    case notRegistered
    /// Keychain write returned a non-success OSStatus. The most common cause is
    /// errSecInteractionNotAllowed (-25308): the device was locked when a
    /// WhenUnlockedThisDeviceOnly item was written from a background context.
    case keychainWriteFailed(OSStatus)
}

// MARK: - AttestationPolicy

/// Controls which device attestation mechanisms the SDK will accept.
///
/// App Attest cryptographically binds the key to the app binary and the Secure Enclave.
/// DeviceCheck only proves "real Apple device" — it cannot verify app integrity and
/// its synthetic keyId cannot sign subsequent assertions (so requests fail at runtime).
///
/// Use `.requireAppAttest` (the default) for any client that fetches secrets or uses ZK mode.
/// Use `.allowDeviceCheckFallback` only if you explicitly want to gate real devices
/// even when App Attest isn't available, and understand that signed requests will not work.
public enum AttestationPolicy: Sendable {
    /// Only App Attest is accepted. Throws `attestationUnavailable` on iOS <14 or
    /// devices without a Secure Enclave rather than falling back to DeviceCheck.
    /// This is the default and the only safe choice for secret-bearing requests.
    case requireAppAttest

    /// Allow DeviceCheck as a fallback when App Attest is unavailable.
    /// Note: DeviceCheck devices cannot sign assertions — any protected request
    /// will still throw. This mode is useful only for device-gating without serving secrets.
    case allowDeviceCheckFallback
}

// MARK: - BlobIntegrityPolicy

/// Controls whether blob downloads are accepted without a SHA-256 hash.
///
/// The hash arrives over the authenticated, response-signed config channel. Under
/// `.requireHash` (the default) the SDK refuses to even fetch a blob whose config
/// entry omits `sha256` — no bandwidth wasted, no unverified bytes written to disk.
///
/// Use `.allowUnverified` only for publicly accessible assets where you deliberately
/// chose not to include a hash (e.g. a static image that changes frequently and whose
/// compromise has no security consequence).
public enum BlobIntegrityPolicy: Sendable {
    /// Blob downloads are refused unless the BlobReference contains a SHA-256 hash.
    /// This is the default. Throws `blobIntegrityFailed` before fetching.
    case requireHash

    /// Allow blob downloads even when no hash is present.
    /// The download proceeds and no integrity check is performed.
    case allowUnverified
}

public enum CertificatePinningPolicy: Sendable {
    /// SPKI pins in `PinningDelegate` are enforced on top of standard TLS
    /// chain validation. This is the default.
    case enabled

    /// Disable SPKI pinning (standard TLS chain validation still applies).
    /// Why: an operational kill switch. If a CA key rotation ever ships before
    /// the pin set is updated, every install would fail closed with no way to
    /// recover short of an App Store release. This lets an app disable pinning
    /// via its own remote config without a resubmission. Leave it `.enabled`.
    case disabled
}

// MARK: - KiskisClient

/// Main entry point for the Kiskis SDK.
///
/// Usage:
/// ```swift
/// let kiskis = KiskisClient(teamId: "A1B2C3D4E5")
/// let config = try await kiskis.fetchConfig()
/// let stripeKey = config.string("api_keys.stripe")
/// ```
public final class KiskisClient: @unchecked Sendable {
    public static var shared: KiskisClient?

    private let teamId: String
    private let bundleId: String
    /// The configuration key (identifies which config document this client reads).
    /// Default: "default". Other common values: "flags", "promos", "region_us".
    /// Each key has its own cache, its own version history, its own kill switch.
    public let configKey: String
    private let apiURL: URL
    private let cachePolicy: CachePolicy
    private let zeroKnowledge: ZeroKnowledgeMode
    private let attestationPolicy: AttestationPolicy
    private let blobIntegrityPolicy: BlobIntegrityPolicy
    // Why: never read at init time to avoid Bundle I/O in the initializer.
    // This file is plaintext inside the IPA — secrets must never live here.
    private let fallbackConfigURL: URL?

    private let attestationManager: AttestationManager
    private let configCache: ConfigCache
    private let urlSession: URLSession

    /// The device push token (set by the app delegate after registering for push).
    public var pushToken: String?

    public enum KiskisEnvironment: Sendable { case sandbox, production }
    public var environment: KiskisEnvironment

    public init(
        teamId: String,
        bundleId: String? = nil,
        key: String = "default",
        apiURL: URL = URL(string: "https://api.kiskis.dev")!,
        cachePolicy: CachePolicy = CachePolicy(),
        zeroKnowledge: ZeroKnowledgeMode = .disabled,
        attestationPolicy: AttestationPolicy = .requireAppAttest,
        blobIntegrityPolicy: BlobIntegrityPolicy = .requireHash,
        certificatePinning: CertificatePinningPolicy = .enabled,
        /// URL to a bundled JSON file used when the network is unavailable on first
        /// launch and no disk cache exists yet.
        ///
        /// WARNING: Never put secrets in this file. Bundle resources are plaintext
        /// inside the IPA — anyone who downloads the app and unpacks the archive can
        /// read every byte. Use the fallback only for values that are safe to be
        /// fully public: feature flags, UI copy, non-secret endpoint URLs. API keys,
        /// tokens, signing secrets, and any value that must stay confidential must
        /// come from the server. There is no encryption path for bundled resources.
        fallbackConfig: URL? = nil,
        environment: KiskisEnvironment? = nil
    ) {
        self.teamId = teamId
        self.bundleId = bundleId ?? Bundle.main.bundleIdentifier ?? "unknown"
        self.configKey = key
        self.apiURL = apiURL
        self.cachePolicy = cachePolicy
        self.zeroKnowledge = zeroKnowledge
        self.attestationPolicy = attestationPolicy
        self.blobIntegrityPolicy = blobIntegrityPolicy
        self.fallbackConfigURL = fallbackConfig

        // Environment detection priority:
        // 1. Explicit override (if developer passed environment:)
        // 2. Server-detected from previous attestation (persisted in Keychain)
        // 3. Fallback to #if DEBUG heuristic (used until first attestation)
        if let env = environment {
            self.environment = env
        } else if let persisted = KeychainHelper.load(key: "kiskis.env.\(self.teamId).\(self.bundleId)") {
            self.environment = persisted == "sandbox" ? .sandbox : .production
        } else {
            #if DEBUG
            self.environment = .sandbox
            #else
            self.environment = .production
            #endif
        }

        // Cache is scoped per (teamId, bundleId, key) — multiple clients for the same
        // app but different keys have independent caches.
        // Why: a flag flip shouldn't invalidate the base config cache, and vice versa.
        let keychainGroup = "kiskis.\(self.teamId).\(self.bundleId).\(self.configKey)"
        self.configCache = ConfigCache(keychainGroup: keychainGroup, cachePolicy: cachePolicy)
        // AttestationManager is per-app (teamId+bundleId) — shared across all keys.
        // Only the first client created for an app triggers attestation; subsequent
        // clients reuse the keyId stored in the Keychain.
        self.attestationManager = AttestationManager(teamId: self.teamId, bundleId: self.bundleId)
        // Why PinningDelegate: ephemeral configuration avoids credential caching but
        // does not pin. PinningDelegate adds SPKI hash verification on top of standard
        // TLS chain validation — rejects connections whose cert chain does not contain
        // a pinned Let's Encrypt CA, even on devices with custom trust stores.
        // See PinningDelegate.swift for the openssl command to obtain SPKI hashes.
        // Why optional: certificatePinning: .disabled is a kill switch for a CA
        // rotation emergency — see CertificatePinningPolicy.
        switch certificatePinning {
        case .enabled:
            self.urlSession = URLSession(configuration: .ephemeral, delegate: PinningDelegate(), delegateQueue: nil)
        case .disabled:
            self.urlSession = URLSession(configuration: .ephemeral)
        }

        // Only set as shared if this is the "default" client (avoids overwriting
        // with a flags-scoped client accidentally).
        if self.configKey == "default" {
            KiskisClient.shared = self
        }
    }

    // MARK: - App Version

    // Why: version is self-reported from the app bundle — the server receives it as a
    // client-asserted value. App Attest proves the device and binary are genuine, but
    // does not cryptographically bind the assertion to a specific version string.
    // The server uses this to select a config variant; never put secrets in
    // version-specific variants (see matchVersion in delivery/index.ts for the full
    // trust model). Use version targeting only for feature flags and non-sensitive defaults.
    private var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0.0"
    }

    // MARK: - Public API: Config

    /// ZK mode always requires App Attest regardless of the caller-set policy —
    /// a DeviceCheck device that somehow obtained a vault key could still reconstruct
    /// it from the binary, so ZK's server-side guarantee depends on the device being
    /// trustworthy, which only App Attest can assert.
    private var effectiveAttestationPolicy: AttestationPolicy {
        if case .disabled = zeroKnowledge { return attestationPolicy }
        return .requireAppAttest
    }

    /// Cache-load helper that is ZK-aware.
    /// Standard mode: delegates directly to ConfigCache.load() (memory then plaintext disk).
    /// ZK mode: ConfigCache.load() returns the memory cache (it skips the encrypted disk file);
    /// on cold start (memory empty) we decrypt the disk ciphertext and return the plaintext.
    private func loadCachedConfig() -> KiskisConfig? {
        guard let vaultKey = zeroKnowledge.resolvedKey else {
            return configCache.load()
        }
        // Memory cache holds the decrypted KiskisConfig for the session duration.
        if let memCached = configCache.load() { return memCached }
        // Cold start: ciphertext is on disk — decrypt on read; plaintext never written to disk.
        guard let raw = configCache.loadEncryptedRaw(),
              let decrypted = ZeroKnowledgeCrypto.decrypt(data: raw.data, key: vaultKey, teamId: teamId, bundleId: bundleId),
              let json = try? JSONSerialization.jsonObject(with: decrypted) as? [String: Any] else {
            return nil
        }
        let age = Date().timeIntervalSince(raw.fetchedAt)
        return KiskisConfig(data: json, isCached: true, isStale: age > raw.ttl, fetchedAt: raw.fetchedAt)
    }

    /// Return the currently cached config synchronously, without network I/O.
    /// Used by feature flag helpers that need fast, non-async reads.
    /// Returns nil if no config has ever been fetched (first launch offline, no fallback).
    public func currentConfig() -> KiskisConfig? {
        return loadCachedConfig()
    }

    /// Fetch the app's configuration.
    /// Handles attestation, assertion signing, caching, and background refresh automatically.
    public func fetchConfig() async throws -> KiskisConfig {
        // 1. Try cache first
        if let cached = loadCachedConfig() {
            if !cached.isStale {
                if cachePolicy.backgroundRefresh {
                    Task { try? await refreshConfigFromServer() }
                }
                return cached
            }
            // Stale — try refresh, fall back to stale
            do {
                return try await refreshConfigFromServer()
            } catch {
                switch cachePolicy.onStaleConfig {
                case .warnAndUse: return cached
                case .useSilently:
                    return KiskisConfig(data: cached.data, isCached: true, isStale: false, fetchedAt: cached.fetchedAt)
                case .failHard:
                    throw KiskisError.staleConfigRejected
                }
            }
        }

        // 2. No cache — must fetch
        do {
            return try await refreshConfigFromServer()
        } catch {
            // 3. First install offline — serve the bundled fallback.
            // Why: isStale:true signals that a server fetch is needed when connectivity
            // returns. The fallback must contain only non-sensitive defaults because it
            // is plaintext inside the IPA; see the fallbackConfig: init parameter warning.
            if let fallbackURL = fallbackConfigURL,
               let data = try? Data(contentsOf: fallbackURL),
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                return KiskisConfig(data: json, isCached: false, isStale: true, fetchedAt: .distantPast)
            }
            throw error
        }
    }

    // MARK: - Public API: Blob Download

    /// Download a binary blob to a file path.
    /// If `destination` is nil, saves to the caches directory under `kiskis-blobs/`.
    ///
    /// Under `.requireHash` (the default `blobIntegrityPolicy`) the download is refused
    /// before any network request if the BlobReference has no SHA-256 hash. Pass
    /// `blobIntegrityPolicy: .allowUnverified` at init to opt out for public assets.
    ///
    /// Integrity is verified by streaming the downloaded file through SHA256 in 256 KB
    /// chunks — the file is never loaded fully into memory.
    public func downloadBlob(_ ref: BlobReference, to destination: URL? = nil) async throws -> URL {
        // Why: refuse before the network request — no bandwidth wasted on a blob we'd
        // reject anyway. The hash arrives over the authenticated, signed config channel
        // so its absence is a configuration error, not a runtime surprise.
        if ref.sha256 == nil && blobIntegrityPolicy == .requireHash {
            throw KiskisError.blobIntegrityFailed(
                "Blob \"\(ref.key)\" has no SHA-256 hash in config. " +
                "Add sha256 to the blob entry, or init with blobIntegrityPolicy: .allowUnverified."
            )
        }

        // Get presigned URL from Kiskis API
        let presignedURL = try await fetchPresignedBlobURL(blobKey: ref.key)

        // Download from S3
        let (tempURL, response) = try await urlSession.kiskisDownload(from: presignedURL)

        guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
            throw KiskisError.blobDownloadFailed("Bad response from S3")
        }

        // Stream SHA-256 over the downloaded file in 256 KB chunks.
        // Why: Data(contentsOf:) maps the whole file into memory — a 1 GB ML model
        // would pin 1 GB of RAM just for the hash check. FileHandle reads are bounded.
        if let expectedHash = ref.sha256 {
            var hasher = SHA256()
            let handle = try FileHandle(forReadingFrom: tempURL)
            defer { try? handle.close() }
            while true {
                let chunk = handle.readData(ofLength: 256 * 1024)
                if chunk.isEmpty { break }
                hasher.update(data: chunk)
            }
            let actualHash = hasher.finalize().map { String(format: "%02x", $0) }.joined()
            if actualHash != expectedHash.lowercased() {
                try? FileManager.default.removeItem(at: tempURL)
                throw KiskisError.blobIntegrityFailed("SHA-256 mismatch: expected \(expectedHash), got \(actualHash)")
            }
        }

        // Move to destination
        let finalURL: URL
        if let destination = destination {
            let dir = destination.deletingLastPathComponent()
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            if FileManager.default.fileExists(atPath: destination.path) {
                try FileManager.default.removeItem(at: destination)
            }
            try FileManager.default.moveItem(at: tempURL, to: destination)
            finalURL = destination
        } else {
            let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first!
            let blobDir = caches.appendingPathComponent("kiskis-blobs")
            try FileManager.default.createDirectory(at: blobDir, withIntermediateDirectories: true)
            let dest = blobDir.appendingPathComponent(ref.key)
            if FileManager.default.fileExists(atPath: dest.path) {
                try FileManager.default.removeItem(at: dest)
            }
            try FileManager.default.moveItem(at: tempURL, to: dest)
            finalURL = dest
        }

        return finalURL
    }

    // MARK: - Public API: Per-User Data

    /// Save per-user data. `userId` is any identifier from your system.
    public func saveUserData(userId: String, data: [String: Any]) async throws {
        let jsonData = try JSONSerialization.data(withJSONObject: data)
        var request = try await signedRequest(
            path: "user/data",
            queryItems: [URLQueryItem(name: "user_id", value: userId)],
            method: "PUT",
            body: jsonData
        )
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let (_, response) = try await urlSession.kiskisData(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw KiskisError.networkError("Failed to save user data")
        }
    }

    /// Load per-user data. Returns nil if no data exists for this user.
    public func loadUserData(userId: String) async throws -> [String: Any]? {
        let request = try await signedRequest(
            path: "user/data",
            queryItems: [URLQueryItem(name: "user_id", value: userId)]
        )

        let (data, response) = try await urlSession.kiskisData(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw KiskisError.networkError("Invalid response")
        }

        if http.statusCode == 404 { return nil }
        guard http.statusCode == 200 else {
            throw KiskisError.serverError(http.statusCode, String(data: data, encoding: .utf8) ?? "")
        }

        let sig = http.value(forHTTPHeaderField: "X-Kiskis-Sig")
        let tsStr = http.value(forHTTPHeaderField: "X-Kiskis-Sig-Ts")
        guard let sig, let tsStr, let ts = Int(tsStr) else {
            throw KiskisError.serverError(200, "Missing response signature")
        }
        guard verifyResponseSignature(sig: sig, ts: ts, path: request.url?.path ?? "/user/data", body: data) else {
            throw KiskisError.serverError(200, "Response signature verification failed")
        }

        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let userData = json["data"] as? [String: Any] else {
            return nil
        }
        return userData
    }

    // MARK: - Public API: Device Info

    /// Returns when this device first attested with Kiskis (`firstSeen`) and its last
    /// assertion time (`lastSeen`). Useful for implementing trial logic, tenure badges,
    /// welcome-back flows, or any policy based on "how long has this device been using
    /// the app?" — without running your own backend to track install timestamps.
    ///
    /// Kiskis stays out of trial policy; you get the timestamps and decide what they
    /// mean for your app. Example — a plan-dependent trial:
    /// ```swift
    /// let info = try await kiskis.deviceInfo()
    /// let trialDays = userPlan == .pro ? 30 : 7
    /// let trialEndsAt = info.firstSeen.addingTimeInterval(Double(trialDays) * 86400)
    /// if Date() > trialEndsAt { showPaywall() }
    /// ```
    ///
    /// Caveat: `firstSeen` is tied to this App Attest install. If the user uninstalls
    /// and reinstalls, they get a new keyId and `firstSeen` resets. Apple designed
    /// App Attest this way for privacy; there's no signal that survives reinstall.
    /// For stronger anti-abuse, pair with StoreKit Introductory Offer limits (tied to
    /// Apple ID) or your own user identity.
    public func deviceInfo() async throws -> DeviceInfo {
        let request = try await signedRequest(path: "device/info")
        let (data, response) = try await urlSession.kiskisData(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw KiskisError.networkError("Failed to fetch device info")
        }
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let firstSeenStr = json["first_seen"] as? String,
              let lastSeenStr = json["last_seen"] as? String,
              let firstSeen = Self.isoFormatter.date(from: firstSeenStr),
              let lastSeen = Self.isoFormatter.date(from: lastSeenStr) else {
            throw KiskisError.networkError("Invalid device info response")
        }
        return DeviceInfo(firstSeen: firstSeen, lastSeen: lastSeen)
    }

    /// ISO 8601 formatter for parsing timestamps from the Kiskis API.
    /// Why static: reused across calls, expensive to construct.
    private static let isoFormatter: ISO8601DateFormatter = {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f
    }()

    // MARK: - Public API: Push Notification Registration

    /// Associate this device with a user ID for push targeting.
    /// Call this after your user logs in (e.g., with their iCloud recordID).
    /// The user ID enables cross-device push delivery — sending a push to this
    /// userId will reach ALL their devices within this team/bundle.
    ///
    /// Example use case: SwiftData sync notification — when data changes on one
    /// device, send a push to the userId so all other devices refresh immediately.
    public func setUserId(_ userId: String) async throws {
        let body = try JSONSerialization.data(withJSONObject: ["user_id": userId])
        var request = try await signedRequest(path: "push/register", method: "POST", body: body)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let (_, response) = try await urlSession.kiskisData(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw KiskisError.networkError("Failed to register userId for push")
        }
    }

    // MARK: - Internal: Assertion-Based Request Signing

    /// Build a request with assertion headers.
    /// Every protected request is signed by the Secure Enclave — no tokens.
    /// Build the canonical request string that the server will reconstruct independently.
    /// Format: "{METHOD}:{path}:{sorted_query}:{body_sha256_or_empty}:{teamId}:{ts}"
    /// Must match buildCanonicalClientData() in delivery/index.ts exactly.
    ///
    /// - Note: `static` and `internal` (not `private`) so the contract test can pin the exact
    ///   output. This string is what the Secure Enclave signs; if it drifts from the server's
    ///   buildCanonicalClientData, every assertion fails verification (this happened — SDK 0.1.0
    ///   omitted teamId + ts). See CanonicalContractTests, whose golden vectors are shared with
    ///   the server's canonical-contract.test.ts.
    static func canonicalClientData(
        method: String,
        path: String,
        queryItems: [URLQueryItem],
        body: Data?,
        teamId: String,
        ts: Int
    ) -> String {
        let sortedQuery = queryItems
            .sorted { $0.name < $1.name }
            .map { "\($0.name)=\($0.value ?? "")" }
            .joined(separator: "&")
        let bodyHash: String
        if let body = body {
            bodyHash = SHA256.hash(data: body).map { String(format: "%02x", $0) }.joined()
        } else {
            bodyHash = ""
        }
        // Why: teamId binds the assertion to this tenant; ts bounds replay to a 5-minute
        // window even if signCount hasn't advanced (e.g. MITM-captured never-sent assertion).
        // The Secure Enclave signs SHA256 of this string — neither field is spoofable.
        return "\(method):\(path):\(sortedQuery):\(bodyHash):\(teamId):\(ts)"
    }

    // Ed25519 public key (raw 32 bytes) for server response signature verification.
    // Rotate by updating this constant and shipping a new SDK version.
    // The corresponding private key lives in SSM at /kiskis/prod/response-signing-key.
    // To regenerate: node -e "const {generateKeyPairSync}=require('crypto');
    //   const {publicKey}=generateKeyPairSync('ed25519',{publicKeyEncoding:{type:'spki',format:'der'}});
    //   console.log(publicKey.slice(12).toString('base64'));"
    private static let responseSigningPublicKey = Data(base64Encoded: "LNhWnM1urrQcPFe4Xu/woTDu8O3sAmhtq4vEl+a6da8=")!

    /// Verify the Ed25519 signature the server attaches to secret-bearing responses.
    /// Payload: "${ts}:${path}:${body}" — binds the signature to a specific timestamp,
    /// endpoint, and exact byte sequence, making it impossible to replay or tamper.
    private func verifyResponseSignature(sig sigB64url: String, ts: Int, path: String, body: Data) -> Bool {
        // Reject responses outside a ±5-minute replay window
        let now = Int(Date().timeIntervalSince1970)
        guard abs(now - ts) < 300 else { return false }

        // base64url → base64 (replace URL-safe chars, add padding)
        var b64 = sigB64url
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let rem = b64.count % 4
        if rem != 0 { b64 += String(repeating: "=", count: 4 - rem) }
        guard let sigData = Data(base64Encoded: b64) else { return false }

        guard let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: Self.responseSigningPublicKey) else { return false }
        let bodyStr = String(data: body, encoding: .utf8) ?? ""
        let payload = Data("\(ts):\(path):\(bodyStr)".utf8)
        return publicKey.isValidSignature(sigData, for: payload)
    }

    private func signedRequest(
        path: String,
        queryItems: [URLQueryItem] = [],
        method: String = "GET",
        body: Data? = nil
    ) async throws -> URLRequest {
        var components = URLComponents(url: apiURL.appendingPathComponent(path), resolvingAgainstBaseURL: false)!
        if !queryItems.isEmpty {
            components.queryItems = queryItems
        }
        var request = URLRequest(url: components.url!)
        request.httpMethod = method
        if let body = body {
            request.httpBody = body
        }

        // Why: gated on `targetEnvironment(simulator)`, not just DEBUG. App Attest cannot
        // run in the Simulator (no Secure Enclave), which is the only reason the bypass
        // exists. On a real device — DEBUG or not — this block is physically compiled out,
        // so a device build always uses real attestation even if KISKIS_BYPASS_SECRET is
        // set. Lets developers leave the env var in the scheme permanently: inert on device,
        // active only in the Simulator. Also means the bypass can never fire against prod.
        #if DEBUG && targetEnvironment(simulator)
        if let bypassSecret = ProcessInfo.processInfo.environment["KISKIS_BYPASS_SECRET"] {
            // Bypass path: send the secret instead of an App Attest assertion.
            // The server verifies the secret against a SHA-256 hash in DynamoDB and,
            // if valid, treats the request as authenticated for this (teamId, bundleId).
            request.setValue(bypassSecret, forHTTPHeaderField: "X-Bypass-Token")
            request.setValue(teamId, forHTTPHeaderField: "X-Team-Id")
            request.setValue(bundleId, forHTTPHeaderField: "X-Bundle-Id")
            return request
        }
        #endif

        // Production path: full App Attest assertion
        let keyId = try await ensureRegistered()

        // Why: build canonical data server-side style so the server can reconstruct
        // it independently from the actual request — never accepted from a header.
        // Format must match buildCanonicalClientData() in delivery/index.ts exactly.
        let ts = Int(Date().timeIntervalSince1970)
        let signingPayload = Self.canonicalClientData(
            method: method,
            path: components.path,
            queryItems: components.queryItems ?? [],
            body: body,
            teamId: teamId,
            ts: ts
        )

        // Sign with Secure Enclave
        let assertionB64 = try await attestationManager.generateAssertion(
            payload: Data(signingPayload.utf8),
            keyId: keyId
        )

        // Set assertion headers — X-Client-Data is intentionally omitted;
        // the server reconstructs canonical data from the request itself.
        request.setValue(keyId, forHTTPHeaderField: "X-Key-Id")
        request.setValue(teamId, forHTTPHeaderField: "X-Team-Id")
        request.setValue(bundleId, forHTTPHeaderField: "X-Bundle-Id")
        request.setValue(environment == .sandbox ? "sandbox" : "production", forHTTPHeaderField: "X-Environment")
        request.setValue(assertionB64, forHTTPHeaderField: "X-Assertion")
        // Why: ts is sent as a plain header so the server can validate the window before
        // running the assertion crypto. The assertion itself signs this value — a modified
        // header would produce a canonical-string mismatch and fail signature verification.
        request.setValue(String(ts), forHTTPHeaderField: "X-Request-Ts")

        // Include push token if available (for registration/updates)
        if let pushToken = pushToken {
            request.setValue(pushToken, forHTTPHeaderField: "X-Push-Token")
        }

        return request
    }

    /// Ensure the device is registered (attested). Returns the keyId.
    /// First launch: performs attestation. Subsequent: returns stored keyId.
    private func ensureRegistered() async throws -> String {
        // Simulator-only (see signedRequest): a device build compiles this out and always
        // attests for real, so the bypass env var is inert on device.
        #if DEBUG && targetEnvironment(simulator)
        // Bypass mode: no Secure Enclave needed. Return a dummy keyId; the server
        // identifies the request by the X-Bypass-Token header instead.
        if ProcessInfo.processInfo.environment["KISKIS_BYPASS_SECRET"] != nil {
            return "bypass-simulator"
        }
        #endif

        // Already registered?
        if let keyId = attestationManager.storedKeyId {
            // Why: a device may have stored a dc- key before attestationPolicy was
            // set to .requireAppAttest (or before ZK was enabled). Clear it and refuse
            // rather than letting the request reach generateAssertion and fail there.
            if keyId.hasPrefix("dc-") && effectiveAttestationPolicy == .requireAppAttest {
                attestationManager.clearKeyId()
                throw KiskisError.attestationUnavailable
            }
            return keyId
        }

        // Need to attest
        let (keyId, _) = try await performAttestation()
        return keyId
    }

    /// Perform the full App Attest ceremony with the server.
    private func performAttestation() async throws -> (keyId: String, registered: Bool) {
        // Enforce policy before any network round-trip. If App Attest is required and
        // this device doesn't support it, fail immediately rather than falling through
        // to DeviceCheck and storing a dc- keyId that can't sign assertions.
        if effectiveAttestationPolicy == .requireAppAttest && !attestationManager.isSupported {
            throw KiskisError.attestationUnavailable
        }

        // 1. Get challenge nonce
        let nonce = try await fetchChallenge()

        // 2. Attest with Apple
        let (keyId, attestationObject) = try await attestationManager.attestKey(challenge: nonce)

        // 3. Send to server
        let attestURL = apiURL.appendingPathComponent("auth/attest")
        var request = URLRequest(url: attestURL)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        var body: [String: Any] = [
            "attestationObject": attestationObject,
            "keyId": keyId,
            "nonce": nonce,
            "teamId": teamId,
            "bundleId": bundleId,
            "environment": environment == .sandbox ? "sandbox" : "production",
        ]

        // Include push token during registration
        if let pushToken = pushToken {
            body["pushToken"] = pushToken
        }

        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await urlSession.kiskisData(for: request)

        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            let errorBody = String(data: data, encoding: .utf8) ?? "Unknown error"
            throw KiskisError.attestationFailed(errorBody)
        }

        // Server detects environment from Apple's AAGUID field — authoritative
        if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let serverEnv = json["environment"] as? String {
            if serverEnv == "sandbox" {
                environment = .sandbox
            } else {
                environment = .production
            }
            // Persist so subsequent launches use the correct environment.
            // Why: best-effort — failure here only costs the #if DEBUG environment
            // fallback on the next cold launch, not correctness or security.
            KeychainHelper.save(key: "kiskis.env.\(teamId).\(bundleId)", value: serverEnv)
        }

        // Save keyId for future assertions.
        // Why: catch rather than propagate — the keyId is already registered server-side.
        // Rethrowing would fail the current request even though attestation succeeded.
        // The session continues using the in-memory keyId; next launch re-attests, which
        // risks Apple's key-generation rate limit. Most likely cause of failure: device
        // locked between attestation completing and this write (errSecInteractionNotAllowed
        // = -25308 from WhenUnlockedThisDeviceOnly). Log so developers can diagnose.
        do {
            try attestationManager.saveKeyId(keyId)
        } catch KiskisError.keychainWriteFailed(let status) {
            print("[Kiskis] WARNING: keyId could not be persisted to Keychain (OSStatus \(status)). " +
                  "Re-attestation will be required next launch — if this recurs, the device may " +
                  "be hitting Apple's App Attest key-generation rate limit.")
        }

        return (keyId, true)
    }

    // MARK: - Internal: Config Fetch

    private func refreshConfigFromServer() async throws -> KiskisConfig {
        // Send both key (which config document) and version (which variant within it).
        let queryItems: [URLQueryItem] = [
            URLQueryItem(name: "key", value: configKey),
            URLQueryItem(name: "version", value: appVersion),
        ]

        var request = try await signedRequest(path: "config", queryItems: queryItems)

        let (data, response) = try await urlSession.kiskisData(for: request)

        guard let http = response as? HTTPURLResponse else {
            throw KiskisError.networkError("Invalid response")
        }

        if http.statusCode == 401 || http.statusCode == 403 {
            // Assertion failed — might be device migration
            // Try re-attestation once
            attestationManager.clearKeyId()
            let _ = try await performAttestation()
            // Retry with fresh assertion
            request = try await signedRequest(path: "config", queryItems: queryItems)
            let (retryData, retryResponse) = try await urlSession.kiskisData(for: request)
            guard let retryHttp = retryResponse as? HTTPURLResponse, retryHttp.statusCode == 200 else {
                throw KiskisError.attestationFailed("Re-attestation failed")
            }
            return try processConfigResponse(retryData, response: retryHttp)
        }

        guard http.statusCode == 200 else {
            throw KiskisError.serverError(http.statusCode, String(data: data, encoding: .utf8) ?? "")
        }

        return try processConfigResponse(data, response: http)
    }

    private func processConfigResponse(_ data: Data, response: HTTPURLResponse) throws -> KiskisConfig {
        // Verify server signature before trusting any content.
        // Why: makes config integrity independent of TLS — a jailbroken device with a
        // custom trust anchor or a TLS-inspecting proxy cannot tamper with the config
        // payload without invalidating the Ed25519 signature over the exact bytes.
        let sig = response.value(forHTTPHeaderField: "X-Kiskis-Sig")
        let tsStr = response.value(forHTTPHeaderField: "X-Kiskis-Sig-Ts")
        guard let sig, let tsStr, let ts = Int(tsStr) else {
            throw KiskisError.serverError(200, "Missing response signature — ensure SDK and server versions match")
        }
        let path = response.url?.path ?? "/config"
        guard verifyResponseSignature(sig: sig, ts: ts, path: path, body: data) else {
            throw KiskisError.serverError(200, "Response signature verification failed")
        }

        // Always parse the outer JSON envelope first.
        guard let responseJson = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw KiskisError.serverError(200, "Invalid JSON")
        }

        // Server returns { "config": <value>, "matchedPattern": "2.*", ... }
        let configDict: [String: Any]

        if let vaultKey = zeroKnowledge.resolvedKey {
            // Why: ZK upload path — CLI encrypts the plaintext JSON with AES-256-GCM
            // and base64-encodes the binary before sending it. The server stores that
            // base64 string as the config value and returns it verbatim in `config`.
            // We must: (1) extract the base64 string, (2) decode to binary,
            // (3) decrypt to get the original plaintext JSON, (4) parse that.
            // Decrypting `data` directly (the full HTTP response JSON) was incorrect —
            // that bytestream is not the binary ciphertext.
            guard let ciphertextB64 = responseJson["config"] as? String,
                  let ciphertextData = Data(base64Encoded: ciphertextB64),
                  let decrypted = ZeroKnowledgeCrypto.decrypt(data: ciphertextData, key: vaultKey, teamId: teamId, bundleId: bundleId),
                  let decryptedDict = try? JSONSerialization.jsonObject(with: decrypted) as? [String: Any] else {
                throw KiskisError.zeroKnowledgeDecryptionFailed
            }
            configDict = decryptedDict
            // Why: ZK — disk holds ciphertext only so plaintext never persists outside
            // process memory. Decrypt on read via loadCachedConfig() on cold start.
            configCache.saveEncrypted(ciphertextData: ciphertextData, plaintextData: decrypted)
        } else {
            // Standard mode: config is a JSON object inline in the response.
            if let inner = responseJson["config"] as? [String: Any] {
                configDict = inner
            } else {
                configDict = responseJson
            }
            if let innerData = try? JSONSerialization.data(withJSONObject: configDict) {
                configCache.save(data: innerData)
            }
        }

        return KiskisConfig(data: configDict, isCached: false, isStale: false, fetchedAt: Date())
    }

    // MARK: - Internal: Blob Presigned URL

    private func fetchPresignedBlobURL(blobKey: String) async throws -> URL {
        let request = try await signedRequest(path: "blob/\(blobKey)")

        let (data, response) = try await urlSession.kiskisData(for: request)

        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw KiskisError.blobDownloadFailed("Failed to get presigned URL")
        }

        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let urlString = json["url"] as? String,
              let url = URL(string: urlString) else {
            throw KiskisError.blobDownloadFailed("Invalid presigned URL response")
        }

        return url
    }

    // MARK: - Internal: Helpers

    private func fetchChallenge() async throws -> String {
        let challengeURL = apiURL.appendingPathComponent("auth/challenge")
        var request = URLRequest(url: challengeURL)
        request.httpMethod = "POST"

        let (data, response) = try await urlSession.kiskisData(for: request)

        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw KiskisError.networkError("Failed to fetch challenge")
        }

        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let nonce = json["nonce"] as? String else {
            throw KiskisError.networkError("Invalid challenge response")
        }

        return nonce
    }
}
