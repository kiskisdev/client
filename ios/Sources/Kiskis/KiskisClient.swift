import Foundation
import CryptoKit

// MARK: - Configuration Types

/// Cache staleness policy when offline.
public enum StaleConfigPolicy: Sendable {
    case warnAndUse
    case failHard
    case useSilently
}

/// Configuration for cache behavior.
public struct CachePolicy: Sendable {
    public var maxStaleness: TimeInterval
    public var backgroundRefresh: Bool
    public var onStaleConfig: StaleConfigPolicy

    public init(
        maxStaleness: TimeInterval = 7 * 24 * 3600,
        backgroundRefresh: Bool = true,
        onStaleConfig: StaleConfigPolicy = .warnAndUse
    ) {
        self.maxStaleness = maxStaleness
        self.backgroundRefresh = backgroundRefresh
        self.onStaleConfig = onStaleConfig
    }
}

/// Zero-knowledge mode configuration.
public enum ZeroKnowledgeMode: Sendable {
    case disabled
    case enabled(key: String)
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
    private let apiURL: URL
    private let cachePolicy: CachePolicy
    private let zeroKnowledge: ZeroKnowledgeMode
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
        apiURL: URL = URL(string: "https://api.kiskis.dev")!,
        cachePolicy: CachePolicy = CachePolicy(),
        zeroKnowledge: ZeroKnowledgeMode = .disabled,
        fallbackConfig: URL? = nil,
        environment: KiskisEnvironment? = nil
    ) {
        self.teamId = teamId
        self.bundleId = bundleId ?? Bundle.main.bundleIdentifier ?? "unknown"
        self.apiURL = apiURL
        self.cachePolicy = cachePolicy
        self.zeroKnowledge = zeroKnowledge
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

        let keychainGroup = "kiskis.\(self.teamId).\(self.bundleId)"
        self.configCache = ConfigCache(keychainGroup: keychainGroup, cachePolicy: cachePolicy)
        self.attestationManager = AttestationManager(teamId: self.teamId, bundleId: self.bundleId)
        self.urlSession = URLSession(configuration: .ephemeral)

        KiskisClient.shared = self
    }

    // MARK: - App Version

    private var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0.0"
    }

    // MARK: - Public API: Config

    /// Fetch the app's configuration.
    /// Handles attestation, assertion signing, caching, and background refresh automatically.
    public func fetchConfig() async throws -> KiskisConfig {
        // 1. Try cache first
        if let cached = configCache.load() {
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
            // 3. First install offline — try fallback
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
    /// If `destination` is nil, saves to a temp directory and returns the URL.
    /// Verifies SHA-256 integrity if the BlobReference includes a hash.
    public func downloadBlob(_ ref: BlobReference, to destination: URL? = nil) async throws -> URL {
        // Get presigned URL from Kiskis API
        let presignedURL = try await fetchPresignedBlobURL(blobKey: ref.key)

        // Download from S3
        let (tempURL, response) = try await urlSession.kiskisDownload(from: presignedURL)

        guard let httpResponse = response as? HTTPURLResponse, httpResponse.statusCode == 200 else {
            throw KiskisError.blobDownloadFailed("Bad response from S3")
        }

        // Verify integrity if SHA-256 is provided
        if let expectedHash = ref.sha256 {
            let fileData = try Data(contentsOf: tempURL)
            let actualHash = SHA256.hash(data: fileData).map { String(format: "%02x", $0) }.joined()
            if actualHash != expectedHash.lowercased() {
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
            queryItems: [URLQueryItem(name: "user_id", value: userId)]
        )
        request.httpMethod = "PUT"
        request.httpBody = jsonData
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

        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let userData = json["data"] as? [String: Any] else {
            return nil
        }
        return userData
    }

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
        var request = try await signedRequest(path: "push/register")
        request.httpMethod = "POST"
        request.httpBody = body
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let (_, response) = try await urlSession.kiskisData(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw KiskisError.networkError("Failed to register userId for push")
        }
    }

    // MARK: - Internal: Assertion-Based Request Signing

    /// Build a request with assertion headers.
    /// Every protected request is signed by the Secure Enclave — no tokens.
    private func signedRequest(
        path: String,
        queryItems: [URLQueryItem] = []
    ) async throws -> URLRequest {
        let keyId = try await ensureRegistered()

        var components = URLComponents(url: apiURL.appendingPathComponent(path), resolvingAgainstBaseURL: false)!
        if !queryItems.isEmpty {
            components.queryItems = queryItems
        }
        var request = URLRequest(url: components.url!)

        // Client data = SHA256 of the request URL + current timestamp
        let clientData = "\(components.url!.absoluteString)|\(Int(Date().timeIntervalSince1970))"

        // Sign with Secure Enclave
        let assertionB64 = try await attestationManager.generateAssertion(
            payload: Data(clientData.utf8),
            keyId: keyId
        )

        // Set assertion headers
        request.setValue(keyId, forHTTPHeaderField: "X-Key-Id")
        request.setValue(teamId, forHTTPHeaderField: "X-Team-Id")
        request.setValue(bundleId, forHTTPHeaderField: "X-Bundle-Id")
        request.setValue(environment == .sandbox ? "sandbox" : "production", forHTTPHeaderField: "X-Environment")
        request.setValue(assertionB64, forHTTPHeaderField: "X-Assertion")
        request.setValue(clientData, forHTTPHeaderField: "X-Client-Data")

        // Include push token if available (for registration/updates)
        if let pushToken = pushToken {
            request.setValue(pushToken, forHTTPHeaderField: "X-Push-Token")
        }

        return request
    }

    /// Ensure the device is registered (attested). Returns the keyId.
    /// First launch: performs attestation. Subsequent: returns stored keyId.
    private func ensureRegistered() async throws -> String {
        // Already registered?
        if let keyId = attestationManager.storedKeyId {
            return keyId
        }

        // Need to attest
        let (keyId, _) = try await performAttestation()
        return keyId
    }

    /// Perform the full App Attest ceremony with the server.
    private func performAttestation() async throws -> (keyId: String, registered: Bool) {
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
            // Persist so subsequent launches use the correct environment
            KeychainHelper.save(key: "kiskis.env.\(teamId).\(bundleId)", value: serverEnv)
        }

        // Save keyId for future assertions
        attestationManager.saveKeyId(keyId)

        return (keyId, true)
    }

    // MARK: - Internal: Config Fetch

    private func refreshConfigFromServer() async throws -> KiskisConfig {
        var components = URLComponents(url: apiURL.appendingPathComponent("config"), resolvingAgainstBaseURL: false)!
        components.queryItems = [URLQueryItem(name: "version", value: appVersion)]

        var request = try await signedRequest(
            path: "config",
            queryItems: [URLQueryItem(name: "version", value: appVersion)]
        )

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
            request = try await signedRequest(
                path: "config",
                queryItems: [URLQueryItem(name: "version", value: appVersion)]
            )
            let (retryData, retryResponse) = try await urlSession.kiskisData(for: request)
            guard let retryHttp = retryResponse as? HTTPURLResponse, retryHttp.statusCode == 200 else {
                throw KiskisError.attestationFailed("Re-attestation failed")
            }
            return try processConfigResponse(retryData)
        }

        guard http.statusCode == 200 else {
            throw KiskisError.serverError(http.statusCode, String(data: data, encoding: .utf8) ?? "")
        }

        return try processConfigResponse(data)
    }

    private func processConfigResponse(_ data: Data) throws -> KiskisConfig {
        var configData = data

        // Zero-knowledge: decrypt locally
        if let vaultKey = zeroKnowledge.resolvedKey {
            guard let decrypted = ZeroKnowledgeCrypto.decrypt(data: data, key: vaultKey) else {
                throw KiskisError.zeroKnowledgeDecryptionFailed
            }
            configData = decrypted
        }

        guard let responseJson = try? JSONSerialization.jsonObject(with: configData) as? [String: Any] else {
            throw KiskisError.serverError(200, "Invalid JSON")
        }

        // Server returns { "config": {...}, "matchedPattern": "2.*" }
        let configDict: [String: Any]
        if let inner = responseJson["config"] as? [String: Any] {
            configDict = inner
        } else {
            configDict = responseJson
        }

        let config = KiskisConfig(data: configDict, isCached: false, isStale: false, fetchedAt: Date())

        // Cache
        if let innerData = try? JSONSerialization.data(withJSONObject: configDict) {
            configCache.save(data: innerData)
        } else {
            configCache.save(data: configData)
        }

        return config
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
