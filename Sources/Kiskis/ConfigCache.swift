import Foundation

/// Manages caching of config data.
///
/// Storage layers:
/// - **In-memory**: holds the current config for instant repeated access within a session
/// - **File system**: persists config under Library/Application Support with the file-protection
///   class specified by `CachePolicy.fileProtection` (default: `NSFileProtectionComplete`).
///   **Important:** `.complete` means the disk cache is unreadable while the device is locked.
///   Background refresh tasks and locked-state reads fall through to a full network fetch.
///   Use `CacheFileProtection.untilFirstUserAuthentication` if you need background reads to
///   hit the cache.
/// - **Keychain**: stores ONLY the keyId and attestation credentials (small, sensitive)
///
/// For developers who need stronger encryption, Zero-Knowledge mode encrypts the config
/// with AES-256-GCM before it ever reaches the cache. In ZK mode the disk cache holds
/// the server ciphertext; plaintext is kept in the in-process memory cache only.
final class ConfigCache: @unchecked Sendable {
    /// Freshness window before a cached config is flagged stale and a background
    /// refresh is triggered. Why 6h (was 1h): the cache is still served up to
    /// `CachePolicy.maxStaleness` (7 days) regardless, and urgent config changes
    /// propagate instantly via silent push — so the TTL is only the fallback refresh
    /// cadence for devices that missed a push. 6h cuts background refresh fetches
    /// ~6x versus hourly, with negligible freshness impact.
    static let defaultTTL: TimeInterval = 6 * 3600

    private let cacheDir: URL
    private let configFile: URL
    private let metadataFile: URL
    private let cachePolicy: CachePolicy

    /// In-memory cache — instant access, no disk read
    private var memoryCache: KiskisConfig?

    /// Serializes every entry point. What makes `@unchecked Sendable` above actually true —
    /// without this, that annotation was an unbacked claim.
    ///
    /// Why it's needed: `backgroundRefresh` defaults to true, and KiskisClient fires
    /// `Task { try? await refreshConfigFromServer() }` on every cache hit without awaiting it.
    /// So a detached refresh writing the cache while the app reads it is the NORMAL path, not
    /// a corner case. `memoryCache` was mutated from those tasks with no synchronization at
    /// all — a data race, which in Swift is undefined behaviour rather than a stale read.
    ///
    /// It also makes each save atomic as a WHOLE. Individual writes already use `.atomic`, but
    /// config and metadata are two separate files: two overlapping saves could interleave into
    /// config-from-B paired with metadata-from-A, so the stored config would carry the wrong
    /// fetch time and TTL. Holding the lock across both writes prevents that pairing.
    ///
    /// Why RECURSIVE and not a plain NSLock: `load()` and `loadEncryptedRaw()` both call
    /// `clear()` on a corrupt-cache path. A non-recursive lock would deadlock there — hanging
    /// the host app, which is a worse failure than the race being fixed here.
    ///
    /// Scope note: this guards a single process. Two processes sharing the container (an app
    /// and its extension) can still interleave; the `.atomic` per-file writes keep each file
    /// individually intact, and the versioned single-envelope format would be the real fix.
    private let lock = NSRecursiveLock()

    init(keychainGroup: String, cachePolicy: CachePolicy) {
        self.cachePolicy = cachePolicy

        // Store in app's Library/Application Support (NOT Caches or Documents)
        // - Library/Application Support: not user-visible, not cleared by iOS low-storage cleanup
        // - We exclude from backup so it never appears in iTunes/Finder backups
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        self.cacheDir = appSupport.appendingPathComponent("kiskis").appendingPathComponent(keychainGroup)
        self.configFile = cacheDir.appendingPathComponent("config.dat")
        self.metadataFile = cacheDir.appendingPathComponent("metadata.json")

        // Create directory if needed
        try? FileManager.default.createDirectory(at: cacheDir, withIntermediateDirectories: true)

        // Exclude from iCloud/iTunes backup — config never leaves the device via backup
        var dir = cacheDir
        var resourceValues = URLResourceValues()
        resourceValues.isExcludedFromBackup = true
        try? dir.setResourceValues(resourceValues)

        // Why: the directory-level fileProtectionKey is NOT set here. Setting it on a
        // directory only affects files created without explicit write options, and every
        // write in this class passes the appropriate Data.WritingOptions flag derived from
        // CachePolicy.fileProtection. A directory-level call would be a no-op here and
        // misleadingly suggest it's doing the protecting work.
    }

    /// Load cached config. Returns nil if no cache exists or if disk holds ZK ciphertext
    /// (caller must use loadEncryptedRaw() + decrypt for the cold-start ZK path).
    func load() -> KiskisConfig? {
        lock.lock(); defer { lock.unlock() }
        // Level 1: in-memory (instant)
        if let cached = memoryCache {
            let age = Date().timeIntervalSince(cached.fetchedAt)
            if age <= cachePolicy.maxStaleness {
                // Update staleness flag (may have changed since last check)
                let ttl = readTTL()
                let isStale = age > ttl
                if isStale != cached.isStale {
                    memoryCache = KiskisConfig(
                        data: cached.data,
                        isCached: true,
                        isStale: isStale,
                        fetchedAt: cached.fetchedAt
                    )
                }
                return memoryCache
            } else {
                // Beyond maxStaleness — discard
                memoryCache = nil
            }
        }

        // Level 2: file system — skip if disk holds ZK ciphertext.
        // KiskisClient uses loadEncryptedRaw() to handle that path.
        if readMetadata()?.isEncrypted == true { return nil }
        guard FileManager.default.fileExists(atPath: configFile.path) else {
            return nil
        }

        guard let configData = try? Data(contentsOf: configFile),
              let json = try? JSONSerialization.jsonObject(with: configData) as? [String: Any] else {
            return nil
        }

        guard let metadata = readMetadata() else {
            return nil
        }

        let fetchedAt = Date(timeIntervalSince1970: metadata.timestamp)
        let age = Date().timeIntervalSince(fetchedAt)

        // Check if beyond maxStaleness — don't return at all
        if age > cachePolicy.maxStaleness {
            clear()
            return nil
        }

        let isStale = age > metadata.ttl

        let config = KiskisConfig(
            data: json,
            isCached: true,
            isStale: isStale,
            fetchedAt: fetchedAt
        )

        // Populate memory cache
        memoryCache = config

        return config
    }

    /// Save plaintext config data to file cache and memory.
    func save(data: Data, ttl: TimeInterval = ConfigCache.defaultTTL) {
        lock.lock(); defer { lock.unlock() }
        // Write config data to file
        try? data.write(to: configFile, options: writeOptions())

        // Write metadata
        let metadata = CacheMetadata(
            timestamp: Date().timeIntervalSince1970,
            ttl: ttl,
            sizeBytes: data.count
        )
        if let metadataData = try? JSONEncoder().encode(metadata) {
            try? metadataData.write(to: metadataFile, options: writeOptions())
        }

        // Update memory cache
        if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            memoryCache = KiskisConfig(
                data: json,
                isCached: false,
                isStale: false,
                fetchedAt: Date()
            )
        }
    }

    /// Save ZK-mode config: ciphertext goes to disk, plaintext stays in memory only.
    /// On the cold-start read path, use loadEncryptedRaw() + decrypt rather than load().
    func saveEncrypted(ciphertextData: Data, plaintextData: Data, ttl: TimeInterval = ConfigCache.defaultTTL) {
        lock.lock(); defer { lock.unlock() }
        // Why: ZK guarantee — disk holds ciphertext only; an attacker with file access
        // cannot read secrets while the device is unlocked without also having the vault key.
        try? ciphertextData.write(to: configFile, options: writeOptions())

        let metadata = CacheMetadata(
            timestamp: Date().timeIntervalSince1970,
            ttl: ttl,
            sizeBytes: ciphertextData.count,
            isEncrypted: true
        )
        if let metadataData = try? JSONEncoder().encode(metadata) {
            try? metadataData.write(to: metadataFile, options: writeOptions())
        }

        // Memory cache holds decrypted config — in-process only, cleared on app termination.
        if let json = try? JSONSerialization.jsonObject(with: plaintextData) as? [String: Any] {
            memoryCache = KiskisConfig(data: json, isCached: false, isStale: false, fetchedAt: Date())
        }
    }

    /// Return the raw ciphertext bytes from disk for the ZK cold-start decrypt path.
    /// Returns nil if the cache is absent, not encrypted, or beyond maxStaleness.
    func loadEncryptedRaw() -> (data: Data, fetchedAt: Date, ttl: TimeInterval)? {
        lock.lock(); defer { lock.unlock() }
        guard let metadata = readMetadata(), metadata.isEncrypted else { return nil }
        guard FileManager.default.fileExists(atPath: configFile.path),
              let data = try? Data(contentsOf: configFile) else { return nil }
        let fetchedAt = Date(timeIntervalSince1970: metadata.timestamp)
        let age = Date().timeIntervalSince(fetchedAt)
        guard age <= cachePolicy.maxStaleness else {
            clear()
            return nil
        }
        return (data, fetchedAt, metadata.ttl)
    }

    /// Clear both memory and file cache.
    func clear() {
        lock.lock(); defer { lock.unlock() }
        memoryCache = nil
        try? FileManager.default.removeItem(at: configFile)
        try? FileManager.default.removeItem(at: metadataFile)
    }

    // MARK: - Private

    /// Convert the policy's file-protection level to Data write options.
    private func writeOptions() -> Data.WritingOptions {
        switch cachePolicy.fileProtection {
        case .complete:
            return [.atomic, .completeFileProtection]
        case .untilFirstUserAuthentication:
            return [.atomic, .completeFileProtectionUntilFirstUserAuthentication]
        }
    }

    private func readTTL() -> TimeInterval {
        return readMetadata()?.ttl ?? ConfigCache.defaultTTL
    }

    private func readMetadata() -> CacheMetadata? {
        guard let data = try? Data(contentsOf: metadataFile) else { return nil }
        return try? JSONDecoder().decode(CacheMetadata.self, from: data)
    }
}

private struct CacheMetadata: Codable {
    let timestamp: TimeInterval
    let ttl: TimeInterval
    let sizeBytes: Int
    let isEncrypted: Bool

    init(timestamp: TimeInterval, ttl: TimeInterval, sizeBytes: Int, isEncrypted: Bool = false) {
        self.timestamp = timestamp
        self.ttl = ttl
        self.sizeBytes = sizeBytes
        self.isEncrypted = isEncrypted
    }

    enum CodingKeys: String, CodingKey {
        case timestamp, ttl, sizeBytes, isEncrypted
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        timestamp = try c.decode(TimeInterval.self, forKey: .timestamp)
        ttl = try c.decode(TimeInterval.self, forKey: .ttl)
        sizeBytes = try c.decode(Int.self, forKey: .sizeBytes)
        // Why: old cache files written before ZK-cache landed don't have this field;
        // default to false so existing plaintext caches are read correctly on upgrade.
        isEncrypted = try c.decodeIfPresent(Bool.self, forKey: .isEncrypted) ?? false
    }
}
