import Foundation

/// Manages caching of config data.
///
/// Storage layers:
/// - **In-memory**: holds the current config for instant repeated access within a session
/// - **File system**: persists config to the app's Caches directory with NSFileProtectionComplete
///   (encrypted by iOS when the device is locked)
/// - **Keychain**: stores ONLY the keyId and attestation credentials (small, sensitive)
///
/// For developers who need stronger encryption, Zero-Knowledge mode encrypts the config
/// with AES-256-GCM before it ever reaches the cache.
final class ConfigCache: @unchecked Sendable {
    private let cacheDir: URL
    private let configFile: URL
    private let metadataFile: URL
    private let cachePolicy: CachePolicy

    /// In-memory cache — instant access, no disk read
    private var memoryCache: KiskisConfig?

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

        // Set NSFileProtectionComplete — iOS encrypts files when device is locked
        try? (cacheDir as NSURL).setResourceValue(
            URLFileProtection.complete,
            forKey: .fileProtectionKey
        )
    }

    /// Load cached config. Returns nil if no cache exists.
    /// Sets `isStale` if past TTL but within maxStaleness.
    func load() -> KiskisConfig? {
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

        // Level 2: file system
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

    /// Save config data to the file cache and memory.
    func save(data: Data, ttl: TimeInterval = 3600) {
        // Write config data to file
        try? data.write(to: configFile, options: [.atomic, .completeFileProtection])

        // Write metadata
        let metadata = CacheMetadata(
            timestamp: Date().timeIntervalSince1970,
            ttl: ttl,
            sizeBytes: data.count
        )
        if let metadataData = try? JSONEncoder().encode(metadata) {
            try? metadataData.write(to: metadataFile, options: [.atomic, .completeFileProtection])
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

    /// Clear both memory and file cache.
    func clear() {
        memoryCache = nil
        try? FileManager.default.removeItem(at: configFile)
        try? FileManager.default.removeItem(at: metadataFile)
    }

    // MARK: - Private

    private func readTTL() -> TimeInterval {
        return readMetadata()?.ttl ?? 3600
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
}
