import Foundation
import os

/// Lightweight diagnostic logging for the SDK.
///
/// Traces the attestation, assertion, config, and push flows through the unified log
/// (subsystem `dev.kiskis`, one category per area). Messages appear in Xcode's console and
/// in Console.app — filter by subsystem `dev.kiskis`. Toggle with
/// `KiskisClient.loggingEnabled` (default `true` so integration issues are visible; set
/// `false` in production to silence).
enum KiskisLog {
    /// Set to false to silence all SDK logging.
    static var enabled = true

    enum Category: String { case attestation, config, push, network, cache }

    private static let loggers: [Category: Logger] = [
        .attestation: Logger(subsystem: "dev.kiskis", category: "attestation"),
        .config:      Logger(subsystem: "dev.kiskis", category: "config"),
        .push:        Logger(subsystem: "dev.kiskis", category: "push"),
        .network:     Logger(subsystem: "dev.kiskis", category: "network"),
        .cache:       Logger(subsystem: "dev.kiskis", category: "cache"),
    ]

    /// Informational trace (default log level — always captured and shown in Xcode).
    static func info(_ category: Category, _ message: @autoclosure () -> String) {
        guard enabled else { return }
        let msg = message() // evaluate before the (escaping) Logger interpolation
        loggers[category]?.log("\(msg, privacy: .public)")
    }

    /// Error trace.
    static func error(_ category: Category, _ message: @autoclosure () -> String) {
        guard enabled else { return }
        let msg = message()
        loggers[category]?.error("\(msg, privacy: .public)")
    }
}

/// Short, log-safe form of a keyId (identifier, not a secret) to keep traces readable.
func kiskisShortKey(_ keyId: String) -> String {
    keyId.count > 10 ? "\(keyId.prefix(8))…" : keyId
}
