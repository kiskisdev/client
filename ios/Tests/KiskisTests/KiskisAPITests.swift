// KiskisAPITests.swift
// Integration tests for the Kiskis API.
//
// SETUP
// ─────
// 1. Add this file to your app's test target (or the KiskisTests target).
// 2. Edit the values in the Config enum below — everything you need is there.
// 3. Run with ⌘U.  Results appear in the Test navigator with pass/fail per test.
//
// Each test is self-contained and cleans up after itself.
// Tests that require devAuthEnabled=true are skipped automatically when false.

import XCTest
import CryptoKit

// ─────────────────────────────────────────────────────────────────────────────
// MARK: - Configuration  ← edit everything here
// ─────────────────────────────────────────────────────────────────────────────

private enum Config {

    // API base URL
    static let baseURL          = "https://api.kiskis.dev"

    // An ACTIVE provisioning key from the Kiskis dashboard (kk_prod_...)
    static let provisioningKey  = "kk_prod_REPLACE_ME"

    // Your Apple Team ID (10-char string from developer.apple.com)
    static let teamId           = "REPLACE_TEAM_ID"

    // Your app's bundle identifier
    static let bundleId         = "com.example.yourapp"

    // Config key used for test uploads.
    // Uses a unique name so tests can't accidentally overwrite production configs.
    static let testConfigKey    = "xcode_test"

    // User ID for per-user data tests. Any stable string works.
    static let testUserId       = "xcode_test_user_001"

    // Set to true ONLY when the backend has ALLOW_DEV_TOKENS=true.
    // Enables the delivery-API tests that run from Simulator without App Attest.
    static let devAuthEnabled   = false
}

// ─────────────────────────────────────────────────────────────────────────────
// MARK: - Network helper
// ─────────────────────────────────────────────────────────────────────────────

private struct R {
    let raw: [String: Any]
    let status: Int
    var ok: Bool { (200..<300).contains(status) }

    func str(_ k: String) -> String?            { raw[k] as? String }
    func int(_ k: String) -> Int?               { raw[k] as? Int }
    func bool(_ k: String) -> Bool?             { raw[k] as? Bool }
    func arr(_ k: String) -> [Any]?             { raw[k] as? [Any] }
    func obj(_ k: String) -> [String: Any]?     { raw[k] as? [String: Any] }
    func strArr(_ k: String) -> [String]?       { raw[k] as? [String] }
}

/// Make a REST call and return the decoded JSON + HTTP status.
/// - Parameters:
///   - path:    Path starting with "/", e.g. "/admin/config"
///   - method:  HTTP method (default GET)
///   - body:    JSON-serialisable dictionary (POST/PUT/DELETE body)
///   - auth:    Bearer token; pass nil to omit the Authorization header entirely
///   - query:   URL query parameters appended to path
///   - headers: Any extra headers (e.g. delivery dev-auth)
private func kk(
    _ path: String,
    method: String = "GET",
    body: [String: Any]? = nil,
    auth: String? = Config.provisioningKey,
    query: [String: String] = [:],
    headers: [String: String] = [:]
) async throws -> R {
    var urlStr = Config.baseURL + path
    if !query.isEmpty {
        let qs = query
            .sorted(by: { $0.key < $1.key })
            .map { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? $0.value)" }
            .joined(separator: "&")
        urlStr += "?" + qs
    }
    var req = URLRequest(url: URL(string: urlStr)!)
    req.httpMethod = method
    req.setValue("application/json", forHTTPHeaderField: "Content-Type")
    if let auth = auth, !auth.isEmpty {
        req.setValue("Bearer \(auth)", forHTTPHeaderField: "Authorization")
    }
    for (k, v) in headers { req.setValue(v, forHTTPHeaderField: k) }
    if let body = body {
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
    }
    let (data, resp) = try await URLSession.shared.data(for: req)
    let status = (resp as! HTTPURLResponse).statusCode
    let json = (try? JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:]
    return R(raw: json, status: status)
}

// ─────────────────────────────────────────────────────────────────────────────
// MARK: - Zero-Knowledge crypto helper
//
// Intentionally duplicates the algorithm from ZeroKnowledgeCrypto.swift.
// If that file changes in an incompatible way — different salt, different info
// string, different binary layout — these tests will fail and catch the regression
// before it ships to users whose cached ciphertext can no longer be decrypted.
// ─────────────────────────────────────────────────────────────────────────────

private enum ZKHelper {

    // Must match ZeroKnowledgeCrypto.swift exactly
    private static let salt = Data("kiskis-zk-salt".utf8)
    private static let info = Data("kiskis-zk-v1".utf8)

    static func deriveKey(_ password: String) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: Data(password.utf8)),
            salt: salt,
            info: info,
            outputByteCount: 32
        )
    }

    /// Returns: 12-byte nonce || ciphertext || 16-byte GCM tag
    static func encrypt(_ plaintext: Data, password: String) -> Data? {
        guard let box = try? AES.GCM.seal(plaintext, using: deriveKey(password)) else { return nil }
        var out = Data()
        out.append(contentsOf: box.nonce)
        out.append(box.ciphertext)
        out.append(box.tag)
        return out
    }

    static func decrypt(_ ciphertext: Data, password: String) -> Data? {
        guard ciphertext.count > 28 else { return nil }
        let nonce = ciphertext.prefix(12)
        let body  = ciphertext.dropFirst(12)
        guard let box = try? AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: nonce),
            ciphertext: body.dropLast(16),
            tag: body.suffix(16)
        ) else { return nil }
        return try? AES.GCM.open(box, using: deriveKey(password))
    }

    /// Encrypt a JSON dictionary and base64-encode — exact wire format sent to Kiskis
    static func encryptJson(_ dict: [String: Any], password: String) -> String? {
        guard let json = try? JSONSerialization.data(withJSONObject: dict),
              let enc  = encrypt(json, password: password) else { return nil }
        return enc.base64EncodedString()
    }

    /// Decode base64, decrypt, parse JSON — mirrors KiskisClient.processConfigResponse
    static func decryptJson(_ b64: String, password: String) -> [String: Any]? {
        guard let data = Data(base64Encoded: b64),
              let dec  = decrypt(data, password: password),
              let json = try? JSONSerialization.jsonObject(with: dec) as? [String: Any] else { return nil }
        return json
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MARK: - Test Suite
// ─────────────────────────────────────────────────────────────────────────────

final class KiskisAPITests: XCTestCase {

    // MARK: Convenience for cleanup

    private func deleteConfig(key: String = Config.testConfigKey,
                               version: String? = nil,
                               env: String = "sandbox") async throws {
        var q: [String: String] = [
            "key": key,
            "teamId": Config.teamId,
            "bundleId": Config.bundleId,
            "environment": env,
        ]
        if let v = version { q["version"] = v }
        _ = try await kk("/admin/config", method: "DELETE", query: q)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MARK: Config — Upload & Fetch round-trip
    // ─────────────────────────────────────────────────────────────────────────

    func testConfigUploadAndFetchRoundTrip() async throws {
        let payload: [String: Any] = ["stripe_key": "sk_test_abc", "flags": ["dark_mode": true]]

        // Upload
        let up = try await kk("/admin/config/upload", method: "POST", body: [
            "key": Config.testConfigKey, "version": "*",
            "config": payload, "environment": "sandbox",
        ])
        XCTAssertTrue(up.ok, "Upload failed (HTTP \(up.status)): \(up.raw)")
        XCTAssertEqual(up.str("key"), Config.testConfigKey)
        XCTAssertEqual(up.str("version"), "*")
        XCTAssertNotNil(up.int("revision"), "Upload response should include revision number")

        // Fetch manifest
        let m = try await kk("/admin/config", query: [
            "key": Config.testConfigKey,
            "teamId": Config.teamId,
            "bundleId": Config.bundleId,
            "environment": "sandbox",
        ])
        XCTAssertTrue(m.ok, "Manifest fetch failed (HTTP \(m.status)): \(m.raw)")
        XCTAssertEqual(m.str("key"), Config.testConfigKey)

        let manifest = m.obj("manifest")
        XCTAssertNotNil(manifest, "Response must include 'manifest' object")
        let entry = manifest?["*"] as? [String: Any]
        XCTAssertNotNil(entry, "Wildcard version should appear in manifest after upload")
        XCTAssertEqual(entry?["stripe_key"] as? String, "sk_test_abc",
                       "Config content should round-trip correctly")

        // patterns field should list "*" without underscore keys
        let patterns = m.strArr("patterns")
        XCTAssertTrue(patterns?.contains("*") == true, "patterns array should include *")
        XCTAssertFalse(patterns?.contains(where: { $0.hasPrefix("_") }) == true,
                       "patterns should not include underscore metadata keys")

        try await deleteConfig(version: "*")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MARK: Config — Delete & verify gone
    // ─────────────────────────────────────────────────────────────────────────

    func testConfigDeleteRemovesVersion() async throws {
        // Upload a unique version
        let up = try await kk("/admin/config/upload", method: "POST", body: [
            "key": Config.testConfigKey, "version": "9.*",
            "config": ["delete_test": true], "environment": "sandbox",
        ])
        XCTAssertTrue(up.ok, "Setup upload failed: \(up.raw)")

        // Confirm it exists
        let before = try await kk("/admin/config", query: [
            "key": Config.testConfigKey, "teamId": Config.teamId,
            "bundleId": Config.bundleId, "environment": "sandbox",
        ])
        XCTAssertNotNil(before.obj("manifest")?["9.*"], "Version 9.* should exist before delete")

        // Delete specific version
        let del = try await kk("/admin/config", method: "DELETE", query: [
            "key": Config.testConfigKey, "teamId": Config.teamId,
            "bundleId": Config.bundleId, "environment": "sandbox",
            "version": "9.*",
        ])
        XCTAssertTrue(del.ok, "Delete failed (HTTP \(del.status)): \(del.raw)")

        // Confirm it is gone
        let after = try await kk("/admin/config", query: [
            "key": Config.testConfigKey, "teamId": Config.teamId,
            "bundleId": Config.bundleId, "environment": "sandbox",
        ])
        let manifestAfter = after.obj("manifest") ?? [:]
        XCTAssertNil(manifestAfter["9.*"], "Version 9.* should be absent after delete")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MARK: Config — Update replaces data
    // ─────────────────────────────────────────────────────────────────────────

    func testConfigUpdateReplacesExistingVersion() async throws {
        // Upload v1
        _ = try await kk("/admin/config/upload", method: "POST", body: [
            "key": Config.testConfigKey, "version": "*",
            "config": ["value": 1, "old_field": "yes"], "environment": "sandbox",
        ])

        // Re-upload same version with different data
        let up2 = try await kk("/admin/config/upload", method: "POST", body: [
            "key": Config.testConfigKey, "version": "*",
            "config": ["value": 2, "new_field": "yes"], "environment": "sandbox",
        ])
        XCTAssertTrue(up2.ok, "Re-upload failed: \(up2.raw)")

        let m = try await kk("/admin/config", query: [
            "key": Config.testConfigKey, "teamId": Config.teamId,
            "bundleId": Config.bundleId, "environment": "sandbox",
        ])
        let entry = m.obj("manifest")?["*"] as? [String: Any]
        XCTAssertEqual(entry?["value"] as? Int, 2, "Updated value should be 2")
        XCTAssertEqual(entry?["new_field"] as? String, "yes", "New field should be present")
        XCTAssertNil(entry?["old_field"], "Old field should be replaced, not merged")

        try await deleteConfig(version: "*")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MARK: Config — Version pattern precedence
    // ─────────────────────────────────────────────────────────────────────────

    func testConfigVersionPatternsInManifest() async throws {
        // Upload three patterns — exact, major-wildcard, fallback
        for (version, label) in [("*", "wildcard"), ("2.*", "major"), ("2.1.3", "exact")] {
            let r = try await kk("/admin/config/upload", method: "POST", body: [
                "key": Config.testConfigKey, "version": version,
                "config": ["tier": label], "environment": "sandbox",
            ])
            XCTAssertTrue(r.ok, "Upload \(version) failed: \(r.raw)")
        }

        let m = try await kk("/admin/config", query: [
            "key": Config.testConfigKey, "teamId": Config.teamId,
            "bundleId": Config.bundleId, "environment": "sandbox",
        ])
        XCTAssertTrue(m.ok, "Manifest fetch failed: \(m.raw)")
        let manifest = m.obj("manifest") ?? [:]
        XCTAssertNotNil(manifest["*"],     "Wildcard pattern should be in manifest")
        XCTAssertNotNil(manifest["2.*"],   "Major-wildcard pattern should be in manifest")
        XCTAssertNotNil(manifest["2.1.3"], "Exact version should be in manifest")
        XCTAssertEqual(m.strArr("patterns")?.count, 3,
                       "patterns array should list exactly 3 version keys")

        for v in ["*", "2.*", "2.1.3"] { try await deleteConfig(version: v) }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MARK: Config — Bulk delete (no version param removes all patterns)
    // ─────────────────────────────────────────────────────────────────────────

    func testConfigBulkDeleteRemovesAllVersions() async throws {
        let bulkKey = Config.testConfigKey + "_bulk"
        for (version, label) in [("*", "wild"), ("3.*", "major"), ("3.5.0", "exact")] {
            let r = try await kk("/admin/config/upload", method: "POST", body: [
                "key": bulkKey, "version": version,
                "config": ["bulk_test": label], "environment": "sandbox",
            ])
            XCTAssertTrue(r.ok, "Upload \(version) failed: \(r.raw)")
        }

        let before = try await kk("/admin/config", query: [
            "key": bulkKey, "teamId": Config.teamId,
            "bundleId": Config.bundleId, "environment": "sandbox",
        ])
        let countBefore = (before.obj("manifest") ?? [:])
            .keys.filter { !$0.hasPrefix("_") }.count
        XCTAssertGreaterThanOrEqual(countBefore, 3, "Expected ≥3 patterns before bulk delete")

        // Delete without specifying a version → removes all patterns for this key
        let del = try await kk("/admin/config", method: "DELETE", query: [
            "key": bulkKey, "teamId": Config.teamId,
            "bundleId": Config.bundleId, "environment": "sandbox",
        ])
        XCTAssertTrue(del.ok, "Bulk delete failed (HTTP \(del.status)): \(del.raw)")

        let after = try await kk("/admin/config", query: [
            "key": bulkKey, "teamId": Config.teamId,
            "bundleId": Config.bundleId, "environment": "sandbox",
        ])
        let remaining = (after.obj("manifest") ?? [:])
            .keys.filter { !$0.hasPrefix("_") }
        XCTAssertTrue(remaining.isEmpty,
                      "All patterns should be gone after bulk delete (remaining: \(remaining))")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MARK: Config — Nonexistent key returns empty manifest or 404
    // ─────────────────────────────────────────────────────────────────────────

    func testConfigFetchNonexistentKeyReturnsEmptyOrNotFound() async throws {
        let ghostKey = "xctest_ghost_\(Int(Date().timeIntervalSince1970))"
        let r = try await kk("/admin/config", query: [
            "key": ghostKey, "teamId": Config.teamId,
            "bundleId": Config.bundleId, "environment": "sandbox",
        ])
        if r.status == 404 {
            XCTAssertNotNil(r.str("error"), "404 response should include an error message")
        } else {
            XCTAssertTrue(r.ok, "Expected 200 or 404, got \(r.status): \(r.raw)")
            let patterns = (r.obj("manifest") ?? [:]).keys.filter { !$0.hasPrefix("_") }
            XCTAssertTrue(patterns.isEmpty,
                          "Non-existent key should have empty manifest, got: \(patterns)")
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MARK: Config — Empty {} is a valid config payload
    // ─────────────────────────────────────────────────────────────────────────

    func testConfigUploadEmptyJsonIsAccepted() async throws {
        let r = try await kk("/admin/config/upload", method: "POST", body: [
            "key": Config.testConfigKey, "version": "empty_test",
            "config": [:] as [String: Any], "environment": "sandbox",
        ])
        XCTAssertTrue(r.ok, "Empty config {} should be accepted (HTTP \(r.status)): \(r.raw)")
        XCTAssertNil(r.str("error"), "Response must not contain error field")

        let m = try await kk("/admin/config", query: [
            "key": Config.testConfigKey, "teamId": Config.teamId,
            "bundleId": Config.bundleId, "environment": "sandbox",
        ])
        XCTAssertNotNil(m.obj("manifest")?["empty_test"],
                        "empty_test version should appear in manifest after upload")

        try await deleteConfig(version: "empty_test")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MARK: Config — Missing required fields are rejected
    // ─────────────────────────────────────────────────────────────────────────

    func testConfigUploadMissingConfigFieldIsRejected() async throws {
        let r = try await kk("/admin/config/upload", method: "POST", body: [
            "key": Config.testConfigKey, "version": "*", "environment": "sandbox",
            // "config" deliberately absent
        ])
        XCTAssertFalse(r.ok,
                       "Upload missing 'config' field should fail, got HTTP \(r.status): \(r.raw)")
        XCTAssertNotEqual(r.status, 500, "Server must not 500 on missing field")
    }

    func testConfigUploadMissingVersionFieldIsRejected() async throws {
        let r = try await kk("/admin/config/upload", method: "POST", body: [
            "key": Config.testConfigKey,
            "config": ["test": true],
            "environment": "sandbox",
            // "version" deliberately absent
        ])
        XCTAssertFalse(r.ok,
                       "Upload missing 'version' field should fail, got HTTP \(r.status): \(r.raw)")
        XCTAssertNotEqual(r.status, 500, "Server must not 500 on missing version")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MARK: Config — Revision number increments on re-upload
    // ─────────────────────────────────────────────────────────────────────────

    func testConfigRevisionNumberIncrements() async throws {
        let up1 = try await kk("/admin/config/upload", method: "POST", body: [
            "key": Config.testConfigKey, "version": "rev_test",
            "config": ["v": 1], "environment": "sandbox",
        ])
        XCTAssertTrue(up1.ok, "First upload failed: \(up1.raw)")
        let rev1 = up1.int("revision")

        let up2 = try await kk("/admin/config/upload", method: "POST", body: [
            "key": Config.testConfigKey, "version": "rev_test",
            "config": ["v": 2], "environment": "sandbox",
        ])
        XCTAssertTrue(up2.ok, "Second upload failed: \(up2.raw)")
        let rev2 = up2.int("revision")

        if let r1 = rev1, let r2 = rev2 {
            XCTAssertGreaterThan(r2, r1, "Revision number must increment on each upload")
        }

        try await deleteConfig(version: "rev_test")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MARK: Config — Sandbox / Production isolation
    // ─────────────────────────────────────────────────────────────────────────

    func testConfigSandboxProductionIsolation() async throws {
        // Upload distinct data to each environment
        let sbUp = try await kk("/admin/config/upload", method: "POST", body: [
            "key": Config.testConfigKey, "version": "*",
            "config": ["env": "sandbox"], "environment": "sandbox",
        ])
        let prUp = try await kk("/admin/config/upload", method: "POST", body: [
            "key": Config.testConfigKey, "version": "*",
            "config": ["env": "production"], "environment": "production",
        ])
        XCTAssertTrue(sbUp.ok, "Sandbox upload failed: \(sbUp.raw)")
        XCTAssertTrue(prUp.ok, "Production upload failed: \(prUp.raw)")

        // Sandbox manifest should show sandbox data
        let sbM = try await kk("/admin/config", query: [
            "key": Config.testConfigKey, "teamId": Config.teamId,
            "bundleId": Config.bundleId, "environment": "sandbox",
        ])
        let sbEntry = sbM.obj("manifest")?["*"] as? [String: Any]
        XCTAssertEqual(sbEntry?["env"] as? String, "sandbox",
                       "Sandbox manifest should contain sandbox data")
        XCTAssertNotEqual(sbEntry?["env"] as? String, "production",
                          "Sandbox manifest must NOT leak production data")

        // Production manifest should show production data
        let prM = try await kk("/admin/config", query: [
            "key": Config.testConfigKey, "teamId": Config.teamId,
            "bundleId": Config.bundleId, "environment": "production",
        ])
        let prEntry = prM.obj("manifest")?["*"] as? [String: Any]
        XCTAssertEqual(prEntry?["env"] as? String, "production",
                       "Production manifest should contain production data")
        XCTAssertNotEqual(prEntry?["env"] as? String, "sandbox",
                          "Production manifest must NOT leak sandbox data")

        try await deleteConfig(version: "*", env: "sandbox")
        try await deleteConfig(version: "*", env: "production")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MARK: Config — Named keys are isolated from each other
    // ─────────────────────────────────────────────────────────────────────────

    func testNamedConfigKeysAreIsolated() async throws {
        let keyA = Config.testConfigKey + "_a"
        let keyB = Config.testConfigKey + "_b"

        for (k, val) in [(keyA, "alpha"), (keyB, "beta")] {
            let r = try await kk("/admin/config/upload", method: "POST", body: [
                "key": k, "version": "*",
                "config": ["marker": val], "environment": "sandbox",
            ])
            XCTAssertTrue(r.ok, "Upload for key \(k) failed: \(r.raw)")
        }

        let mA = try await kk("/admin/config", query: [
            "key": keyA, "teamId": Config.teamId,
            "bundleId": Config.bundleId, "environment": "sandbox",
        ])
        let mB = try await kk("/admin/config", query: [
            "key": keyB, "teamId": Config.teamId,
            "bundleId": Config.bundleId, "environment": "sandbox",
        ])

        let valA = (mA.obj("manifest")?["*"] as? [String: Any])?["marker"] as? String
        let valB = (mB.obj("manifest")?["*"] as? [String: Any])?["marker"] as? String
        XCTAssertEqual(valA, "alpha", "Key A should return alpha")
        XCTAssertEqual(valB, "beta",  "Key B should return beta")
        XCTAssertNotEqual(valA, valB, "Different named keys must not share data")

        for k in [keyA, keyB] { try await deleteConfig(key: k, version: "*") }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MARK: Billing
    // ─────────────────────────────────────────────────────────────────────────

    func testBillingReadReturnsValidStructure() async throws {
        let r = try await kk("/admin/billing", query: [
            "teamId": Config.teamId, "bundleId": Config.bundleId,
        ])
        XCTAssertTrue(r.ok, "Billing GET failed (HTTP \(r.status)): \(r.raw)")

        // Required fields
        XCTAssertNotNil(r.str("tier"),          "Missing tier")
        XCTAssertNotNil(r.str("status"),        "Missing status")
        XCTAssertNotNil(r.str("billing_mode"),  "Missing billing_mode")
        XCTAssertNotNil(r.str("month"),         "Missing month (YYYY-MM)")
        XCTAssertNotNil(r.str("team_id"),       "Missing team_id")
        XCTAssertNotNil(r.str("bundle_id"),     "Missing bundle_id")

        // mau_count and mau_limit must be non-negative integers
        let mauCount = r.int("mau_count")
        let mauLimit = r.int("mau_limit")
        XCTAssertNotNil(mauCount, "Missing mau_count")
        XCTAssertNotNil(mauLimit, "Missing mau_limit")
        XCTAssertGreaterThanOrEqual(mauCount ?? -1, 0, "mau_count must be >= 0")
        XCTAssertGreaterThan(mauLimit ?? 0, 0, "mau_limit must be > 0")

        // tier must be a known value
        let validTiers = ["hobby", "indie", "pro", "growth", "scale"]
        XCTAssertTrue(validTiers.contains(r.str("tier") ?? ""),
                      "Unexpected tier '\(r.str("tier") ?? "nil")'")

        // billing_mode must be test or live
        let validModes = ["test", "live"]
        XCTAssertTrue(validModes.contains(r.str("billing_mode") ?? ""),
                      "Unexpected billing_mode '\(r.str("billing_mode") ?? "nil")'")

        // Month format YYYY-MM
        let month = r.str("month") ?? ""
        XCTAssertTrue(month.range(of: #"^\d{4}-\d{2}$"#, options: .regularExpression) != nil,
                      "month '\(month)' should be YYYY-MM format")

        // apps array (may be empty)
        XCTAssertNotNil(r.arr("apps"), "Missing apps array")

        // subscriptions object
        XCTAssertNotNil(r.obj("subscriptions"), "Missing subscriptions object")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MARK: Billing — Mode toggle (test ↔ live)
    // ─────────────────────────────────────────────────────────────────────────

    func testBillingModeToggleAndRestore() async throws {
        let initial = try await kk("/admin/billing", query: [
            "teamId": Config.teamId, "bundleId": Config.bundleId,
        ])
        XCTAssertTrue(initial.ok, "Initial billing GET failed: \(initial.raw)")
        guard let originalMode = initial.str("billing_mode") else {
            XCTFail("Could not determine current billing_mode"); return
        }
        XCTAssertTrue(["test", "live"].contains(originalMode),
                      "billing_mode must be test or live, got '\(originalMode)'")

        let altMode = originalMode == "test" ? "live" : "test"

        let toggle = try await kk("/admin/billing/mode", method: "PUT", body: [
            "teamId": Config.teamId, "bundleId": Config.bundleId, "mode": altMode,
        ])
        XCTAssertTrue(toggle.ok,
                      "Mode toggle to \(altMode) failed (HTTP \(toggle.status)): \(toggle.raw)")

        let afterToggle = try await kk("/admin/billing", query: [
            "teamId": Config.teamId, "bundleId": Config.bundleId,
        ])
        XCTAssertEqual(afterToggle.str("billing_mode"), altMode,
                       "billing_mode should now be \(altMode)")

        // Restore to avoid leaving test in an unexpected mode
        let restore = try await kk("/admin/billing/mode", method: "PUT", body: [
            "teamId": Config.teamId, "bundleId": Config.bundleId, "mode": originalMode,
        ])
        XCTAssertTrue(restore.ok, "Mode restore failed: \(restore.raw)")

        let afterRestore = try await kk("/admin/billing", query: [
            "teamId": Config.teamId, "bundleId": Config.bundleId,
        ])
        XCTAssertEqual(afterRestore.str("billing_mode"), originalMode,
                       "billing_mode should be restored to \(originalMode)")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MARK: Coupon — Public validation endpoint
    // ─────────────────────────────────────────────────────────────────────────

    func testCouponInvalidCodeReturnsError() async throws {
        // /billing/redeem-coupon is intentionally public — no auth required
        let r = try await kk("/billing/redeem-coupon", method: "POST", auth: nil, body: [
            "code": "XCTEST_INVALID_COUPON_CODE_NEVER_REAL",
        ])
        XCTAssertNotEqual(r.status, 500, "Server must not 500 on invalid coupon code")
        if r.ok {
            // Some implementations return 200 with valid: false
            let isValid = r.bool("valid") ?? true
            XCTAssertFalse(isValid, "Invalid coupon should return valid: false (got \(r.raw))")
        } else {
            XCTAssertTrue(r.status == 400 || r.status == 404,
                          "Invalid coupon should return 400/404, got \(r.status): \(r.raw)")
        }
    }

    func testCouponMissingCodeFieldHandledGracefully() async throws {
        let r = try await kk("/billing/redeem-coupon", method: "POST", auth: nil, body: [:])
        XCTAssertNotEqual(r.status, 500, "Server must not 500 on empty body")
        XCTAssertFalse(r.ok, "Empty body should not return 2xx (got \(r.status))")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MARK: User Data — Full CRUD round-trip
    // ─────────────────────────────────────────────────────────────────────────

    func testUserDataWriteReadDeleteRoundTrip() async throws {
        let userId = Config.testUserId
        let v1: [String: Any] = ["score": 42, "level": "bronze", "tags": ["early_adopter"]]

        // Write
        let put1 = try await kk("/admin/users/\(userId)/data", method: "PUT", body: v1)
        XCTAssertTrue(put1.ok, "Initial PUT failed (HTTP \(put1.status)): \(put1.raw)")
        XCTAssertEqual(put1.str("message"), "User data saved")
        XCTAssertEqual(put1.str("user_id"), userId)

        // Read back and verify all fields
        let get1 = try await kk("/admin/users/\(userId)/data")
        XCTAssertTrue(get1.ok, "GET after PUT failed: \(get1.raw)")
        XCTAssertEqual(get1.str("user_id"), userId)
        let data1 = get1.obj("data")
        XCTAssertNotNil(data1, "GET response should wrap data in 'data' key")
        XCTAssertEqual(data1?["score"] as? Int, 42,            "score should round-trip")
        XCTAssertEqual(data1?["level"] as? String, "bronze",   "level should round-trip")
        let tags = data1?["tags"] as? [String]
        XCTAssertEqual(tags?.first, "early_adopter", "tags array should round-trip")

        // Overwrite with different data — confirm full replacement (not merge)
        let v2: [String: Any] = ["score": 100, "new_field": "present"]
        let put2 = try await kk("/admin/users/\(userId)/data", method: "PUT", body: v2)
        XCTAssertTrue(put2.ok, "Update PUT failed: \(put2.raw)")

        let get2 = try await kk("/admin/users/\(userId)/data")
        let data2 = get2.obj("data")
        XCTAssertEqual(data2?["score"] as? Int, 100,       "score should be updated")
        XCTAssertNotNil(data2?["new_field"],               "new_field should exist")
        XCTAssertNil(data2?["level"],                      "level should be gone — PUT replaces, not merges")
        XCTAssertNil(data2?["tags"],                       "tags should be gone after replacement")

        // Delete
        let del = try await kk("/admin/users/\(userId)/data", method: "DELETE")
        XCTAssertTrue(del.ok, "DELETE failed (HTTP \(del.status)): \(del.raw)")
        XCTAssertEqual(del.str("message"), "User data deleted")
        XCTAssertEqual(del.str("user_id"), userId)

        // Verify deletion — GET should return 404 or empty data
        let get3 = try await kk("/admin/users/\(userId)/data")
        if get3.status == 404 {
            XCTAssertNotNil(get3.str("error"), "404 response should have error message")
        } else {
            // Some implementations return 200 with null/empty data
            let data3 = get3.obj("data")
            XCTAssertTrue(data3 == nil || data3?.isEmpty == true,
                          "Data should be absent or empty after delete (got \(get3.raw))")
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MARK: Push — Broadcast returns ID and status
    // ─────────────────────────────────────────────────────────────────────────

    func testPushBroadcastReturnsId() async throws {
        let r = try await kk("/push/broadcast", method: "POST", body: [
            "teamId": Config.teamId,
            "bundleId": Config.bundleId,
            "title": "XCTest Broadcast",
            "body": "Automated test push",
            "data": ["source": "xcode_test", "ts": Int(Date().timeIntervalSince1970)],
            "silent": false,
            "env": "sandbox",
        ])
        XCTAssertTrue(r.ok, "Broadcast failed (HTTP \(r.status)): \(r.raw)")
        XCTAssertNotNil(r.str("id"),      "Response must include push ID")
        XCTAssertNotNil(r.str("status"),  "Response must include status")
        let validStatuses = ["queued", "sent", "sending", "complete"]
        XCTAssertTrue(validStatuses.contains(r.str("status") ?? ""),
                      "Unexpected status '\(r.str("status") ?? "nil")'")
    }

    func testPushBroadcastStatusCheckRoundTrip() async throws {
        // Send a silent broadcast
        let broadcast = try await kk("/push/broadcast", method: "POST", body: [
            "teamId": Config.teamId,
            "bundleId": Config.bundleId,
            "silent": true,
            "data": ["test": "status_check"],
            "env": "sandbox",
        ])
        XCTAssertTrue(broadcast.ok, "Broadcast failed: \(broadcast.raw)")

        guard let pushId = broadcast.str("id") else {
            XCTFail("No push ID in broadcast response"); return
        }

        // Allow the push worker a moment to process
        try await Task.sleep(nanoseconds: 1_500_000_000)

        // Check status — ID must match and status must be a known value
        let status = try await kk("/push/status/\(pushId)", query: [
            "teamId": Config.teamId, "bundleId": Config.bundleId,
        ])
        XCTAssertTrue(status.ok, "Status check failed (HTTP \(status.status)): \(status.raw)")
        XCTAssertEqual(status.str("id"), pushId, "Returned ID must match the broadcast ID")
        let validStatuses = ["queued", "sending", "complete", "sent", "failed"]
        XCTAssertTrue(validStatuses.contains(status.str("status") ?? ""),
                      "Unexpected status '\(status.str("status") ?? "nil")'")
    }

    func testPushSendToUserDoesNotError() async throws {
        // User may have zero registered devices — that's OK.
        // The important thing is no 4xx/5xx error and no error field.
        let r = try await kk("/push/send", method: "POST", body: [
            "teamId": Config.teamId,
            "bundleId": Config.bundleId,
            "to": Config.testUserId,
            "title": "XCTest Direct Push",
            "body": "Direct push test",
            "env": "sandbox",
        ])
        XCTAssertTrue(r.ok, "Push send errored (HTTP \(r.status)): \(r.raw)")
        XCTAssertNil(r.str("error"), "Response should not contain an error field")
        XCTAssertNotNil(r.str("id") ?? r.str("status"),
                        "Response should include an id or status field")
    }

    func testPushBroadcastWithVersionFilter() async throws {
        // Broadcasts can be targeted to devices running a specific app version range
        let r = try await kk("/push/broadcast", method: "POST", body: [
            "teamId": Config.teamId,
            "bundleId": Config.bundleId,
            "title": "Version-filtered XCTest push",
            "body": "Only for v2.x",
            "version": "2.*",
            "env": "sandbox",
        ])
        XCTAssertTrue(r.ok, "Version-filtered broadcast failed (HTTP \(r.status)): \(r.raw)")
        XCTAssertNotNil(r.str("id"),     "Response must include push ID")
        XCTAssertNotNil(r.str("status"), "Response must include status")
        XCTAssertNil(r.str("error"),     "Response must not include error field")
    }

    func testPushSilentBroadcastWithNoTitleOrBody() async throws {
        // Silent pushes wake the app in background — title and body are optional
        let r = try await kk("/push/broadcast", method: "POST", body: [
            "teamId": Config.teamId,
            "bundleId": Config.bundleId,
            "silent": true,
            "data": ["action": "refresh", "xctest": true],
            "env": "sandbox",
        ])
        XCTAssertTrue(r.ok,
                      "Silent broadcast without title/body failed (HTTP \(r.status)): \(r.raw)")
        XCTAssertNotNil(r.str("id"), "Silent broadcast should return a push ID")
        XCTAssertNil(r.str("error"), "Response must not include error field")
    }

    func testPushSendToDeviceByKeyId() async throws {
        // Sending by device keyId to a key that doesn't exist must not crash the server.
        // Accept 200 (0 sent) or 404 (device not found) — but never 500.
        let r = try await kk("/push/send", method: "POST", body: [
            "teamId": Config.teamId,
            "bundleId": Config.bundleId,
            "device": "xctest_nonexistent_device_key_000",
            "title": "Device-targeted push",
            "body": "XCTest",
            "env": "sandbox",
        ])
        XCTAssertNotEqual(r.status, 500, "Server must not 500 on unknown device keyId")
        XCTAssertTrue(r.ok || r.status == 404,
                      "Push to unknown device should be 2xx or 404, got \(r.status): \(r.raw)")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MARK: Kill Switch
    // ─────────────────────────────────────────────────────────────────────────

    func testKillSwitchEnableAndDisable() async throws {
        // Upload a config we can kill
        _ = try await kk("/admin/config/upload", method: "POST", body: [
            "key": Config.testConfigKey, "version": "*",
            "config": ["kill_test": true], "environment": "sandbox",
        ])

        // Enable kill switch for the wildcard version
        let kill = try await kk("/admin/kill-switch", method: "POST", body: [
            "versions": ["*"],
            "enabled": true,
            "key": Config.testConfigKey,
            "reason": "XCTest kill switch test",
        ])
        XCTAssertTrue(kill.ok, "Kill switch enable failed (HTTP \(kill.status)): \(kill.raw)")
        XCTAssertNotNil(kill.str("message"), "Kill response should include message")

        // Re-enable (undo)
        let reenable = try await kk("/admin/kill-switch", method: "POST", body: [
            "versions": ["*"],
            "enabled": false,
            "key": Config.testConfigKey,
        ])
        XCTAssertTrue(reenable.ok, "Kill switch disable failed (HTTP \(reenable.status)): \(reenable.raw)")
        XCTAssertNotNil(reenable.str("message"), "Re-enable response should include message")

        try await deleteConfig(version: "*")
    }

    func testEmergencyRevokeSetsForceTTL() async throws {
        // Upload a version to revoke
        _ = try await kk("/admin/config/upload", method: "POST", body: [
            "key": Config.testConfigKey, "version": "*",
            "config": ["emergency_test": true], "environment": "sandbox",
        ])

        let revoke = try await kk("/admin/emergency-revoke", method: "POST", body: [
            "version": "*",
            "key": Config.testConfigKey,
            "force_refresh_ttl": 300,
        ])
        XCTAssertTrue(revoke.ok, "Emergency revoke failed (HTTP \(revoke.status)): \(revoke.raw)")
        XCTAssertNotNil(revoke.str("message"),         "Missing message in revoke response")
        XCTAssertEqual(revoke.int("force_refresh_ttl"), 300, "force_refresh_ttl should echo back")

        // push field should always be present (sent: N, failed: M)
        let push = revoke.obj("push")
        XCTAssertNotNil(push, "Emergency revoke response should include 'push' field")
        XCTAssertNotNil(push?["sent"],   "push.sent should be present")
        XCTAssertNotNil(push?["failed"], "push.failed should be present")

        try await deleteConfig(version: "*")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MARK: Authentication — rejection tests
    // ─────────────────────────────────────────────────────────────────────────

    func testMissingAuthReturns401() async throws {
        let r = try await kk("/admin/config", auth: nil, query: [
            "key": "default",
            "teamId": Config.teamId,
            "bundleId": Config.bundleId,
            "environment": "sandbox",
        ])
        XCTAssertEqual(r.status, 401, "No auth header should yield 401, got \(r.status): \(r.raw)")
    }

    func testInvalidProvisioningKeyReturns401() async throws {
        let r = try await kk("/admin/config",
                             auth: "kk_prod_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                             query: [
            "key": "default",
            "teamId": Config.teamId,
            "bundleId": Config.bundleId,
            "environment": "sandbox",
        ])
        XCTAssertEqual(r.status, 401, "Invalid key should yield 401, got \(r.status): \(r.raw)")
    }

    func testMalformedBearerTokenReturns401() async throws {
        // A plausible-looking but invalid JWT
        let fakeJwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.invalidsig"
        let r = try await kk("/admin/config",
                             auth: fakeJwt,
                             query: [
            "key": "default",
            "teamId": Config.teamId,
            "bundleId": Config.bundleId,
            "environment": "sandbox",
        ])
        XCTAssertEqual(r.status, 401, "Forged JWT should yield 401, got \(r.status)")
    }

    func testConfigUploadWithoutAuthReturns401() async throws {
        let r = try await kk("/admin/config/upload", method: "POST", auth: nil, body: [
            "key": "default", "version": "*",
            "config": ["hack": true], "environment": "sandbox",
        ])
        XCTAssertEqual(r.status, 401, "Upload without auth should yield 401, got \(r.status)")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MARK: Input validation
    // ─────────────────────────────────────────────────────────────────────────

    func testUploadWithInvalidVersionPatternRejected() async throws {
        // Path traversal string is not a valid semver pattern
        let r = try await kk("/admin/config/upload", method: "POST", body: [
            "key": Config.testConfigKey,
            "version": "../../../etc/passwd",
            "config": ["hack": true],
            "environment": "sandbox",
        ])
        // Must be rejected (400) — must NOT 200 and store a path traversal key
        if r.ok {
            // If accepted, verify the manifest does NOT contain the traversal string
            let m = try await kk("/admin/config", query: [
                "key": Config.testConfigKey, "teamId": Config.teamId,
                "bundleId": Config.bundleId, "environment": "sandbox",
            ])
            let keys = (m.obj("manifest") ?? [:]).keys
            XCTAssertFalse(keys.contains("../../../etc/passwd"),
                           "Path traversal version must not be stored verbatim")
            // Cleanup whatever was stored
            try await deleteConfig()
        } else {
            XCTAssertEqual(r.status, 400,
                           "Invalid version pattern should return 400, got \(r.status)")
        }
        // Either way, server must not 500
        XCTAssertNotEqual(r.status, 500, "Server must not 500 on invalid version input")
    }

    func testBillingWithBadAuthReturns401() async throws {
        let r = try await kk("/admin/billing",
                             auth: "kk_prod_notavalidkey00000000000000000000000",
                             query: ["teamId": Config.teamId, "bundleId": Config.bundleId])
        XCTAssertEqual(r.status, 401, "Billing with invalid key should be 401, got \(r.status)")
    }

    func testUserDataEndpointsRequireAuth() async throws {
        let userId = Config.testUserId

        let get = try await kk("/admin/users/\(userId)/data", auth: nil)
        XCTAssertEqual(get.status, 401,
                       "User data GET without auth must be 401, got \(get.status)")

        let put = try await kk("/admin/users/\(userId)/data", method: "PUT",
                                auth: nil, body: ["test": "value"])
        XCTAssertEqual(put.status, 401,
                       "User data PUT without auth must be 401, got \(put.status)")

        let del = try await kk("/admin/users/\(userId)/data", method: "DELETE", auth: nil)
        XCTAssertEqual(del.status, 401,
                       "User data DELETE without auth must be 401, got \(del.status)")
    }

    func testKillSwitchRequiresAuth() async throws {
        let r = try await kk("/admin/kill-switch", method: "POST", auth: nil, body: [
            "versions": ["*"], "enabled": true, "key": Config.testConfigKey,
        ])
        XCTAssertEqual(r.status, 401,
                       "Kill switch without auth must be 401, got \(r.status)")
    }

    func testEmergencyRevokeRequiresAuth() async throws {
        let r = try await kk("/admin/emergency-revoke", method: "POST", auth: nil, body: [
            "version": "*", "key": Config.testConfigKey, "force_refresh_ttl": 60,
        ])
        XCTAssertEqual(r.status, 401,
                       "Emergency revoke without auth must be 401, got \(r.status)")
    }

    func testPushEndpointsRequireAuth() async throws {
        let broadcast = try await kk("/push/broadcast", method: "POST", auth: nil, body: [
            "teamId": Config.teamId, "bundleId": Config.bundleId,
            "title": "Test", "body": "Test",
        ])
        XCTAssertEqual(broadcast.status, 401,
                       "Push broadcast without auth must be 401, got \(broadcast.status)")

        let send = try await kk("/push/send", method: "POST", auth: nil, body: [
            "teamId": Config.teamId, "bundleId": Config.bundleId,
            "to": Config.testUserId, "title": "Test",
        ])
        XCTAssertEqual(send.status, 401,
                       "Push send without auth must be 401, got \(send.status)")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MARK: Zero-Knowledge — Crypto unit tests (no network required)
    // ─────────────────────────────────────────────────────────────────────────

    func testZKEncryptProducesOutput() {
        let data = Data("hello world".utf8)
        XCTAssertNotNil(ZKHelper.encrypt(data, password: "testpass"),
                        "encrypt must return non-nil for valid input")
    }

    func testZKEncryptedLengthIsNoncePlusCiphertextPlusTag() {
        let plaintext = Data("hello".utf8)  // 5 bytes
        let enc = ZKHelper.encrypt(plaintext, password: "pass")!
        // 12-byte nonce + 5-byte ciphertext + 16-byte GCM tag = 33
        XCTAssertEqual(enc.count, 12 + plaintext.count + 16,
                       "encrypted length must be nonce(12) + plaintext + tag(16)")
    }

    func testZKEncryptThenDecryptRoundTrip() {
        let original = Data(#"{"stripe":"sk_live_abc","openai":"sk-xyz"}"#.utf8)
        let password = "vault_password_123"
        let enc = ZKHelper.encrypt(original, password: password)!
        let dec = ZKHelper.decrypt(enc, password: password)!
        XCTAssertEqual(dec, original, "decrypted bytes must match original plaintext")
    }

    func testZKJsonRoundTrip() {
        let payload: [String: Any] = [
            "stripe": "sk_live_abc123",
            "openai": "sk-proj-xyz",
            "feature_flags": ["new_checkout": true, "max_items": 50],
        ]
        let password = "my_vault_key"
        let b64 = ZKHelper.encryptJson(payload, password: password)!
        let decoded = ZKHelper.decryptJson(b64, password: password)!

        XCTAssertEqual(decoded["stripe"] as? String, "sk_live_abc123")
        XCTAssertEqual(decoded["openai"] as? String, "sk-proj-xyz")
        let flags = decoded["feature_flags"] as? [String: Any]
        XCTAssertEqual(flags?["new_checkout"] as? Bool, true)
        XCTAssertEqual(flags?["max_items"] as? Int, 50)
    }

    func testZKEncryptProducesUniqueNoncesEachTime() {
        let data = Data("same plaintext".utf8)
        let enc1 = ZKHelper.encrypt(data, password: "pass")!
        let enc2 = ZKHelper.encrypt(data, password: "pass")!
        // Nonces are the first 12 bytes — must differ (random per call)
        XCTAssertNotEqual(enc1.prefix(12), enc2.prefix(12),
                          "each encryption must use a unique random nonce")
        // Full ciphertext must also differ
        XCTAssertNotEqual(enc1, enc2,
                          "two encryptions of the same plaintext must produce different output")
    }

    func testZKDecryptWithWrongPasswordReturnsNil() {
        let enc = ZKHelper.encrypt(Data("secret".utf8), password: "correct_password")!
        let result = ZKHelper.decrypt(enc, password: "wrong_password")
        XCTAssertNil(result, "decryption with wrong password must return nil")
    }

    func testZKDecryptWithBitFlipInCiphertextReturnsNil() {
        var enc = ZKHelper.encrypt(Data("tamper test".utf8), password: "pass")!
        // Flip a bit in the ciphertext (byte 13 — first byte after the 12-byte nonce)
        enc[13] ^= 0xFF
        XCTAssertNil(ZKHelper.decrypt(enc, password: "pass"),
                     "GCM auth tag must reject tampered ciphertext")
    }

    func testZKDecryptWithBitFlipInTagReturnsNil() {
        var enc = ZKHelper.encrypt(Data("tamper test".utf8), password: "pass")!
        // Flip the last byte (part of the 16-byte tag)
        enc[enc.count - 1] ^= 0xFF
        XCTAssertNil(ZKHelper.decrypt(enc, password: "pass"),
                     "GCM auth tag must reject tampered tag")
    }

    func testZKDecryptWithBitFlipInNonceReturnsNil() {
        var enc = ZKHelper.encrypt(Data("tamper test".utf8), password: "pass")!
        // Flip a bit in the nonce (first 12 bytes)
        enc[0] ^= 0xFF
        XCTAssertNil(ZKHelper.decrypt(enc, password: "pass"),
                     "GCM auth tag must reject modified nonce")
    }

    func testZKDecryptTooShortDataReturnsNil() {
        // 28 bytes is the minimum (12 nonce + 0 plaintext + 16 tag)
        // Anything shorter must be rejected before attempting decryption
        let tooShort = Data(repeating: 0, count: 27)
        XCTAssertNil(ZKHelper.decrypt(tooShort, password: "pass"),
                     "data shorter than 28 bytes must return nil")
    }

    func testZKDecryptEmptyDataReturnsNil() {
        XCTAssertNil(ZKHelper.decrypt(Data(), password: "pass"),
                     "empty data must return nil")
    }

    func testZKKeyDerivationIsDeterministic() {
        let k1 = ZKHelper.deriveKey("my_vault_pass")
        let k2 = ZKHelper.deriveKey("my_vault_pass")
        // SymmetricKey doesn't expose rawBytes directly — compare via a known encryption
        let enc1 = ZKHelper.encrypt(Data("test".utf8), password: "my_vault_pass")!
        // k1 and k2 are the same key, so we can decrypt with the same password
        XCTAssertNotNil(ZKHelper.decrypt(enc1, password: "my_vault_pass"),
                        "key derivation must be deterministic — same password, same key")
    }

    func testZKDifferentPasswordsProduceDifferentKeys() {
        let enc = ZKHelper.encrypt(Data("test".utf8), password: "password_A")!
        XCTAssertNil(ZKHelper.decrypt(enc, password: "password_B"),
                     "different passwords must produce different keys")
    }

    func testZKUnicodePayloadRoundTrip() {
        let payload: [String: Any] = ["greeting": "こんにちは", "emoji": "🔑", "arabic": "مرحبا"]
        let b64 = ZKHelper.encryptJson(payload, password: "unicode_test")!
        let decoded = ZKHelper.decryptJson(b64, password: "unicode_test")!
        XCTAssertEqual(decoded["greeting"] as? String, "こんにちは")
        XCTAssertEqual(decoded["emoji"]    as? String, "🔑")
        XCTAssertEqual(decoded["arabic"]   as? String, "مرحبا")
    }

    func testZKLargePayloadRoundTrip() {
        // 10,000-entry dictionary — exercises multi-block AES-GCM
        var large: [String: Any] = [:]
        for i in 0..<10_000 { large["key_\(i)"] = "value_\(i)" }
        let b64 = ZKHelper.encryptJson(large, password: "large_payload_pass")!
        let decoded = ZKHelper.decryptJson(b64, password: "large_payload_pass")!
        XCTAssertEqual(decoded.count, 10_000, "all 10,000 keys must survive round-trip")
        XCTAssertEqual(decoded["key_9999"] as? String, "value_9999")
    }

    func testZKVaultKeyDerivedComponentsAreDeterministic() {
        // Same components must always produce the same key
        let pass1 = ["com.myapp", "247", "k8Xm"].joined(separator: "\u{001F}")
        let pass2 = ["com.myapp", "247", "k8Xm"].joined(separator: "\u{001F}")
        XCTAssertEqual(pass1, pass2, "derived vault key must be deterministic")

        let enc = ZKHelper.encrypt(Data("test".utf8), password: pass1)!
        XCTAssertNotNil(ZKHelper.decrypt(enc, password: pass2),
                        "derived key must decrypt what it encrypted")
    }

    func testZKVaultKeyComponentSeparatorPreventsCollisions() {
        // ["a", "bc"] and ["ab", "c"] must produce different keys
        let pass1 = ["a",  "bc"].joined(separator: "\u{001F}")
        let pass2 = ["ab", "c" ].joined(separator: "\u{001F}")
        XCTAssertNotEqual(pass1, pass2,
                          "unit-separator must prevent component-boundary collisions")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MARK: Zero-Knowledge — Management API (upload + manifest)
    // ─────────────────────────────────────────────────────────────────────────

    func testZKUploadedConfigAppearsAsOpaqueStringInManifest() async throws {
        let password = "test_vault_pass_\(Int(Date().timeIntervalSince1970))"
        let b64 = ZKHelper.encryptJson(["stripe": "sk_live_zk_test"], password: password)!

        let up = try await kk("/admin/config/upload", method: "POST", body: [
            "key": Config.testConfigKey, "version": "zk_test",
            "config": b64,   // string, not object — ZK upload
            "environment": "sandbox",
        ])
        XCTAssertTrue(up.ok, "ZK upload failed (HTTP \(up.status)): \(up.raw)")

        let m = try await kk("/admin/config", query: [
            "key": Config.testConfigKey, "teamId": Config.teamId,
            "bundleId": Config.bundleId, "environment": "sandbox",
        ])
        XCTAssertTrue(m.ok, "Manifest fetch failed: \(m.raw)")

        // The manifest entry must be a String (opaque ciphertext), not a parsed object
        let entry = m.obj("manifest")?["zk_test"]
        XCTAssertNotNil(entry, "zk_test version must appear in manifest")
        XCTAssertTrue(entry is String,
                      "ZK config must be stored as an opaque string, not a JSON object (got \(type(of: entry)))")
        XCTAssertNil(entry as? [String: Any],
                     "ZK config must NOT be unwrapped into a dictionary")

        try await deleteConfig(version: "zk_test")
    }

    func testZKBase64StringRoundTripsVerbatim() async throws {
        let password = "verbatim_test"
        let b64 = ZKHelper.encryptJson(["key": "value"], password: password)!

        _ = try await kk("/admin/config/upload", method: "POST", body: [
            "key": Config.testConfigKey, "version": "zk_verbatim",
            "config": b64, "environment": "sandbox",
        ])

        let m = try await kk("/admin/config", query: [
            "key": Config.testConfigKey, "teamId": Config.teamId,
            "bundleId": Config.bundleId, "environment": "sandbox",
        ])
        let stored = m.obj("manifest")?["zk_verbatim"] as? String
        XCTAssertEqual(stored, b64,
                       "stored base64 must be byte-for-byte identical to what was uploaded")

        // Stored string must be decryptable with the original password
        let decoded = stored.flatMap { ZKHelper.decryptJson($0, password: password) }
        XCTAssertEqual(decoded?["key"] as? String, "value",
                       "ciphertext retrieved from server must decrypt to original plaintext")

        try await deleteConfig(version: "zk_verbatim")
    }

    func testZKAndStandardConfigsForSameKeyAreIndependent() async throws {
        // Upload a standard config and a ZK config under different version patterns
        // for the same key — they must not interfere with each other
        let stdPayload: [String: Any] = ["mode": "standard", "visible": true]
        let zkPassword = "isolation_test_pass"
        let zkPayload:  [String: Any] = ["mode": "zk",       "secret": "sk_live_isolated"]
        let zkB64 = ZKHelper.encryptJson(zkPayload, password: zkPassword)!

        _ = try await kk("/admin/config/upload", method: "POST", body: [
            "key": Config.testConfigKey, "version": "std_ver",
            "config": stdPayload, "environment": "sandbox",
        ])
        _ = try await kk("/admin/config/upload", method: "POST", body: [
            "key": Config.testConfigKey, "version": "zk_ver",
            "config": zkB64, "environment": "sandbox",
        ])

        let m = try await kk("/admin/config", query: [
            "key": Config.testConfigKey, "teamId": Config.teamId,
            "bundleId": Config.bundleId, "environment": "sandbox",
        ])
        let manifest = m.obj("manifest") ?? [:]

        // Standard entry must be a dict
        XCTAssertTrue(manifest["std_ver"] is [String: Any],
                      "Standard config entry must be a dictionary")

        // ZK entry must be an opaque string
        XCTAssertTrue(manifest["zk_ver"] is String,
                      "ZK config entry must be an opaque string")

        // Decrypting the ZK entry with wrong password must fail
        if let zkStored = manifest["zk_ver"] as? String {
            XCTAssertNil(ZKHelper.decryptJson(zkStored, password: "wrong_password"),
                         "ZK ciphertext must not decrypt with a different password")
            let correct = ZKHelper.decryptJson(zkStored, password: zkPassword)
            XCTAssertEqual(correct?["secret"] as? String, "sk_live_isolated",
                           "ZK ciphertext must decrypt to original payload with correct password")
        }

        try await deleteConfig(version: "std_ver")
        try await deleteConfig(version: "zk_ver")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MARK: Delivery API  (requires devAuthEnabled = true)
    // ─────────────────────────────────────────────────────────────────────────

    func testDeliveryFetchesConfigContent() async throws {
        try XCTSkipUnless(Config.devAuthEnabled,
            "Set Config.devAuthEnabled = true (and ALLOW_DEV_TOKENS=true on server) to run delivery tests")

        // Seed a known config
        _ = try await kk("/admin/config/upload", method: "POST", body: [
            "key": "default", "version": "*",
            "config": ["delivery_test": "pass", "value": 99], "environment": "sandbox",
        ])

        let devAuth = "\(Config.teamId).\(Config.bundleId)"
        let fetch = try await kk("/v1/config",
                                  query: ["version": "1.0.0"],
                                  headers: ["X-Dev-Auth": devAuth, "X-Environment": "sandbox"])

        XCTAssertTrue(fetch.ok, "Delivery fetch failed (HTTP \(fetch.status)): \(fetch.raw)")
        let config = fetch.obj("config")
        XCTAssertEqual(config?["delivery_test"] as? String, "pass", "Config content mismatch")
        XCTAssertEqual(config?["value"] as? Int, 99, "Config value mismatch")
        XCTAssertNotNil(fetch.str("matchedPattern"), "Response should include matchedPattern")

        try await deleteConfig(key: "default", version: "*")
    }

    func testDeliveryVersionPatternPrecedence() async throws {
        try XCTSkipUnless(Config.devAuthEnabled,
            "Set Config.devAuthEnabled = true (and ALLOW_DEV_TOKENS=true on server) to run delivery tests")

        // Seed wildcard and major-wildcard
        _ = try await kk("/admin/config/upload", method: "POST", body: [
            "key": "default", "version": "*",
            "config": ["tier": "fallback"], "environment": "sandbox",
        ])
        _ = try await kk("/admin/config/upload", method: "POST", body: [
            "key": "default", "version": "2.*",
            "config": ["tier": "v2"], "environment": "sandbox",
        ])

        let devAuth = "\(Config.teamId).\(Config.bundleId)"

        // 2.3.1 → should match "2.*" (more specific wins)
        let v2 = try await kk("/v1/config",
                               query: ["version": "2.3.1"],
                               headers: ["X-Dev-Auth": devAuth, "X-Environment": "sandbox"])
        XCTAssertEqual((v2.obj("config") ?? [:])["tier"] as? String, "v2",
                       "2.3.1 should match 2.*")
        XCTAssertEqual(v2.str("matchedPattern"), "2.*")

        // 3.0.0 → should fall through to "*"
        let v3 = try await kk("/v1/config",
                               query: ["version": "3.0.0"],
                               headers: ["X-Dev-Auth": devAuth, "X-Environment": "sandbox"])
        XCTAssertEqual((v3.obj("config") ?? [:])["tier"] as? String, "fallback",
                       "3.0.0 should match * fallback")
        XCTAssertEqual(v3.str("matchedPattern"), "*")

        for v in ["*", "2.*"] { try await deleteConfig(key: "default", version: v) }
    }

    func testDeliveryWithoutAuthReturns401() async throws {
        try XCTSkipUnless(Config.devAuthEnabled,
            "Set Config.devAuthEnabled = true (and ALLOW_DEV_TOKENS=true on server) to run delivery tests")

        let r = try await kk("/v1/config", auth: nil, query: ["version": "1.0.0"])
        XCTAssertEqual(r.status, 401, "Delivery without auth should return 401, got \(r.status)")
    }

    func testDeliveryWithBadDevAuthReturns401() async throws {
        try XCTSkipUnless(Config.devAuthEnabled,
            "Set Config.devAuthEnabled = true (and ALLOW_DEV_TOKENS=true on server) to run delivery tests")

        // Malformed dev auth (not TEAMID.BUNDLEID format)
        let r = try await kk("/v1/config",
                              auth: nil,
                              query: ["version": "1.0.0"],
                              headers: ["X-Dev-Auth": "not-a-valid-format"])
        XCTAssertTrue(r.status == 401 || r.status == 403,
                      "Malformed dev auth should be 401/403, got \(r.status)")
    }

    func testDeliveryKillSwitchBlocksConfigFetch() async throws {
        try XCTSkipUnless(Config.devAuthEnabled,
            "Set Config.devAuthEnabled = true (and ALLOW_DEV_TOKENS=true on server) to run delivery tests")

        let devAuth = "\(Config.teamId).\(Config.bundleId)"

        _ = try await kk("/admin/config/upload", method: "POST", body: [
            "key": "default", "version": "*",
            "config": ["kill_switch_test": true], "environment": "sandbox",
        ])

        let kill = try await kk("/admin/kill-switch", method: "POST", body: [
            "versions": ["*"], "enabled": true, "key": "default",
        ])
        XCTAssertTrue(kill.ok, "Kill switch enable failed: \(kill.raw)")

        // Delivery must now be blocked
        let blocked = try await kk("/v1/config",
                                    query: ["version": "1.0.0"],
                                    headers: ["X-Dev-Auth": devAuth, "X-Environment": "sandbox"])
        XCTAssertFalse(blocked.ok,
                       "Config delivery should be blocked by kill switch (HTTP \(blocked.status))")
        XCTAssertTrue(blocked.status == 403 || blocked.status == 404 || blocked.status == 410,
                      "Kill switch should return 403/404/410, got \(blocked.status)")

        // Re-enable
        _ = try await kk("/admin/kill-switch", method: "POST", body: [
            "versions": ["*"], "enabled": false, "key": "default",
        ])

        // Delivery must work again
        let unblocked = try await kk("/v1/config",
                                      query: ["version": "1.0.0"],
                                      headers: ["X-Dev-Auth": devAuth, "X-Environment": "sandbox"])
        XCTAssertTrue(unblocked.ok,
                      "Config fetch should succeed after kill switch disabled (HTTP \(unblocked.status))")

        try await deleteConfig(key: "default", version: "*")
    }

    func testDeliveryBlobEndpointForUnknownKeyIs404() async throws {
        try XCTSkipUnless(Config.devAuthEnabled,
            "Set Config.devAuthEnabled = true (and ALLOW_DEV_TOKENS=true on server) to run delivery tests")

        let devAuth = "\(Config.teamId).\(Config.bundleId)"
        let r = try await kk("/v1/blob/xctest_nonexistent_blob_xyz_\(Int(Date().timeIntervalSince1970))",
                              headers: ["X-Dev-Auth": devAuth])
        XCTAssertNotEqual(r.status, 500, "Server must not 500 on nonexistent blob key")
        XCTAssertTrue(r.status == 404 || r.status == 400,
                      "Unknown blob key should return 404/400, got \(r.status)")
    }

    func testDeliveryExactVersionBeatsWildcard() async throws {
        try XCTSkipUnless(Config.devAuthEnabled,
            "Set Config.devAuthEnabled = true (and ALLOW_DEV_TOKENS=true on server) to run delivery tests")

        let devAuth = "\(Config.teamId).\(Config.bundleId)"

        for (v, label) in [("*", "fallback"), ("1.*", "major"), ("1.2.3", "exact")] {
            _ = try await kk("/admin/config/upload", method: "POST", body: [
                "key": "default", "version": v,
                "config": ["tier": label], "environment": "sandbox",
            ])
        }

        // 1.2.3 must match the exact pattern over 1.* and *
        let exactFetch = try await kk("/v1/config",
                                       query: ["version": "1.2.3"],
                                       headers: ["X-Dev-Auth": devAuth, "X-Environment": "sandbox"])
        XCTAssertTrue(exactFetch.ok, "Exact version fetch failed: \(exactFetch.raw)")
        XCTAssertEqual((exactFetch.obj("config") ?? [:])["tier"] as? String, "exact",
                       "1.2.3 should match the exact pattern")
        XCTAssertEqual(exactFetch.str("matchedPattern"), "1.2.3")

        // 1.9.0 must match 1.* over *
        let majorFetch = try await kk("/v1/config",
                                       query: ["version": "1.9.0"],
                                       headers: ["X-Dev-Auth": devAuth, "X-Environment": "sandbox"])
        XCTAssertTrue(majorFetch.ok, "Major version fetch failed: \(majorFetch.raw)")
        XCTAssertEqual((majorFetch.obj("config") ?? [:])["tier"] as? String, "major",
                       "1.9.0 should match 1.*")
        XCTAssertEqual(majorFetch.str("matchedPattern"), "1.*")

        for v in ["*", "1.*", "1.2.3"] { try await deleteConfig(key: "default", version: v) }
    }

    func testDeliveryMissingVersionHandledGracefully() async throws {
        try XCTSkipUnless(Config.devAuthEnabled,
            "Set Config.devAuthEnabled = true (and ALLOW_DEV_TOKENS=true on server) to run delivery tests")

        let devAuth = "\(Config.teamId).\(Config.bundleId)"

        // No version query param — server may default to * (200) or require it (400).
        // What must not happen is a 500.
        let r = try await kk("/v1/config",
                              headers: ["X-Dev-Auth": devAuth, "X-Environment": "sandbox"])
        XCTAssertNotEqual(r.status, 500, "Server must not 500 when version param is absent")
        XCTAssertTrue(r.ok || r.status == 400,
                      "Missing version should yield 200 or 400, got \(r.status): \(r.raw)")
    }

    // ─────────────────────────────────────────────────────────────────────────
    // MARK: Zero-Knowledge — Delivery (requires devAuthEnabled = true)
    //
    // These tests verify the full ZK contract: the server returns opaque
    // ciphertext over the delivery API, and local decryption recovers the
    // original plaintext. A regression anywhere in the chain — wrong salt,
    // wrong info string, changed binary layout, broken base64 — fails here.
    // ─────────────────────────────────────────────────────────────────────────

    func testZKDeliveryReturnsOpaqueString() async throws {
        try XCTSkipUnless(Config.devAuthEnabled,
            "Set Config.devAuthEnabled = true (and ALLOW_DEV_TOKENS=true on server) to run delivery tests")

        let devAuth = "\(Config.teamId).\(Config.bundleId)"
        let password = "zk_delivery_test"
        let b64 = ZKHelper.encryptJson(["secret": "sk_live_zk_delivery"], password: password)!

        _ = try await kk("/admin/config/upload", method: "POST", body: [
            "key": "default", "version": "*",
            "config": b64, "environment": "sandbox",
        ])

        let delivery = try await kk("/v1/config",
                                     query: ["version": "1.0.0"],
                                     headers: ["X-Dev-Auth": devAuth, "X-Environment": "sandbox"])
        XCTAssertTrue(delivery.ok, "ZK delivery fetch failed (HTTP \(delivery.status)): \(delivery.raw)")

        // The delivery response must return the config as a String, not a parsed object
        let configField = delivery.raw["config"]
        XCTAssertNotNil(configField, "Response must include config field")
        XCTAssertTrue(configField is String,
                      "ZK config in delivery response must be an opaque string, not \(type(of: configField))")
        XCTAssertNil(configField as? [String: Any],
                     "Delivery must NOT unwrap ZK ciphertext into a dictionary")

        try await deleteConfig(key: "default", version: "*")
    }

    func testZKFullEndToEndRoundTrip() async throws {
        try XCTSkipUnless(Config.devAuthEnabled,
            "Set Config.devAuthEnabled = true (and ALLOW_DEV_TOKENS=true on server) to run delivery tests")

        let devAuth = "\(Config.teamId).\(Config.bundleId)"
        let password = "e2e_vault_key_\(Int(Date().timeIntervalSince1970))"
        let originalPayload: [String: Any] = [
            "stripe":  "sk_live_end_to_end",
            "openai":  "sk-proj-e2e-test",
            "version": 42,
        ]

        // Step 1: Encrypt locally (mirrors what the CLI does)
        let b64 = ZKHelper.encryptJson(originalPayload, password: password)!

        // Step 2: Upload ciphertext — server stores opaque blob
        let up = try await kk("/admin/config/upload", method: "POST", body: [
            "key": "default", "version": "*",
            "config": b64, "environment": "sandbox",
        ])
        XCTAssertTrue(up.ok, "ZK upload failed: \(up.raw)")

        // Step 3: Fetch via delivery API — server returns same opaque blob
        let delivery = try await kk("/v1/config",
                                     query: ["version": "2.0.0"],
                                     headers: ["X-Dev-Auth": devAuth, "X-Environment": "sandbox"])
        XCTAssertTrue(delivery.ok, "ZK delivery fetch failed: \(delivery.raw)")

        // Step 4: Decrypt locally (mirrors what KiskisClient does)
        guard let cipherB64 = delivery.raw["config"] as? String else {
            XCTFail("Delivery response missing string config field (got \(delivery.raw["config"] as Any))"); return
        }
        guard let decrypted = ZKHelper.decryptJson(cipherB64, password: password) else {
            XCTFail("Local decryption failed — ciphertext returned by server is not decryptable"); return
        }

        // Step 5: Verify every field matches the original
        XCTAssertEqual(decrypted["stripe"]  as? String, "sk_live_end_to_end",
                       "stripe key must survive ZK round-trip")
        XCTAssertEqual(decrypted["openai"]  as? String, "sk-proj-e2e-test",
                       "openai key must survive ZK round-trip")
        XCTAssertEqual(decrypted["version"] as? Int, 42,
                       "integer value must survive ZK round-trip")

        try await deleteConfig(key: "default", version: "*")
    }

    func testZKDeliveryWithWrongPasswordFailsDecryption() async throws {
        try XCTSkipUnless(Config.devAuthEnabled,
            "Set Config.devAuthEnabled = true (and ALLOW_DEV_TOKENS=true on server) to run delivery tests")

        let devAuth = "\(Config.teamId).\(Config.bundleId)"
        let correctPass = "correct_vault_pass"
        let b64 = ZKHelper.encryptJson(["secret": "real_value"], password: correctPass)!

        _ = try await kk("/admin/config/upload", method: "POST", body: [
            "key": "default", "version": "*",
            "config": b64, "environment": "sandbox",
        ])

        let delivery = try await kk("/v1/config",
                                     query: ["version": "1.0.0"],
                                     headers: ["X-Dev-Auth": devAuth, "X-Environment": "sandbox"])
        XCTAssertTrue(delivery.ok, "Delivery fetch failed: \(delivery.raw)")

        if let cipherB64 = delivery.raw["config"] as? String {
            // Wrong password must not produce any output
            XCTAssertNil(ZKHelper.decryptJson(cipherB64, password: "wrong_vault_pass"),
                         "Decryption with wrong password must return nil")
            // Correct password must succeed
            XCTAssertNotNil(ZKHelper.decryptJson(cipherB64, password: correctPass),
                            "Decryption with correct password must succeed")
        }

        try await deleteConfig(key: "default", version: "*")
    }

    func testZKServerNeverReceivesPlaintext() async throws {
        try XCTSkipUnless(Config.devAuthEnabled,
            "Set Config.devAuthEnabled = true (and ALLOW_DEV_TOKENS=true on server) to run delivery tests")

        // Verify that the server-side representation contains no recognizable plaintext.
        // This is the core ZK guarantee — even if the Kiskis backend is fully compromised,
        // the attacker gets only ciphertext.
        let devAuth = "\(Config.teamId).\(Config.bundleId)"
        let password = "plaintext_leak_test"
        let sentinel = "SENTINEL_VALUE_MUST_NOT_APPEAR_IN_STORAGE"
        let b64 = ZKHelper.encryptJson(["sentinel": sentinel], password: password)!

        _ = try await kk("/admin/config/upload", method: "POST", body: [
            "key": "default", "version": "*",
            "config": b64, "environment": "sandbox",
        ])

        // Fetch via management API (what a compromised server would return)
        let manifest = try await kk("/admin/config", query: [
            "key": "default", "teamId": Config.teamId,
            "bundleId": Config.bundleId, "environment": "sandbox",
        ])

        // Serialize the entire manifest response to a string and verify the sentinel is absent
        if let manifestData = try? JSONSerialization.data(withJSONObject: manifest.raw),
           let manifestStr = String(data: manifestData, encoding: .utf8) {
            XCTAssertFalse(manifestStr.contains(sentinel),
                           "Sentinel value must NOT appear in server-side manifest — ZK is broken")
        }

        // Also verify via delivery API
        let delivery = try await kk("/v1/config",
                                     query: ["version": "1.0.0"],
                                     headers: ["X-Dev-Auth": devAuth, "X-Environment": "sandbox"])
        if let deliveryData = try? JSONSerialization.data(withJSONObject: delivery.raw),
           let deliveryStr = String(data: deliveryData, encoding: .utf8) {
            XCTAssertFalse(deliveryStr.contains(sentinel),
                           "Sentinel value must NOT appear in delivery response — ZK is broken")
        }

        try await deleteConfig(key: "default", version: "*")
    }
}
