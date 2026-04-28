import XCTest
@testable import Kiskis

final class KiskisTests: XCTestCase {
    func testZeroKnowledgeRoundTrip() throws {
        let plaintext = Data("{\"stripe_key\":\"sk_test_123\"}".utf8)
        let password = "MyVaultKey"

        let encrypted = ZeroKnowledgeCrypto.encrypt(data: plaintext, key: password)
        XCTAssertNotNil(encrypted, "Encryption should succeed")
        XCTAssertNotEqual(encrypted, plaintext, "Encrypted data should differ from plaintext")

        let decrypted = ZeroKnowledgeCrypto.decrypt(data: encrypted!, key: password)
        XCTAssertNotNil(decrypted, "Decryption should succeed")
        XCTAssertEqual(decrypted, plaintext, "Decrypted data should match original")
    }

    func testZeroKnowledgeWrongKey() throws {
        let plaintext = Data("{\"key\":\"value\"}".utf8)
        let encrypted = ZeroKnowledgeCrypto.encrypt(data: plaintext, key: "CorrectKey")
        XCTAssertNotNil(encrypted)

        let decrypted = ZeroKnowledgeCrypto.decrypt(data: encrypted!, key: "WrongKey")
        XCTAssertNil(decrypted, "Decryption with wrong key should fail")
    }

    func testZeroKnowledgeTamperedData() throws {
        let plaintext = Data("{\"key\":\"value\"}".utf8)
        var encrypted = ZeroKnowledgeCrypto.encrypt(data: plaintext, key: "MyKey")!

        // Tamper with ciphertext (byte 15, which is in the ciphertext portion)
        encrypted[15] ^= 0xFF

        let decrypted = ZeroKnowledgeCrypto.decrypt(data: encrypted, key: "MyKey")
        XCTAssertNil(decrypted, "Decryption of tampered data should fail (GCM auth tag)")
    }

    func testBlobReferenceScanning() throws {
        let config = KiskisConfig(
            data: [
                "api_keys": ["stripe": "sk_test"],
                "assets": [
                    "ml_model": [
                        "_type": "blob",
                        "key": "model-v3.bin",
                        "sha256": "abc123",
                        "size_bytes": 5242880,
                    ] as [String: Any],
                    "normal_value": "not a blob",
                ] as [String: Any],
            ],
            isCached: false,
            isStale: false,
            fetchedAt: Date()
        )

        let blobs = config.blobs()
        XCTAssertEqual(blobs.count, 1, "Should find exactly one blob reference")
        XCTAssertEqual(blobs[0].key, "model-v3.bin")
        XCTAssertEqual(blobs[0].sha256, "abc123")
        XCTAssertEqual(blobs[0].sizeBytes, 5242880)
        XCTAssertEqual(blobs[0].keyPath, "assets.ml_model")
    }

    func testConfigKeyPathAccess() throws {
        let config = KiskisConfig(
            data: [
                "api_keys": ["stripe": "sk_test_123"] as [String: Any],
                "features": ["dark_mode": true, "max_upload": 50] as [String: Any],
            ],
            isCached: false,
            isStale: false,
            fetchedAt: Date()
        )

        XCTAssertEqual(config.string("api_keys.stripe"), "sk_test_123")
        XCTAssertEqual(config.bool("features.dark_mode"), true)
        XCTAssertEqual(config.int("features.max_upload"), 50)
        XCTAssertNil(config.string("nonexistent.key"))
    }
}
