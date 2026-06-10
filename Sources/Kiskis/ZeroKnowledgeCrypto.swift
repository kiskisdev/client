import Foundation
import CryptoKit

/// Client-side encryption/decryption for Zero-Knowledge Mode.
/// Uses AES-256-GCM with a key derived from the vault password via HKDF.
enum ZeroKnowledgeCrypto {
    /// Derive a symmetric key from a password string.
    /// Uses HKDF (not PBKDF2) since the password is compiled into the app
    /// and doesn't need the slow iteration count of a user-typed password.
    private static func deriveKey(from password: String, salt: String) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: Data(password.utf8)),
            salt: Data(salt.utf8),
            info: Data("kiskis-zk-v1".utf8),
            outputByteCount: 32
        )
    }

    /// Decrypt data that was encrypted by the CLI's `--encrypt` flag.
    /// Expected format: nonce (12 bytes) || ciphertext || tag (16 bytes)
    static func decrypt(data: Data, key: String, teamId: String, bundleId: String) -> Data? {
        // Why: per-customer salt prevents the same vault password producing the same
        // encryption key for different apps. Breaking change from v1 (fixed salt).
        let symmetricKey = deriveKey(from: key, salt: "kiskis-zk-v2:\(teamId):\(bundleId)")

        guard data.count > 28 else { return nil } // 12 nonce + 16 tag minimum

        let nonce = data.prefix(12)
        let ciphertextAndTag = data.dropFirst(12)

        do {
            let sealedBox = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: nonce),
                ciphertext: ciphertextAndTag.dropLast(16),
                tag: ciphertextAndTag.suffix(16)
            )
            return try AES.GCM.open(sealedBox, using: symmetricKey)
        } catch {
            return nil
        }
    }

    /// Encrypt data locally (used by tests and the CLI).
    /// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
    static func encrypt(data: Data, key: String, teamId: String, bundleId: String) -> Data? {
        let symmetricKey = deriveKey(from: key, salt: "kiskis-zk-v2:\(teamId):\(bundleId)")

        do {
            let sealedBox = try AES.GCM.seal(data, using: symmetricKey)
            var result = Data()
            result.append(contentsOf: sealedBox.nonce)
            result.append(sealedBox.ciphertext)
            result.append(sealedBox.tag)
            return result
        } catch {
            return nil
        }
    }
}
