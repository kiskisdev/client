import Foundation
import CryptoKit

/// Client-side encryption/decryption for Zero-Knowledge Mode.
/// Uses AES-256-GCM with a key derived from the vault password via HKDF.
enum ZeroKnowledgeCrypto {
    /// Derive a symmetric key from a password string.
    /// Uses HKDF (not PBKDF2) since the password is compiled into the app
    /// and doesn't need the salt/iteration count of a user-typed password.
    private static func deriveKey(from password: String) -> SymmetricKey {
        let passwordData = Data(password.utf8)
        let salt = Data("kiskis-zk-salt".utf8) // Fixed salt — the password is the entropy source
        let keyMaterial = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: passwordData),
            salt: salt,
            info: Data("kiskis-zk-v1".utf8),
            outputByteCount: 32
        )
        return keyMaterial
    }

    /// Decrypt data that was encrypted by the CLI's `--encrypt` flag.
    /// Expected format: nonce (12 bytes) || ciphertext || tag (16 bytes)
    static func decrypt(data: Data, key: String) -> Data? {
        let symmetricKey = deriveKey(from: key)

        // The encrypted payload format: 12-byte nonce + ciphertext + 16-byte GCM tag
        guard data.count > 28 else { return nil } // 12 + 16 minimum

        let nonce = data.prefix(12)
        let ciphertextAndTag = data.dropFirst(12)

        do {
            let sealedBox = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: nonce),
                ciphertext: ciphertextAndTag.dropLast(16),
                tag: ciphertextAndTag.suffix(16)
            )
            let plaintext = try AES.GCM.open(sealedBox, using: symmetricKey)
            return plaintext
        } catch {
            return nil
        }
    }

    /// Encrypt data locally (used by tests and the CLI).
    /// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
    static func encrypt(data: Data, key: String) -> Data? {
        let symmetricKey = deriveKey(from: key)

        do {
            let sealedBox = try AES.GCM.seal(data, using: symmetricKey)
            // Combine nonce + ciphertext + tag
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
