import Foundation
import Security

/// Thin wrapper around the iOS Keychain for secure string storage.
/// Uses kSecAttrAccessibleWhenUnlockedThisDeviceOnly — data does NOT
/// transfer to new devices via backup, which is correct for security tokens.
///
/// Write operations return the raw OSStatus so callers can decide severity.
/// The most important failure code for saves is errSecInteractionNotAllowed (-25308),
/// which means the device was locked at write time — an expected (though rare) outcome
/// for WhenUnlockedThisDeviceOnly items written from a background context.
enum KeychainHelper {
    /// Save a string to the Keychain, replacing any existing value for this key.
    /// Returns errSecSuccess on success; errSecInteractionNotAllowed if the device is
    /// locked; other non-zero codes for unexpected failures.
    @discardableResult
    static func save(key: String, value: String) -> OSStatus {
        guard let data = value.data(using: .utf8) else { return errSecParam }

        // Delete any existing item first — errSecItemNotFound is expected and harmless.
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        return SecItemAdd(addQuery as CFDictionary, nil)
    }

    static func load(key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess,
              let data = result as? Data,
              let string = String(data: data, encoding: .utf8) else {
            return nil
        }

        return string
    }

    /// Delete a Keychain item. Returns the raw OSStatus; errSecItemNotFound is not
    /// treated as an error by callers — absence is the desired post-condition.
    @discardableResult
    static func delete(key: String) -> OSStatus {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
        ]
        return SecItemDelete(query as CFDictionary)
    }
}
