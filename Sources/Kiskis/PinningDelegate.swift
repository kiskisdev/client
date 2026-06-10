import Foundation
import CryptoKit
import Security

/// URLSession delegate that enforces SPKI certificate pinning for api.kiskis.dev.
///
/// Why SPKI (Subject Public Key Info) over certificate pinning: certificate pins break
/// on every renewal even when the key pair is reused. SPKI pins survive cert rotation
/// as long as the public key stays the same — typically true for CA intermediates.
///
/// Why pin intermediates, not leaf: Cloudflare rotates leaf certs frequently.
/// Pinning an intermediate (or the root) survives those rotations without requiring
/// a forced SDK update. Include both the current intermediate and a backup so key
/// rotation can be rolled out before the old cert expires.
///
/// Obtaining SPKI hashes for api.kiskis.dev:
///   openssl s_client -connect api.kiskis.dev:443 -showcerts 2>/dev/null \
///     | awk '/BEGIN CERT/,/END CERT/' \
///     | csplit -f cert - '/END CERT/+1' '{*}' 2>/dev/null
///   for f in cert*; do
///     openssl x509 -in "$f" -pubkey -noout 2>/dev/null \
///       | openssl pkey -pubin -outform der \
///       | openssl dgst -sha256 -binary | base64
///   done
///
/// Update `pinnedSPKIHashes` with the intermediate CA hash(es) from the output above.
/// Include at least one backup hash so future key rotation can be deployed in advance.
final class PinningDelegate: NSObject, URLSessionDelegate {

    // MARK: - Pinned hashes

    // Why: pin the Cloudflare intermediate CA(s), not the leaf cert (which rotates
    // every ~90 days) and not the root alone (too broad — accepts any DigiCert-signed cert).
    // Replace these placeholders with real hashes from the openssl command above before
    // shipping. Require at least two entries (current + backup) so rotation is non-breaking.
    static let pinnedSPKIHashes: Set<Data> = {
        let placeholders: [String] = [
            // TODO: replace with actual Cloudflare intermediate SPKI SHA-256 (base64)
            // from running the openssl command above against api.kiskis.dev
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",  // primary intermediate
            "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",  // backup / rotation target
        ]
        return Set(placeholders.compactMap { Data(base64Encoded: $0) })
    }()

    // MARK: - URLSessionDelegate

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // Standard TLS validation first — pinning on top of, not instead of, chain validation.
        var cfError: CFError?
        guard SecTrustEvaluateWithError(serverTrust, &cfError) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // Walk every cert in the chain (leaf → intermediate → root).
        // A match anywhere in the chain is sufficient.
        let certCount = SecTrustGetCertificateCount(serverTrust)
        for i in 0..<certCount {
            guard let cert = SecTrustGetCertificateAtIndex(serverTrust, i),
                  let spkiHash = Self.spkiSHA256(for: cert) else { continue }
            if PinningDelegate.pinnedSPKIHashes.contains(spkiHash) {
                completionHandler(.useCredential, URLCredential(trust: serverTrust))
                return
            }
        }

        // No pin matched — reject. Fail closed.
        completionHandler(.cancelAuthenticationChallenge, nil)
    }

    // MARK: - SPKI extraction

    /// SHA-256 hash of the SubjectPublicKeyInfo DER bytes for an EC certificate key.
    /// Supports P-256 and P-384 — the key types used by Cloudflare's ECC intermediate CAs.
    /// Returns nil for unsupported key types (RSA, etc.); those certs are not pinnable
    /// by this implementation and will not produce a false match.
    private static func spkiSHA256(for certificate: SecCertificate) -> Data? {
        guard let publicKey = SecCertificateCopyKey(certificate) else { return nil }
        var cfError: Unmanaged<CFError>?
        guard let rawKeyData = SecKeyCopyExternalRepresentation(publicKey, &cfError) as Data? else { return nil }

        let attrs = SecKeyCopyAttributes(publicKey) as? [CFString: Any]
        let keyType = attrs?[kSecAttrKeyType] as? String
        let keySize = attrs?[kSecAttrKeySizeInBits] as? Int

        // Reconstruct the SPKI DER by prepending the ASN.1 AlgorithmIdentifier + BIT STRING
        // header for the specific key type. SecKeyCopyExternalRepresentation returns the raw
        // X9.62 uncompressed point (04 || x || y), not the full SPKI structure.
        let spkiHeader: [UInt8]
        if keyType == (kSecAttrKeyTypeEC as String) && keySize == 256 {
            // P-256: total SPKI = 26-byte header + 65-byte key = 91 bytes
            spkiHeader = [
                0x30, 0x59,                                     // SEQUENCE (89 bytes)
                0x30, 0x13,                                     // SEQUENCE (19 bytes) AlgorithmIdentifier
                0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,  // OID ecPublicKey
                0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,  // OID prime256v1
                0x03, 0x42, 0x00,                               // BIT STRING (66 bytes, 0 unused)
            ]
        } else if keyType == (kSecAttrKeyTypeEC as String) && keySize == 384 {
            // P-384: total SPKI = 23-byte header + 97-byte key = 120 bytes
            spkiHeader = [
                0x30, 0x76,
                0x30, 0x10,
                0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
                0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22,
                0x03, 0x62, 0x00,
            ]
        } else {
            return nil
        }

        var spki = Data(spkiHeader)
        spki.append(rawKeyData)
        return Data(SHA256.hash(data: spki))
    }
}
