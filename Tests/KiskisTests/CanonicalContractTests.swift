import XCTest
import Foundation
@testable import Kiskis

// CLIENT/SERVER CONTRACT.
// The Secure Enclave signs the string produced by KiskisClient.canonicalClientData(...).
// The server rebuilds the identical string in buildCanonicalClientData() (delivery/index.ts).
// If they drift, EVERY assertion fails signature verification — this is exactly what broke
// in SDK 0.1.0, which signed "method:path:query:bodyHash" without teamId + ts.
//
// These golden vectors are duplicated verbatim in the server suite
// (infra/test/canonical-contract.test.ts). Both sides MUST produce these exact strings.
// The first vector is a real captured request whose assertion actually verified server-side.
final class CanonicalContractTests: XCTestCase {

    func testConfigGetGoldenVector() {
        let s = KiskisClient.canonicalClientData(
            method: "GET",
            path: "/config",
            queryItems: [URLQueryItem(name: "key", value: "default"),
                         URLQueryItem(name: "version", value: "1.0")],
            body: nil,
            teamId: "37D3WYGPDW",
            ts: 1783211675
        )
        XCTAssertEqual(s, "GET:/config:key=default&version=1.0::37D3WYGPDW:1783211675")
    }

    func testQueryParamsAreSortedByName() {
        // Supplied version-before-key; must still sort to key&version.
        let s = KiskisClient.canonicalClientData(
            method: "GET",
            path: "/config",
            queryItems: [URLQueryItem(name: "version", value: "2.1.3"),
                         URLQueryItem(name: "key", value: "flags")],
            body: nil,
            teamId: "ABCD1234EF",
            ts: 1000000000
        )
        XCTAssertEqual(s, "GET:/config:key=flags&version=2.1.3::ABCD1234EF:1000000000")
    }

    func testUserDataGetGoldenVector() {
        let s = KiskisClient.canonicalClientData(
            method: "GET",
            path: "/user/data",
            queryItems: [URLQueryItem(name: "user_id", value: "u_42")],
            body: nil,
            teamId: "ABCD1234EF",
            ts: 1
        )
        XCTAssertEqual(s, "GET:/user/data:user_id=u_42::ABCD1234EF:1")
    }
}
