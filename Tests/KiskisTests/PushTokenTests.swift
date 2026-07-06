import XCTest
import Foundation
@testable import Kiskis

// setPushToken(_:) hex-encodes the raw APNs Data the same way the app used to do by hand
// (and the way the server stores it). A wrong encoding = an undeliverable device.
final class PushTokenTests: XCTestCase {
    func testHexEncoding() {
        let data = Data([0x00, 0x0f, 0xa1, 0xff, 0x10])
        XCTAssertEqual(KiskisClient.hexString(from: data), "000fa1ff10")
    }

    func testLowercaseAndZeroPadded() {
        // Each byte must be exactly two lowercase hex chars.
        let data = Data([0x01, 0x0a, 0xb0])
        XCTAssertEqual(KiskisClient.hexString(from: data), "010ab0")
    }

    func testEmptyToken() {
        XCTAssertEqual(KiskisClient.hexString(from: Data()), "")
    }
}
