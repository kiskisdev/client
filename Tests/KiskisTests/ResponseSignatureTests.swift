import XCTest
@testable import Kiskis

/// The replay-window check on the server's response signature.
///
/// This used to be `abs(now - ts) < 300`, where `ts` comes straight from the X-Kiskis-Sig-Ts
/// header. `Int("-9223372036854775808")` parses cleanly, and both `now - Int.min` and
/// `abs(Int.min)` TRAP in Swift — a crash, not a thrown error — before the signature was ever
/// checked. One malformed header would have killed the host app on both the config and
/// /user/data paths. These vectors keep the untrusted value out of the arithmetic.
final class ResponseSignatureTests: XCTestCase {

    private let now = 1_700_000_000

    func testAcceptsTimestampsInsideTheWindow() {
        XCTAssertTrue(KiskisClient.timestampWithinWindow(now, now: now))
        XCTAssertTrue(KiskisClient.timestampWithinWindow(now - 299, now: now))
        XCTAssertTrue(KiskisClient.timestampWithinWindow(now + 299, now: now))
    }

    // Boundary behaviour matches the original `abs(now - ts) < 300` exactly — exclusive at ±300.
    func testRejectsTheBoundaryAndBeyond() {
        XCTAssertFalse(KiskisClient.timestampWithinWindow(now - 300, now: now))
        XCTAssertFalse(KiskisClient.timestampWithinWindow(now + 300, now: now))
        XCTAssertFalse(KiskisClient.timestampWithinWindow(now - 100_000, now: now))
        XCTAssertFalse(KiskisClient.timestampWithinWindow(now + 100_000, now: now))
    }

    // The crash. `Int.min` is reachable from the wire: Int("-9223372036854775808") succeeds.
    // Reject it — do not trap.
    func testExtremeTimestampsAreRejectedRatherThanTrapping() {
        XCTAssertFalse(KiskisClient.timestampWithinWindow(Int.min, now: now))
        XCTAssertFalse(KiskisClient.timestampWithinWindow(Int.max, now: now))
        XCTAssertFalse(KiskisClient.timestampWithinWindow(Int.min + 1, now: now))
        XCTAssertFalse(KiskisClient.timestampWithinWindow(Int.max - 1, now: now))
    }

    // The exact header value that reaches the parser, end to end.
    func testMalformedHeaderValueFromTheWire() {
        let headerValue = "-9223372036854775808"
        guard let ts = Int(headerValue) else {
            return XCTFail("Int(_:) parses this, which is precisely why it was reachable")
        }
        XCTAssertEqual(ts, Int.min)
        XCTAssertFalse(KiskisClient.timestampWithinWindow(ts, now: now))
    }

    // A zero/garbage timestamp (e.g. a header of "0", or a server bug) is out of window, not a crash.
    func testZeroTimestampIsRejected() {
        XCTAssertFalse(KiskisClient.timestampWithinWindow(0, now: now))
    }
}
