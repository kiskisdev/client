import XCTest
@testable import Kiskis

final class SharedClientTests: XCTestCase {
    override func setUp() {
        super.setUp()
        KiskisClient.shared = nil
    }

    // An app that uses only named keys (challenges/news/packs, no "default") must still get a
    // usable KiskisClient.shared, so its app-delegate `KiskisClient.shared?.setPushToken(...)`
    // forwards the APNs token instead of silently dropping it (the mdrop "exists=false" bug).
    func testSharedFallsBackToFirstNamedClient() {
        let client = KiskisClient(teamId: "TESTTEAM", bundleId: "com.test.shared",
                                  key: "challenges", autoRegisterPush: false, environment: .production)
        XCTAssertTrue(KiskisClient.shared === client, "first named client becomes shared")
    }

    // The "default" client is still preferred: it takes over shared even if a named client
    // was created first, and a later named client does NOT clobber it.
    func testDefaultClientIsPreferredAndNotClobbered() {
        let named = KiskisClient(teamId: "TESTTEAM", bundleId: "com.test.shared",
                                 key: "challenges", autoRegisterPush: false, environment: .production)
        XCTAssertTrue(KiskisClient.shared === named)

        let def = KiskisClient(teamId: "TESTTEAM", bundleId: "com.test.shared",
                               key: "default", autoRegisterPush: false, environment: .production)
        XCTAssertTrue(KiskisClient.shared === def, "the default client takes over shared")

        let later = KiskisClient(teamId: "TESTTEAM", bundleId: "com.test.shared",
                                 key: "news", autoRegisterPush: false, environment: .production)
        _ = later
        XCTAssertTrue(KiskisClient.shared === def, "a later named client must not clobber the default")
    }
}
