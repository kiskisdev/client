import XCTest
@testable import Kiskis

/// Where a server-supplied blob key is allowed to land.
///
/// The key arrives in the config, so it is server-controlled, and `appendingPathComponent`
/// does not interpret away "..". Unchecked, "../../foo" resolves outside the blob directory —
/// turning a config value into an arbitrary-write primitive anywhere the app can write.
final class BlobDestinationTests: XCTestCase {

    private let blobDir = URL(fileURLWithPath: "/Users/x/Library/Caches/kiskis-blobs")

    func testOrdinaryKeyLandsInTheBlobDirectory() {
        let dest = KiskisClient.blobDestination(for: "model.bin", in: blobDir)
        XCTAssertEqual(dest?.path, "/Users/x/Library/Caches/kiskis-blobs/model.bin")
    }

    // Nested keys are legitimate, which is why this is a containment check and not a ban on "/".
    func testNestedKeyIsAllowed() {
        let dest = KiskisClient.blobDestination(for: "models/v2/model.bin", in: blobDir)
        XCTAssertEqual(dest?.path, "/Users/x/Library/Caches/kiskis-blobs/models/v2/model.bin")
    }

    // Interior traversal that still resolves inside is fine — it's the destination that matters.
    func testInteriorDotDotThatStaysInsideIsAllowed() {
        let dest = KiskisClient.blobDestination(for: "a/../b.bin", in: blobDir)
        XCTAssertEqual(dest?.path, "/Users/x/Library/Caches/kiskis-blobs/b.bin")
    }

    func testTraversalEscapingTheDirectoryIsRejected() {
        XCTAssertNil(KiskisClient.blobDestination(for: "../../../../evil.dylib", in: blobDir))
        XCTAssertNil(KiskisClient.blobDestination(for: "../../evil.bin", in: blobDir))
    }

    // The subtle one: a sibling directory whose name has the blob dir as a prefix. This only
    // fails if the containment check compares against blobDir + "/" rather than the bare path.
    func testPrefixSiblingDirectoryIsRejected() {
        XCTAssertNil(KiskisClient.blobDestination(for: "../kiskis-blobs-evil/x", in: blobDir))
    }

    // An absolute-looking key is treated as a relative component by appendingPathComponent, so it
    // stays contained. Asserted so the behaviour is pinned rather than assumed.
    func testAbsoluteLookingKeyStaysContained() {
        let dest = KiskisClient.blobDestination(for: "/etc/passwd", in: blobDir)
        XCTAssertEqual(dest?.path, "/Users/x/Library/Caches/kiskis-blobs/etc/passwd")
    }
}
