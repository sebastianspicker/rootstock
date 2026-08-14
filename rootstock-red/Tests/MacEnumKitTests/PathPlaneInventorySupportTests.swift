import XCTest
@testable import MacEnumKit

final class PathPlaneInventorySupportTests: XCTestCase {
    func testEmptyInventoryRetainsInitialHonestyNote() {
        let result = inventory()

        XCTAssertEqual(result.primaryPaths, [])
        XCTAssertEqual(result.secondaryPaths, [])
        XCTAssertEqual(result.tertiaryPaths, [])
        XCTAssertFalse(result.surfacePresent)
        XCTAssertEqual(result.notes, ["honesty note"])
    }

    func testDuplicatePathsAreSortedAndReportedOncePerBucket() {
        let result = inventory(
            primary: ["/a/second", "/a/first", "/a/second"],
            secondary: ["/b/only", "/b/only"],
            present: ["/a/first", "/a/second", "/b/only"]
        )

        XCTAssertEqual(result.primaryPaths, ["/a/first", "/a/second"])
        XCTAssertEqual(result.secondaryPaths, ["/b/only"])
        XCTAssertEqual(result.notes, [
            "honesty note",
            "a: /a/first",
            "a: /a/second",
            "b: /b/only",
        ])
    }

    func testMixedBucketsPreserveMembershipAndNoteOrder() {
        let result = inventory(
            primary: ["/a/present", "/a/absent"],
            secondary: ["/b/present"],
            tertiary: ["/c/second", "/c/first"],
            present: ["/a/present", "/b/present", "/c/first", "/c/second"]
        )

        XCTAssertEqual(result.primaryPaths, ["/a/present"])
        XCTAssertEqual(result.secondaryPaths, ["/b/present"])
        XCTAssertEqual(result.tertiaryPaths, ["/c/first", "/c/second"])
        XCTAssertEqual(result.notes, [
            "honesty note",
            "a: /a/present",
            "b: /b/present",
            "c: /c/first",
            "c: /c/second",
        ])
    }

    func testSurfaceThresholdBoundaries() {
        XCTAssertFalse(inventory().surfacePresent)
        XCTAssertTrue(inventory(primary: ["/a"], present: ["/a"]).surfacePresent)
        XCTAssertTrue(inventory(secondary: ["/b"], present: ["/b"]).surfacePresent)
        XCTAssertFalse(inventory(tertiary: ["/c/one"], present: ["/c/one"]).surfacePresent)
        XCTAssertTrue(
            inventory(
                tertiary: ["/c/two", "/c/one"],
                present: ["/c/one", "/c/two"]
            ).surfacePresent
        )
    }

    private func inventory(
        primary: [String] = [],
        secondary: [String] = [],
        tertiary: [String] = [],
        present: Set<String> = []
    ) -> PathPlaneInventoryResult {
        PathPlaneInventorySupport.collect(
            spec: PathPlaneInventorySpec(
                primaryPaths: primary,
                secondaryPaths: secondary,
                tertiaryPaths: tertiary,
                initialHonestyNote: "honesty note"
            ),
            pathExists: { present.contains($0) }
        )
    }
}
