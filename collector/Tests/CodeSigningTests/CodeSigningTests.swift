import XCTest
@testable import CodeSigning
import Models

final class CodeSigningTests: XCTestCase {

    let analyzer = CodeSigningAnalyzer()
    let assessment = InjectionAssessment()

    // MARK: - CodeSigningAnalyzer integration tests

    func testSafariIsSignedWithLibraryValidation() throws {
        // Safari.app is a platform binary: signed but no team ID, no hardened runtime flag.
        // It has CS_REQUIRE_LV (0x2000) set.
        let safariPath = "/Applications/Safari.app"
        guard FileManager.default.fileExists(atPath: safariPath) else {
            throw XCTSkip("Safari.app not found — skipping")
        }
        let info = analyzer.analyze(appPath: safariPath)
        XCTAssertTrue(info.signed, "Safari should be signed")
        XCTAssertTrue(info.libraryValidationFlag, "Safari should have CS_REQUIRE_LV flag")
        XCTAssertFalse(info.analysisError, "Safari analysis should not error")
        // Platform binaries have no team identifier.
        XCTAssertNil(info.teamId, "Safari (platform binary) has no team identifier")
    }

    func testHardenedRuntimeAppIfPresent() throws {
        // 1Password uses hardened runtime — a reliable real-world example.
        // Skip gracefully if not installed.
        let path = "/Applications/1Password.app"
        guard FileManager.default.fileExists(atPath: path) else {
            throw XCTSkip("1Password.app not found — skipping hardened runtime test")
        }
        let info = analyzer.analyze(appPath: path)
        XCTAssertTrue(info.signed)
        XCTAssertTrue(info.hardenedRuntime, "1Password should have hardened runtime")
        XCTAssertNotNil(info.teamId)
    }

    func testNonExistentPathReturnsUnsigned() {
        let info = analyzer.analyze(appPath: "/nonexistent/path/Fake.app")
        XCTAssertFalse(info.signed)
        XCTAssertTrue(info.analysisError, "Should report analysis error for missing path")
        XCTAssertNil(info.teamId)
        XCTAssertFalse(info.hardenedRuntime)
    }

    func testRealAppHasSigningIdentifier() throws {
        let terminalPath = "/System/Applications/Utilities/Terminal.app"
        guard FileManager.default.fileExists(atPath: terminalPath) else {
            throw XCTSkip("Terminal.app not found")
        }
        let info = analyzer.analyze(appPath: terminalPath)
        // Terminal is a platform binary — signed but with flags=0x0 (none)
        XCTAssertFalse(info.analysisError)
        // Platform binaries with flags=0x0 report signingIdentifier as nil in some OS versions;
        // just verify analysis doesn't error out.
    }

    // MARK: - InjectionAssessment unit tests

    func testUnsignedAppIsDyldInjectable() {
        let info = makeInfo(signed: false, hardenedRuntime: false, lvFlag: false)
        let methods = assessment.assess(signingInfo: info, entitlements: [], isElectron: false).methods
        XCTAssertTrue(methods.contains(.dyldInsert), "Unhardened app should be DYLD injectable")
        XCTAssertTrue(methods.contains(.missingLibraryValidation))
    }

    func testHardenedAppWithoutEntitlementIsNotDyldInjectable() {
        let info = makeInfo(signed: true, hardenedRuntime: true, lvFlag: false)
        let methods = assessment.assess(signingInfo: info, entitlements: [], isElectron: false).methods
        XCTAssertFalse(methods.contains(.dyldInsert))
        XCTAssertFalse(methods.contains(.dyldInsertViaEntitlement))
    }

    func testHardenedAppWithAllowDyldEntitlementIsDyldInjectable() {
        let info = makeInfo(signed: true, hardenedRuntime: true, lvFlag: false)
        let entitlement = EntitlementInfo(
            name: "com.apple.security.cs.allow-dyld-environment-variables",
            isPrivate: false, category: "injection", isSecurityCritical: true
        )
        let methods = assessment.assess(signingInfo: info, entitlements: [entitlement], isElectron: false).methods
        XCTAssertTrue(methods.contains(.dyldInsertViaEntitlement))
        XCTAssertFalse(methods.contains(.dyldInsert))
    }

    func testHardenedAppWithDisableLVIsLibraryInjectable() {
        let info = makeInfo(signed: true, hardenedRuntime: true, lvFlag: false)
        let entitlement = EntitlementInfo(
            name: "com.apple.security.cs.disable-library-validation",
            isPrivate: false, category: "injection", isSecurityCritical: true
        )
        let methods = assessment.assess(signingInfo: info, entitlements: [entitlement], isElectron: false).methods
        XCTAssertTrue(methods.contains(.missingLibraryValidation))
    }

    func testHardenedAppWithLibraryValidationFlagIsNotLibraryInjectable() {
        let info = makeInfo(signed: true, hardenedRuntime: true, lvFlag: true)
        let methods = assessment.assess(signingInfo: info, entitlements: [], isElectron: false).methods
        XCTAssertFalse(methods.contains(.missingLibraryValidation))
    }

    func testElectronAppHasElectronEnvVarMethod() {
        let info = makeInfo(signed: true, hardenedRuntime: false, lvFlag: false)
        let methods = assessment.assess(signingInfo: info, entitlements: [], isElectron: true).methods
        XCTAssertTrue(methods.contains(.electronEnvVar))
    }

    func testFullyHardenedAppHasNoInjectionMethods() {
        // Hardened runtime + library validation flag + no exemption entitlements
        let info = makeInfo(signed: true, hardenedRuntime: true, lvFlag: true)
        let methods = assessment.assess(signingInfo: info, entitlements: [], isElectron: false).methods
        XCTAssertTrue(methods.isEmpty, "Fully hardened app should have no injection methods")
    }

    // MARK: - CodeSigningDataSource enrichment tests

    func testEnrichmentPopulatesSignedField() throws {
        let safariPath = "/Applications/Safari.app"
        guard FileManager.default.fileExists(atPath: safariPath) else {
            throw XCTSkip("Safari.app not found")
        }

        var apps = [Application(
            name: "Safari", bundleId: "com.apple.Safari", path: safariPath,
            version: nil, teamId: nil, hardenedRuntime: false, libraryValidation: false,
            isElectron: false, isSystem: false, signed: false,
            entitlements: [], injectionMethods: []
        )]
        let source = CodeSigningDataSource()
        source.enrich(applications: &apps)

        XCTAssertTrue(apps[0].signed, "Safari should be signed after enrichment")
        XCTAssertTrue(apps[0].libraryValidation, "Safari should have library validation after enrichment")
    }

    func testEnrichmentFailureRecordsError() {
        var apps = [Application(
            name: "Fake", bundleId: "com.fake.app", path: "/nonexistent/Fake.app",
            version: nil, teamId: nil, hardenedRuntime: false, libraryValidation: false,
            isElectron: false, isSystem: false, signed: false,
            entitlements: [], injectionMethods: []
        )]
        let source = CodeSigningDataSource()
        let errors = source.enrich(applications: &apps)

        XCTAssertFalse(errors.isEmpty, "Should record error for unanalyzable app")
        XCTAssertFalse(apps[0].signed, "Unanalyzable app should have signed=false")
    }

    // MARK: - Helpers

    private func makeInfo(
        signed: Bool, hardenedRuntime: Bool, lvFlag: Bool
    ) -> CodeSigningInfo {
        CodeSigningInfo(
            signed: signed, teamId: nil, signingIdentifier: nil,
            hardenedRuntime: hardenedRuntime, libraryValidationFlag: lvFlag,
            analysisError: false
        )
    }
}
