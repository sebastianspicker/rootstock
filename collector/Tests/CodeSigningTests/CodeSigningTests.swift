import XCTest
@testable import CodeSigning
import Models
import TestSupport

final class CodeSigningTests: XCTestCase {

    let assessment = InjectionAssessment()

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

    func testAnalysisErrorDoesNotProduceInjectionMethods() {
        let info = makeInfo(signed: false, hardenedRuntime: false, lvFlag: false, analysisError: true)
        let result = assessment.assess(signingInfo: info, entitlements: [], isElectron: false)
        XCTAssertTrue(result.methods.isEmpty, "Unknown signing posture must not become injectable evidence")
    }

    // MARK: - CodeSigningDataSource enrichment tests

    func testEnrichmentPopulatesSignedField() throws {
        let safariPath = "/Applications/Safari.app"
        guard FileManager.default.fileExists(atPath: safariPath) else {
            throw XCTSkip("Safari.app not found")
        }

        var apps = [ApplicationTestFactory.make(
            name: "Safari",
            bundleId: "com.apple.Safari",
            path: safariPath,
            version: nil,
            options: .init(signing: Application.Signing(
                hardenedRuntime: false,
                libraryValidation: false,
                signed: false
            ))
        )]
        let source = CodeSigningDataSource()
        source.enrich(applications: &apps)

        XCTAssertEqual(apps[0].signed, true, "Safari should be signed after enrichment")
        XCTAssertEqual(apps[0].libraryValidation, true, "Safari should have library validation after enrichment")
    }

    func testEnrichmentFailureRecordsError() {
        var apps = [unanalyzableApplication()]
        let source = CodeSigningDataSource()
        let errors = source.enrich(applications: &apps)

        XCTAssertFalse(errors.isEmpty, "Should record error for unanalyzable app")
        XCTAssertTrue(apps[0].codeSigningAnalysisError, "Unanalyzable app should preserve analysis failure")
        XCTAssertNil(apps[0].signed, "Unanalyzable app signing state should be unknown")
        XCTAssertNil(apps[0].hardenedRuntime, "Unanalyzable hardened runtime state should be unknown")
        XCTAssertNil(apps[0].libraryValidation, "Unanalyzable library validation state should be unknown")
        XCTAssertTrue(apps[0].injectionMethods.isEmpty, "Unanalyzable app should not get injection methods")
        XCTAssertNil(apps[0].launchConstraintCategory, "Unanalyzable launch constraint should be unknown")
    }

    func testEnrichedReturnsCopyAndLeavesInputUntouched() {
        let apps = [unanalyzableApplication()]
        let source = CodeSigningDataSource()

        let (enrichedApps, errors) = source.enriched(applications: apps)

        XCTAssertFalse(errors.isEmpty, "Should record error for unanalyzable app")
        XCTAssertEqual(apps[0].signed, false, "Input application should not be mutated")
        XCTAssertFalse(apps[0].codeSigningAnalysisError, "Input application should not be mutated")
        XCTAssertNil(enrichedApps[0].signed, "Output signing state should be unknown after failed analysis")
        XCTAssertTrue(enrichedApps[0].codeSigningAnalysisError)
    }

    func testNotarizationInfrastructureFailureStaysUnknown() {
        let assessment = CodeSigningDataSource.notarizationStatus(
            from: .admissionTimedOut,
            appPath: "/Applications/Example.app"
        )

        XCTAssertNil(assessment.value)
        XCTAssertTrue(assessment.error?.message.contains("admission timed out") == true)
    }

    func testNotarizationExecutionTimeoutStaysUnknown() {
        let assessment = CodeSigningDataSource.notarizationStatus(
            from: .executionTimedOut(shellResult(timedOut: true)),
            appPath: "/Applications/Example.app"
        )

        XCTAssertNil(assessment.value)
        XCTAssertTrue(assessment.error?.message.contains("execution timed out") == true)
    }

    func testNotarizationNonzeroExitIsDefinitiveRejection() {
        let assessment = CodeSigningDataSource.notarizationStatus(
            from: .nonZeroExit(shellResult(status: 3, stderr: "rejected")),
            appPath: "/Applications/Example.app"
        )

        XCTAssertEqual(assessment.value, false)
        XCTAssertNil(assessment.error)
    }

    func testMissingEntitlementsSuppressesEntitlementDependentInjectionFacts() throws {
        let terminalPath = "/System/Applications/Utilities/Terminal.app"
        guard FileManager.default.fileExists(atPath: terminalPath) else {
            throw XCTSkip("Terminal.app not found")
        }
        var apps = [Application(
            identity: Application.Identity(
                name: "Terminal",
                bundleId: "com.apple.Terminal",
                path: terminalPath,
                version: nil
            ),
            flags: Application.Flags(isElectron: false, isSystem: false),
            signing: Application.Signing(),
            entitlementState: Application.EntitlementState(
                entitlementsAvailable: false,
                entitlementExtractionError: "codesign failed"
            )
        )]
        let source = CodeSigningDataSource()
        _ = source.enrich(applications: &apps)

        XCTAssertEqual(apps[0].signed, true)
        XCTAssertNil(apps[0].libraryValidation)
        XCTAssertFalse(apps[0].entitlementsAvailable)
        XCTAssertEqual(apps[0].entitlementExtractionError, "codesign failed")
        XCTAssertTrue(apps[0].injectionMethods.isEmpty)
    }

    // MARK: - Helpers

    private func makeInfo(
        signed: Bool, hardenedRuntime: Bool, lvFlag: Bool, isAdhoc: Bool = false,
        certificateChain: [CertificateDetail] = [], analysisError: Bool = false
    ) -> CodeSigningInfo {
        CodeSigningInfo(
            signed: signed, teamId: nil, signingIdentifier: nil,
            hardenedRuntime: hardenedRuntime, libraryValidationFlag: lvFlag,
            analysisError: analysisError, isAdhoc: isAdhoc, certificateChain: certificateChain
        )
    }

    private func unanalyzableApplication() -> Application {
        ApplicationTestFactory.make(
            name: "Fake",
            bundleId: "com.fake.app",
            path: "/nonexistent/Fake.app",
            version: nil,
            options: .init(signing: Application.Signing(
                hardenedRuntime: false,
                libraryValidation: false,
                signed: false
            ))
        )
    }

    private func shellResult(
        status: Int32 = 0,
        stderr: String = "",
        timedOut: Bool = false
    ) -> ShellResult {
        ShellResult(
            stdout: "",
            stderr: stderr,
            terminationStatus: status,
            timedOut: timedOut
        )
    }
}
