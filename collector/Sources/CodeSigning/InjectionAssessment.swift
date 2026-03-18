import Models

/// Result of an injection assessment for a single app.
struct InjectionAssessmentResult {
    let methods: [InjectionMethod]
    let effectiveLibraryValidation: Bool
}

/// Determines which injection methods are applicable to an app,
/// based on its code signing state and entitlements.
struct InjectionAssessment {

    /// Entitlement keys checked during injection assessment.
    static let allowDyldEntitlement = "com.apple.security.cs.allow-dyld-environment-variables"
    static let disableLibraryValidationEntitlement = "com.apple.security.cs.disable-library-validation"

    /// Assess injection methods and effective library validation for the given app.
    func assess(
        signingInfo: CodeSigningInfo,
        entitlements: [EntitlementInfo],
        isElectron: Bool
    ) -> InjectionAssessmentResult {
        var methods: [InjectionMethod] = []
        let names = Set(entitlements.map(\.name))

        // DYLD_INSERT_LIBRARIES injection
        if !signingInfo.hardenedRuntime {
            methods.append(.dyldInsert)
        } else if names.contains(Self.allowDyldEntitlement) {
            methods.append(.dyldInsertViaEntitlement)
        }

        // Library validation: CS_REQUIRE_LV flag OR
        // (hardened runtime AND no disable-library-validation entitlement).
        let hasDisableLV = names.contains(Self.disableLibraryValidationEntitlement)
        let effectiveLV = signingInfo.libraryValidationFlag
            || (signingInfo.hardenedRuntime && !hasDisableLV)
        if !effectiveLV {
            methods.append(.missingLibraryValidation)
        }

        // Electron — injectable via ELECTRON_RUN_AS_NODE
        if isElectron {
            methods.append(.electronEnvVar)
        }

        return InjectionAssessmentResult(
            methods: methods,
            effectiveLibraryValidation: effectiveLV
        )
    }
}
