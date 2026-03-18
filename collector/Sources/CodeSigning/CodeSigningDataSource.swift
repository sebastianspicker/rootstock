import Foundation
import Models

/// Enriches Application objects with code signing metadata and injection assessment.
///
/// This is not a standalone DataSource — it enriches Application objects produced by
/// EntitlementDataSource, filling in team_id, hardened_runtime, library_validation,
/// signed, and injection_methods fields.
public struct CodeSigningDataSource {
    private let analyzer = CodeSigningAnalyzer()
    private let assessment = InjectionAssessment()

    public init() {}

    /// Enriches the given Application array in place with code signing metadata.
    ///
    /// For each app, runs Security.framework analysis and injection assessment.
    /// If analysis fails, `signed` is set to `false` and an error is recorded.
    ///
    /// - Returns: Per-app `CollectionError` entries for any analysis failures.
    @discardableResult
    public func enrich(applications: inout [Application]) -> [CollectionError] {
        var errors: [CollectionError] = []

        applications = applications.map { app in
            let info = analyzer.analyze(appPath: app.path)

            if info.analysisError {
                errors.append(CollectionError(
                    source: "CodeSigning",
                    message: "Failed to analyze code signature for \(app.bundleId)",
                    recoverable: true
                ))
            }

            let result = assessment.assess(
                signingInfo: info,
                entitlements: app.entitlements,
                isElectron: app.isElectron
            )

            return Application(
                name: app.name,
                bundleId: app.bundleId,
                path: app.path,
                version: app.version,
                teamId: info.teamId,
                hardenedRuntime: info.hardenedRuntime,
                libraryValidation: result.effectiveLibraryValidation,
                isElectron: app.isElectron,
                isSystem: app.isSystem,
                signed: info.signed,
                entitlements: app.entitlements,
                injectionMethods: result.methods
            )
        }

        return errors
    }
}
