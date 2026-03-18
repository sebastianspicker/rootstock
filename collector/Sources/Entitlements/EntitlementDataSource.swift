import Foundation
import Models

/// Discovers installed apps and extracts their entitlements.
public struct EntitlementDataSource: DataSource {
    public let name = "Entitlements"
    public let requiresElevation = false

    private let discovery: AppDiscovery
    private let extractor: EntitlementExtractor
    private let classifier: EntitlementClassifier

    public init() {
        discovery = AppDiscovery()
        extractor = EntitlementExtractor()
        classifier = EntitlementClassifier()
    }

    public func collect() async -> DataSourceResult {
        let discovered = discovery.discover()

        var applications: [Application] = []
        let errors: [CollectionError] = []

        for app in discovered {
            let entitlementDict = extractor.extract(from: URL(fileURLWithPath: app.executablePath))
            let entitlements = classifier.classify(entitlementDict)

            let application = Application(
                name: app.name,
                bundleId: app.bundleId,
                path: app.path,
                version: app.version,
                teamId: nil,
                hardenedRuntime: false,
                libraryValidation: false,
                isElectron: app.isElectron,
                isSystem: app.isSystem,
                signed: !entitlementDict.isEmpty,
                entitlements: entitlements,
                injectionMethods: []  // populated by CodeSigningDataSource
            )
            applications.append(application)
        }

        return DataSourceResult(nodes: applications, errors: errors)
    }
}
