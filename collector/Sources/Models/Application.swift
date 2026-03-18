import Foundation

/// A discovered macOS .app bundle with entitlement and code signing metadata.
public struct Application: Codable, Sendable, GraphNode {
    public let name: String
    public let bundleId: String
    public let path: String
    public let version: String?
    public let teamId: String?
    public let hardenedRuntime: Bool
    public let libraryValidation: Bool
    public let isElectron: Bool
    public let isSystem: Bool
    public let signed: Bool
    public let entitlements: [EntitlementInfo]
    public let injectionMethods: [InjectionMethod]

    public var nodeType: String { "Application" }

    public init(
        name: String,
        bundleId: String,
        path: String,
        version: String?,
        teamId: String?,
        hardenedRuntime: Bool,
        libraryValidation: Bool,
        isElectron: Bool,
        isSystem: Bool,
        signed: Bool,
        entitlements: [EntitlementInfo] = [],
        injectionMethods: [InjectionMethod] = []
    ) {
        self.name = name
        self.bundleId = bundleId
        self.path = path
        self.version = version
        self.teamId = teamId
        self.hardenedRuntime = hardenedRuntime
        self.libraryValidation = libraryValidation
        self.isElectron = isElectron
        self.isSystem = isSystem
        self.signed = signed
        self.entitlements = entitlements
        self.injectionMethods = injectionMethods
    }

    enum CodingKeys: String, CodingKey {
        case name
        case bundleId = "bundle_id"
        case path
        case version
        case teamId = "team_id"
        case hardenedRuntime = "hardened_runtime"
        case libraryValidation = "library_validation"
        case isElectron = "is_electron"
        case isSystem = "is_system"
        case signed
        case entitlements
        case injectionMethods = "injection_methods"
    }
}
