import Foundation
import Models

/// Classifies raw entitlement keys into `EntitlementInfo` values.
struct EntitlementClassifier {

    private enum Category: String {
        case tcc
        case injection
        case privilege
        case sandbox
        case keychain
        case network
        case other

        var isSecurityCritical: Bool {
            switch self {
            case .tcc, .injection, .privilege: return true
            default: return false
            }
        }
    }

    /// Convert a raw entitlements dictionary into classified `EntitlementInfo` values.
    func classify(_ entitlements: [String: Any]) -> [EntitlementInfo] {
        return entitlements.keys.map { key in
            let category = categorize(key)
            let isPrivate = key.contains("com.apple.private.")
            return EntitlementInfo(
                name: key,
                isPrivate: isPrivate,
                category: category.rawValue,
                isSecurityCritical: category.isSecurityCritical
            )
        }.sorted { $0.name < $1.name }
    }

    // MARK: - Private

    private func categorize(_ name: String) -> Category {
        // TCC-related private entitlements
        if name.hasPrefix("com.apple.private.tcc.") { return .tcc }

        // Injection-enabling entitlements
        if name == "com.apple.security.cs.allow-dyld-environment-variables" { return .injection }
        if name == "com.apple.security.cs.disable-library-validation" { return .injection }
        if name == "com.apple.security.cs.allow-unsigned-executable-memory" { return .injection }
        if name == "com.apple.security.cs.disable-executable-page-protection" { return .injection }

        // Privilege-granting entitlements
        if name == "com.apple.security.get-task-allow" { return .privilege }
        if name == "com.apple.security.cs.debugger" { return .privilege }
        if name.hasPrefix("com.apple.rootless.") { return .privilege }

        // Sandbox-related
        if name == "com.apple.security.app-sandbox" { return .sandbox }
        if name.hasPrefix("com.apple.security.temporary-exception.") { return .sandbox }

        // Network
        if name.hasPrefix("com.apple.security.network.") { return .network }

        // Keychain
        if name == "keychain-access-groups" { return .keychain }
        if name == "com.apple.security.smartcard" { return .keychain }

        return .other
    }
}
