import Foundation

/// A system extension registered via the SystemExtensions framework.
public struct SystemExtension: GraphNode {
    public var nodeType: String { "SystemExtension" }

    /// Extension bundle identifier.
    public let identifier: String

    /// Code signing team ID.
    public let teamId: String?

    /// Extension category: network, endpoint_security, or driver.
    public let extensionType: ExtensionType

    /// Whether the extension is currently enabled.
    public let enabled: Bool

    public enum ExtensionType: String, Codable, Sendable {
        case network
        case endpointSecurity = "endpoint_security"
        case driver
    }

    public init(identifier: String, teamId: String?, extensionType: ExtensionType, enabled: Bool) {
        self.identifier = identifier
        self.teamId = teamId
        self.extensionType = extensionType
        self.enabled = enabled
    }

    enum CodingKeys: String, CodingKey {
        case identifier
        case teamId = "team_id"
        case extensionType = "extension_type"
        case enabled
    }
}
