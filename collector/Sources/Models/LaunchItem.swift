import Foundation

/// A persistence mechanism: a launchd job, login item, cron job, or login hook.
public struct LaunchItem: GraphNode {
    public var nodeType: String { "LaunchItem" }

    /// Label or identifier for this persistence item (e.g., "com.apple.logd").
    public let label: String

    /// Path to the plist, crontab, or hook configuration file.
    public let path: String

    /// How this item achieves persistence.
    public let type: ItemType

    /// Binary or script that is executed.
    public let program: String?

    /// Whether the item starts automatically at boot or login.
    public let runAtLoad: Bool

    /// User account this item runs as (nil = inherits from context).
    public let user: String?

    public enum ItemType: String, Codable, Sendable {
        case daemon
        case agent
        case loginItem = "login_item"
        case cron
        case loginHook = "login_hook"
    }

    public init(
        label: String,
        path: String,
        type: ItemType,
        program: String?,
        runAtLoad: Bool,
        user: String?
    ) {
        self.label = label
        self.path = path
        self.type = type
        self.program = program
        self.runAtLoad = runAtLoad
        self.user = user
    }

    enum CodingKeys: String, CodingKey {
        case label
        case path
        case type
        case program
        case runAtLoad = "run_at_load"
        case user
    }
}
