import Foundation
import RootstockCore

/// Authorization rights / auth.db / PackageKit privilege surface (path only).
///
/// Research basis: auth.db / authorization.plist research, PackageKit privilege-escalation
/// literature, authd inventory ideas.
/// Safety and behavior: typed `AuthRightsState` for privilege-surface vectors; never dumps
/// auth.db rows or right definitions; path/existence probes only.
public struct AuthRightsCollector: Collector {
    public static let id = "collect.auth_rights"
    public static let cost: CollectorCost = .low

    private static let authDbCandidates: [String] = [
        "/var/db/auth.db",
        "/private/var/db/auth.db",
    ]

    private static let authorizationPlistCandidates: [String] = [
        "/System/Library/Security/authorization.plist",
        "/Library/Security/authorization.plist",
        "/System/Library/Security/Authorization.plist",
    ]

    private static let packageKitCandidates: [String] = [
        "/System/Library/PrivateFrameworks/PackageKit.framework",
        "/System/Library/PrivateFrameworks/PackageKit.framework/Versions/A/PackageKit",
        "/usr/sbin/installer",
        "/usr/sbin/pkgutil",
        "/System/Library/CoreServices/Installer.app",
    ]

    private static let authdCandidates: [String] = [
        "/usr/libexec/authd",
        "/System/Library/LaunchDaemons/com.apple.authd.plist",
    ]

    /// Additional privilege-surface path probes (presence only; PHT is a sibling collector).
    private static let rightsHintCandidates: [String] = [
        "/usr/libexec/security_authtrampoline",
        "/System/Library/PrivateFrameworks/SystemAdministration.framework",
        "/etc/authorization",
        "/private/etc/authorization",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "Auth rights / PackageKit surface: path presence only - no auth.db dump, no right enumeration",
        ]

        var authDbPresent: Bool?
        var authDbPath: String?
        for path in Self.authDbCandidates {
            if fm.fileExists(atPath: path) {
                authDbPresent = true
                authDbPath = path
                notes.append("auth.db present: \(path) (not reading rows)")
                break
            }
        }
        if authDbPresent == nil {
            authDbPresent = false
            notes.append("auth.db not observed at catalog paths (may be SIP/root restricted)")
        }

        var authorizationPlistPaths: [String] = []
        for path in Self.authorizationPlistCandidates {
            if fm.fileExists(atPath: path) {
                authorizationPlistPaths.append(path)
                notes.append("authorization.plist: \(path)")
            }
        }

        var packageKitPaths: [String] = []
        for path in Self.packageKitCandidates {
            if fm.fileExists(atPath: path) {
                packageKitPaths.append(path)
                notes.append("packagekit: \(path)")
            }
        }

        var rightsHintCount = 0
        for path in Self.authdCandidates {
            if fm.fileExists(atPath: path) {
                rightsHintCount += 1
                notes.append("authd: \(path)")
            }
        }
        for path in Self.rightsHintCandidates {
            if fm.fileExists(atPath: path) {
                rightsHintCount += 1
                notes.append("rights_hint: \(path)")
            }
        }
        // Count authorization plists as rights-surface hints too.
        rightsHintCount += authorizationPlistPaths.count

        authorizationPlistPaths = Array(Set(authorizationPlistPaths)).sorted()
        packageKitPaths = Array(Set(packageKitPaths)).sorted()

        var state = CollectedState()
        state.authRights = AuthRightsState(
            authDbPresent: authDbPresent,
            authDbPath: authDbPath,
            authorizationPlistPaths: authorizationPlistPaths,
            packageKitPaths: packageKitPaths,
            rightsHintCount: rightsHintCount,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "authDb=\(authDbPresent.map(String.init(describing:)) ?? "nil") "
            + "authPlists=\(authorizationPlistPaths.count) "
            + "packageKit=\(packageKitPaths.count) "
            + "rightsHints=\(rightsHintCount)"
        return state
    }
}
