import Foundation
import RootstockCore

/// User-writable configuration profile / mobileconfig sideload risk (path only).
///
/// Research basis: MDM / profile sideload tradecraft; user Downloads as profile drop path;
/// ConfigurationProfiles store inventory ideas.
/// Safety and behavior: typed `ConfigProfileSideloadState`; lists paths/counts only - never
/// installs profiles, never parses payload secrets, never dumps profile DB contents.
///
/// Honesty: prefs names like `com.apple.SystemProfiler.plist` contain the substring
/// "profile" but are not configuration-profile sideload surface. Matching is tight.
public struct ConfigProfileSideloadCollector: Collector {
    public static let id = "collect.config_profile_sideload"
    public static let cost: CollectorCost = .low

    private static let profileInstallDbCandidates: [String] = [
        "/var/db/ConfigurationProfiles",
        "/private/var/db/ConfigurationProfiles",
        "/Library/ConfigurationProfiles",
        "/var/db/ConfigurationProfiles/Store",
    ]

    /// Prefs basenames that look like config-profile / MDM surface (not SystemProfiler).
    public static func isConfigurationProfilePrefName(_ name: String) -> Bool {
        let lower = name.lowercased()
        // Explicit exclusions: system profiler and similar false friends.
        if lower.contains("systemprofiler") || lower.contains("system_profiler") {
            return false
        }
        if lower.contains("activitymonitor") {
            return false
        }
        // Positive signals for configuration-profile / MDM prefs.
        if lower.hasSuffix(".mobileconfig") { return true }
        if lower.contains("mobileconfig") { return true }
        if lower.contains("configurationprofile") { return true }
        if lower.contains("configurationprofiles") { return true }
        if lower.hasPrefix("com.apple.managedclient") { return true }
        if lower.contains("mdm") && (lower.contains("profile") || lower.contains("enroll")) {
            return true
        }
        if lower.contains("pppc") || lower.contains("tcc.configuration") {
            return true
        }
        // "profile" alone is too broad (SystemProfiler). Require config/mdm/enroll context.
        if lower.contains("config") && lower.contains("profile") {
            return true
        }
        if lower.contains("enroll") && lower.contains("profile") {
            return true
        }
        return false
    }

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        let home = NSHomeDirectory()
        var notes: [String] = [
            "Config profile sideload surface: path/count only - no install, no payload parse",
            "Prefs filter excludes SystemProfiler and other non-config-profile names",
        ]

        var userMobileconfigPaths: [String] = []
        var downloadsProfileHints: [String] = []

        // ~/Downloads/*.mobileconfig (list dir - existence/count only).
        let downloads = (home as NSString).appendingPathComponent("Downloads")
        if fm.fileExists(atPath: downloads) {
            if let items = try? fm.contentsOfDirectory(atPath: downloads) {
                let mobileconfigs = items.filter {
                    $0.lowercased().hasSuffix(".mobileconfig")
                }
                for name in mobileconfigs {
                    let full = (downloads as NSString).appendingPathComponent(name)
                    userMobileconfigPaths.append(full)
                    downloadsProfileHints.append(full)
                }
                notes.append(
                    "Downloads mobileconfig count=\(mobileconfigs.count) dir=\(downloads)"
                )
            } else {
                notes.append("Downloads present but listing denied: \(downloads)")
            }
        } else {
            notes.append("Downloads directory absent: \(downloads)")
        }

        // Other user-writable mobileconfig drop zones (shallow).
        let extraUserDirs = [
            (home as NSString).appendingPathComponent("Desktop"),
            (home as NSString).appendingPathComponent("Documents"),
        ]
        for dir in extraUserDirs {
            guard fm.fileExists(atPath: dir),
                  let items = try? fm.contentsOfDirectory(atPath: dir)
            else { continue }
            for name in items where name.lowercased().hasSuffix(".mobileconfig") {
                let full = (dir as NSString).appendingPathComponent(name)
                userMobileconfigPaths.append(full)
                notes.append("user_mobileconfig: \(full)")
            }
        }

        // ~/Library/Preferences profile-ish hints (tight name filter).
        let userPrefs = (home as NSString).appendingPathComponent("Library/Preferences")
        if let items = try? fm.contentsOfDirectory(atPath: userPrefs) {
            let profileish = items.filter { Self.isConfigurationProfilePrefName($0) }
            for name in profileish {
                let full = (userPrefs as NSString).appendingPathComponent(name)
                downloadsProfileHints.append("prefs:\(full)")
                notes.append("user_prefs_config_profile_hint: \(name)")
            }
            // Record that SystemProfiler-style names were considered and rejected when present.
            if items.contains(where: { $0.lowercased().contains("systemprofiler") }) {
                notes.append("excluded_prefs_false_friend: SystemProfiler (not configuration profile)")
            }
        } else {
            notes.append("User Preferences dir unreadable or absent")
        }

        // System profile install DB presence (not secrets).
        var profileInstallDbPresent: Bool?
        for path in Self.profileInstallDbCandidates {
            if fm.fileExists(atPath: path) {
                profileInstallDbPresent = true
                notes.append("profile_store present: \(path) (not dumping contents)")
            }
        }
        if profileInstallDbPresent == nil {
            profileInstallDbPresent = false
            notes.append("ConfigurationProfiles store not observed at catalog paths")
        }

        // Cap path lists for report size (count still reflected in notes).
        let maxPaths = 50
        if userMobileconfigPaths.count > maxPaths {
            notes.append(
                "userMobileconfigPaths truncated \(userMobileconfigPaths.count)→\(maxPaths)"
            )
            userMobileconfigPaths = Array(userMobileconfigPaths.prefix(maxPaths))
        }
        if downloadsProfileHints.count > maxPaths {
            notes.append(
                "downloadsProfileHints truncated \(downloadsProfileHints.count)→\(maxPaths)"
            )
            downloadsProfileHints = Array(downloadsProfileHints.prefix(maxPaths))
        }

        userMobileconfigPaths = Array(Set(userMobileconfigPaths)).sorted()
        downloadsProfileHints = Array(Set(downloadsProfileHints)).sorted()

        var state = CollectedState()
        state.configProfileSideload = ConfigProfileSideloadState(
            userMobileconfigPaths: userMobileconfigPaths,
            downloadsProfileHints: downloadsProfileHints,
            profileInstallDbPresent: profileInstallDbPresent,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "mobileconfigs=\(userMobileconfigPaths.count) "
            + "hints=\(downloadsProfileHints.count) "
            + "profileDb=\(profileInstallDbPresent.map(String.init(describing:)) ?? "nil")"
        return state
    }
}
