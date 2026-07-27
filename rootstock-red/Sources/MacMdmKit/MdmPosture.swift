import Foundation
import RootstockCore

/// Read-only MDM / management posture - vendor paths, managed prefs, profile store.
///
/// Pure filesystem (no `profiles` CLI). Records paths/names only; never parses
/// binary profile secrets or PPPC payload contents.
public struct MdmPostureCollector: Collector {
    public static let id = "collect.mdm"
    public static let cost: CollectorCost = .low

    private static let vendorPaths: [(String, String)] = [
        ("Jamf", "/usr/local/bin/jamf"),
        ("Jamf", "/usr/local/jamf/bin/jamf"),
        ("Kandji", "/Library/Kandji"),
        ("Mosyle", "/Library/Application Support/Mosyle"),
        ("Intune", "/Library/Intune"),
        ("Company Portal", "/Applications/Company Portal.app"),
        ("Workspace ONE", "/Library/Application Support/AirWatch"),
        ("Addigy", "/Library/Addigy"),
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "MDM posture via filesystem heuristics (no profiles CLI)",
        ]

        // MARK: - Vendor agent paths

        var hints: [String] = []
        for (name, path) in Self.vendorPaths {
            let exists = fm.fileExists(atPath: path)
            notes.append("Vendor path: \(name) \(path) exists=\(exists)")
            if exists {
                hints.append(name)
            }
        }
        let vendorHints = Array(Set(hints)).sorted()

        // MARK: - Managed Preferences (top-level names only)

        let managedPrefsRoot = "/Library/Managed Preferences"
        var managedPreferenceNames: [String] = []
        if fm.fileExists(atPath: managedPrefsRoot) {
            if let names = try? fm.contentsOfDirectory(atPath: managedPrefsRoot) {
                managedPreferenceNames = names.sorted()
                notes.append(
                    "Managed Preferences listable (\(managedPreferenceNames.count) top-level names)"
                )
            } else {
                notes.append("Managed Preferences present but not listable")
            }
        } else {
            notes.append("Managed Preferences root missing: \(managedPrefsRoot)")
        }

        // MARK: - PPPC / TCC configuration-profile policy (path presence only)

        let pppcCandidates = [
            "/Library/Managed Preferences/com.apple.TCC.configuration-profile-policy.plist",
            "/Library/Managed Preferences/com.apple.TCC.configuration-profile-policy",
            "/var/db/ConfigurationProfiles/Settings/com.apple.TCC.configuration-profile-policy.plist",
        ]
        var pppcPath: String?
        for path in pppcCandidates {
            let exists = fm.fileExists(atPath: path)
            notes.append("PPPC policy candidate: \(path) exists=\(exists)")
            if exists, pppcPath == nil {
                pppcPath = path
            }
        }
        // Also match by managed-prefs filename pattern without reading contents.
        if pppcPath == nil {
            let pppcName = managedPreferenceNames.first {
                $0.localizedCaseInsensitiveContains("TCC.configuration-profile-policy")
                    || $0.localizedCaseInsensitiveContains("tcc.configuration-profile-policy")
            }
            if let pppcName {
                pppcPath = (managedPrefsRoot as NSString).appendingPathComponent(pppcName)
                notes.append("PPPC policy matched managed prefs name: \(pppcPath!)")
            }
        }
        let pppcPolicyPresent: Bool? = pppcPath != nil

        // MARK: - Configuration profile stores

        let profileStores = [
            "/var/db/ConfigurationProfiles",
            "/Library/ConfigurationProfiles",
            "/var/db/ConfigurationProfiles/Store",
        ]
        var profileStoreReadable: Bool?
        var profileFileCount: Int?
        var anyStoreExists = false
        for store in profileStores {
            let exists = fm.fileExists(atPath: store)
            let readable = fm.isReadableFile(atPath: store)
            notes.append("Profile store: \(store) exists=\(exists) readable=\(readable)")
            guard exists else { continue }
            anyStoreExists = true
            if let entries = try? fm.contentsOfDirectory(atPath: store) {
                profileStoreReadable = true
                let profileLike = entries.filter { name in
                    let lower = name.lowercased()
                    return lower.hasSuffix(".mobileconfig")
                        || lower.hasSuffix(".profile")
                        || lower.hasSuffix(".plist")
                        || lower == "store"
                        || lower.contains("profile")
                }
                let count = Self.countProfileLikeFiles(root: store, fm: fm, depth: 0, maxDepth: 2)
                let combined = max(count, profileLike.count)
                profileFileCount = (profileFileCount ?? 0) + combined
                notes.append(
                    "Profile store listable: \(store) topLevel=\(entries.count) profileLike≈\(combined)"
                )
            } else if readable {
                profileStoreReadable = profileStoreReadable ?? true
                notes.append("Profile store readable but contentsOfDirectory failed: \(store)")
            } else {
                if profileStoreReadable == nil {
                    profileStoreReadable = false
                }
                notes.append("Profile store not listable (likely root/SIP): \(store)")
            }
        }
        if !anyStoreExists {
            profileStoreReadable = false
            profileFileCount = 0
            notes.append("No configuration profile store paths found")
        }

        // MARK: - Enrollment / ManagedClient prefs (existence only)

        let enrollPaths = [
            "/Library/Preferences/com.apple.ManagedClient.enroll.plist",
            "/Library/Preferences/com.apple.ManagedClient.plist",
            "/var/db/ConfigurationProfiles/MDM_ComputerPrefs.plist",
            "/var/db/ConfigurationProfiles/SecureUserPreferences.plist",
            "/Library/Keychains/FileVaultMaster.keychain",
        ]
        var enrollHits: [String] = []
        for path in enrollPaths {
            let exists = fm.fileExists(atPath: path)
            notes.append("Enrollment/ManagedClient: \(path) exists=\(exists)")
            if exists {
                enrollHits.append(path)
            }
        }

        // MARK: - Enrolled heuristic

        let strongSignals =
            !vendorHints.isEmpty
            || !enrollHits.isEmpty
            || (profileFileCount ?? 0) > 0
            || pppcPolicyPresent == true
            || managedPreferenceNames.contains {
                $0.hasPrefix("com.apple.mdm")
                    || $0.localizedCaseInsensitiveContains("ManagedClient")
            }

        // Managed Preferences often exist on stock systems for other reasons,
        // treat non-empty managed prefs as weak signal only when combined.
        let weakManaged = !managedPreferenceNames.isEmpty
        let enrolled: Bool?
        if strongSignals {
            enrolled = true
            notes.append("Enrollment signal: positive (vendor/enroll/profile/PPPC)")
        } else if weakManaged && anyStoreExists {
            enrolled = true
            notes.append("Enrollment signal: likely (managed prefs + profile store present)")
        } else if !vendorHints.isEmpty {
            enrolled = true
        } else {
            enrolled = nil
            notes.append(
                "Enrollment signal: unknown (no vendor agent / enroll plist / profile files)"
            )
        }

        notes.append(
            "Summary: enrolled=\(enrolled.rootstockDescribe) vendors=\(vendorHints.joined(separator: ",")) "
                + "managedPrefs=\(managedPreferenceNames.count) profileStoreReadable=\(profileStoreReadable.rootstockDescribe) "
                + "profileFiles=\(profileFileCount.map(String.init) ?? "nil") pppc=\(pppcPolicyPresent.rootstockDescribe)"
        )

        var state = CollectedState()
        state.mdm = MDMState(
            enrolled: enrolled,
            vendorHints: vendorHints,
            managedPreferenceNames: managedPreferenceNames,
            profileStoreReadable: profileStoreReadable,
            profileFileCount: profileFileCount,
            pppcPolicyPresent: pppcPolicyPresent,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "mdm fs+vendor enrolled=\(enrolled.rootstockDescribe) "
            + "vendors=\(vendorHints.count) managedPrefs=\(managedPreferenceNames.count) "
            + "profiles=\(profileFileCount.map(String.init) ?? "nil")"
        return state
    }

    /// Bounded recursive count of profile-like filenames (names only).
    private static func countProfileLikeFiles(
        root: String,
        fm: FileManager,
        depth: Int,
        maxDepth: Int
    ) -> Int {
        guard depth <= maxDepth else { return 0 }
        guard let entries = try? fm.contentsOfDirectory(atPath: root) else { return 0 }
        var count = 0
        for name in entries {
            let path = (root as NSString).appendingPathComponent(name)
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: path, isDirectory: &isDir) else { continue }
            if isDir.boolValue {
                count += countProfileLikeFiles(
                    root: path,
                    fm: fm,
                    depth: depth + 1,
                    maxDepth: maxDepth
                )
            } else {
                let lower = name.lowercased()
                if lower.hasSuffix(".mobileconfig")
                    || lower.hasSuffix(".profile")
                    || lower.hasSuffix(".plist")
                {
                    count += 1
                }
            }
        }
        return count
    }

}
