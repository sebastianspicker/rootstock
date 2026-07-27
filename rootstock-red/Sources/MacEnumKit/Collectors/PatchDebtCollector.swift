import Foundation
import RootstockCore

/// OS patch-debt / Software Update heuristics for CVE suggester context.
///
/// Research basis: PEASS OS version checks; compliance scanners' "days since patch" ideas.
/// Safety and behavior: typed `PatchDebtState` with major-version lag heuristics; never weaponizes
/// CVEs; never downloads exploit packs; confidence honesty for operators.
public struct PatchDebtCollector: Collector {
    public static let id = "collect.patch_debt"
    public static let cost: CollectorCost = .low

    /// Conservative "known-current major" for lag heuristics (update as product evolves).
    /// Lag is informational only - not a vulnerability claim by itself.
    public static let knownCurrentMajor = 15

    private static let susPlistCandidates: [String] = [
        "/Library/Preferences/com.apple.SoftwareUpdate.plist",
        "/Library/Preferences/com.apple.commerce.plist",
    ]

    private static let installHistoryCandidates: [String] = [
        "/Library/Receipts/InstallHistory.plist",
        "/System/Library/Receipts",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        let info = ProcessInfo.processInfo
        let os = info.operatingSystemVersion
        let osVersion = "\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)"

        var notes: [String] = [
            "Patch-debt heuristics only - suggester context, not CVE exploit pack",
        ]
        var lastUpdateHints: [String] = []

        var susPresent: Bool?
        for path in Self.susPlistCandidates {
            if fm.fileExists(atPath: path) {
                susPresent = true
                lastUpdateHints.append("sus_plist:\(path)")
                notes.append("Software Update prefs present: \(path)")
            }
        }
        if susPresent == nil {
            susPresent = false
            notes.append("No Software Update preference plists observed at catalog paths")
        }

        for path in Self.installHistoryCandidates {
            if fm.fileExists(atPath: path) {
                lastUpdateHints.append("install_history_path:\(path)")
                notes.append("Install history / receipts path present: \(path)")
            }
        }

        // Optional: read OS build via `sw_vers`-equivalent without shell when possible.
        var osBuild: String?
        let versionPlist = URL(fileURLWithPath: "/System/Library/CoreServices/SystemVersion.plist")
        if let data = try? Data(contentsOf: versionPlist),
           let dict = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        {
            if let build = dict["ProductBuildVersion"] as? String {
                osBuild = build
                notes.append("ProductBuildVersion=\(build)")
            }
            if let productVersion = dict["ProductUserVisibleVersion"] as? String
                ?? dict["ProductVersion"] as? String
            {
                notes.append("ProductVersion=\(productVersion)")
            }
        } else {
            notes.append("SystemVersion.plist unreadable - using ProcessInfo only")
        }

        let majorLag = max(0, Self.knownCurrentMajor - os.majorVersion)
        if majorLag > 0 {
            notes.append(
                "majorVersionLag=\(majorLag) (host major \(os.majorVersion) vs baseline \(Self.knownCurrentMajor))"
            )
        } else {
            notes.append(
                "majorVersionLag=0 (host major \(os.majorVersion) ≥ baseline \(Self.knownCurrentMajor))"
            )
        }

        var state = CollectedState()
        state.patchDebt = PatchDebtState(
            osVersion: osVersion,
            osBuild: osBuild,
            softwareUpdatePlistPresent: susPresent,
            lastUpdateHints: lastUpdateHints,
            majorVersionLag: majorLag,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "os=\(osVersion) build=\(osBuild ?? "nil") lag=\(majorLag) sus=\(susPresent.map(String.init(describing:)) ?? "nil")"
        return state
    }
}
