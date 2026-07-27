import Foundation
import RootstockCore

/// Notarization / stapling trust-depth surface (Wave-7).
///
/// Research basis: Gatekeeper/notarization research; spctl/stapler operator checklists.
/// Safety and behavior: typed `NotarizationStaplingState`; never forges tickets or bypasses GK.
public struct NotarizationStaplingCollector: Collector {
    public static let id = "collect.notarization_stapling"
    public static let cost: CollectorCost = .low

    private static let toolingPaths: [String] = [
        "/usr/bin/stapler",
        "/usr/sbin/spctl",
        "/usr/bin/codesign",
        "/usr/bin/xcrun",
        "/usr/bin/altool",
        "/usr/bin/notarytool",
    ]

    private static let ticketCacheHints: [String] = [
        "/Library/Caches/com.apple.cloudtelemetryd",
        "/var/db/gkopaque.bundle",
        "/Library/Preferences/com.apple.security.plist",
        "/var/db/SystemPolicyConfiguration",
        "/Library/Security/PolicyBanner.rtf",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "Notarization/stapling surface: tooling + path presence - no ticket forge, no GK bypass",
        ]

        var tooling: [String] = []
        for path in Self.toolingPaths {
            if fm.fileExists(atPath: path) {
                tooling.append(path)
                notes.append("tooling: \(path)")
            }
        }

        var caches: [String] = []
        for path in Self.ticketCacheHints {
            if fm.fileExists(atPath: path) {
                caches.append(path)
                notes.append("ticket_or_policy_hint: \(path)")
            }
        }

        // Ad-hoc / unsigned class hints from common download dirs (names only).
        var unstapledOrAdHocHints: [String] = []
        let downloadRoots = [
            NSHomeDirectory() + "/Downloads",
            NSHomeDirectory() + "/Desktop",
        ]
        for root in downloadRoots {
            guard let names = try? fm.contentsOfDirectory(atPath: root) else { continue }
            for name in names.prefix(20) {
                let lower = name.lowercased()
                if lower.hasSuffix(".dmg")
                    || lower.hasSuffix(".pkg")
                    || lower.hasSuffix(".app")
                    || lower.hasSuffix(".zip")
                {
                    let full = (root as NSString).appendingPathComponent(name)
                    unstapledOrAdHocHints.append(full)
                    notes.append("delivery_artifact_hint: \(full)")
                }
            }
        }
        unstapledOrAdHocHints = Array(Set(unstapledOrAdHocHints)).sorted()

        let assessmentToolsPresent = tooling.contains { $0.hasSuffix("spctl") || $0.hasSuffix("stapler") }

        var state = CollectedState()
        state.notarizationStapling = NotarizationStaplingState(
            toolingPaths: tooling.sorted(),
            ticketCacheHints: caches.sorted(),
            unstapledOrAdHocHints: unstapledOrAdHocHints,
            assessmentToolsPresent: assessmentToolsPresent,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "tools=\(tooling.count) caches=\(caches.count) "
            + "deliveryHints=\(unstapledOrAdHocHints.count) "
            + "assessment=\(assessmentToolsPresent)"
        return state
    }
}
