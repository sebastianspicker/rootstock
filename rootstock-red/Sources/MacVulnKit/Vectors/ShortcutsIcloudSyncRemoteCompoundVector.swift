import Foundation
import RootstockCore

/// Wave-16 compound: Shortcuts iCloud sync × remote/FDA path-to-impact.
public struct ShortcutsIcloudSyncRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.automation.shortcuts_icloud_sync_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.shortcutsIcloudSync
        let a = s?.shortcutsAppPaths.count ?? 0
        let b = s?.shortcutsDbPaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        let sensorThin = state.esf?.clientPaths.isEmpty == true || state.securityProducts.filter(\.present).isEmpty
        guard remote || fda || sensorThin || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "shortcuts_icloud_sync_compound", detail: "a=\(a) b=\(b) remote=\(remote) fda=\(fda) sensorThin=\(sensorThin)"),
        ]
        if let s {
            for path in (s.shortcutsAppPaths + s.shortcutsDbPaths).prefix(6) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Shortcuts iCloud sync compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never executes Shortcuts or dumps iCloud-synced automation databases."))
        let severity: Severity = (remote && fda) ? .high : ((remote || fda || sensorThin) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Shortcuts iCloud sync × remote compound" : "Shortcuts iCloud sync × impact compound",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1059", "T1530", "T1083"],
            remediation: [
                "Prioritize hosts co-locating Shortcuts iCloud sync with remote/FDA amplifiers",
                "Use Wave-16 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ],
            falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first.",
            dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]
        )]
    }
}
