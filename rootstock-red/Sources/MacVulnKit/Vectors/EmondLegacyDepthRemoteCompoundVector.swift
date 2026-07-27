import Foundation
import RootstockCore

/// Wave-15 compound: Emond legacy depth × remote/FDA path-to-impact.
public struct EmondLegacyDepthRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.persist.emond_legacy_depth_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.emondLegacyDepth
        let a = s?.emondBinaryPaths.count ?? 0
        let b = s?.emondRulePaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        let sensorThin = state.esf?.clientPaths.isEmpty == true || state.securityProducts.filter(\.present).isEmpty
        guard remote || fda || sensorThin || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "emond_legacy_depth_compound", detail: "a=\(a) b=\(b) remote=\(remote) fda=\(fda) sensorThin=\(sensorThin)"),
        ]
        if let s {
            for path in (s.emondBinaryPaths + s.emondRulePaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Emond legacy depth compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never installs emond rules or enables the legacy event monitor daemon."))
        let severity: Severity = (remote && fda) ? .high : ((remote || fda || sensorThin) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Emond legacy depth × remote compound" : "Emond legacy depth × impact compound",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1546.014", "T1546", "T1059"],
            remediation: [
                "Prioritize hosts co-locating Emond legacy depth with remote/FDA amplifiers",
                "Use Wave-15 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ],
            falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first.",
            dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]
        )]
    }
}
