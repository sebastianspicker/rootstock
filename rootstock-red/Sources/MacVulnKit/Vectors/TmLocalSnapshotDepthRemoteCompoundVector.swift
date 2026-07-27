import Foundation
import RootstockCore

/// Wave-15 compound: TM local snapshot depth × remote/FDA path-to-impact.
public struct TmLocalSnapshotDepthRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.data.tm_local_snapshot_depth_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.tmLocalSnapshotDepth
        let a = s?.tmUtilPaths.count ?? 0
        let b = s?.snapshotStorePaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        let sensorThin = state.esf?.clientPaths.isEmpty == true || state.securityProducts.filter(\.present).isEmpty
        guard remote || fda || sensorThin || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "tm_local_snapshot_depth_compound", detail: "a=\(a) b=\(b) remote=\(remote) fda=\(fda) sensorThin=\(sensorThin)"),
        ]
        if let s {
            for path in (s.tmUtilPaths + s.snapshotStorePaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "TM local snapshot depth compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never mounts snapshots for data theft or deletes backup catalogs."))
        let severity: Severity = (remote && fda) ? .high : ((remote || fda || sensorThin) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "TM local snapshot depth × remote compound" : "TM local snapshot depth × impact compound",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1005", "T1530", "T1083"],
            remediation: [
                "Prioritize hosts co-locating TM local snapshot depth with remote/FDA amplifiers",
                "Use Wave-15 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ],
            falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first.",
            dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]
        )]
    }
}
