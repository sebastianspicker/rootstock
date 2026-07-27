import Foundation
import RootstockCore

/// Path-to-impact: Time Machine local snapshot residual depth.
public struct TmLocalSnapshotDepthVector: Check {
    public static let id = "rootstock.vector.data.tm_local_snapshot_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.tmLocalSnapshotDepth
        let a = s?.tmUtilPaths.count ?? 0
        let b = s?.snapshotStorePaths.count ?? 0
        let c = s?.tmPrefPaths.count ?? 0
        let surface = s?.tmSnapshotSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.tm_local_snapshot_depth"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "tm_local_snapshot_depth_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.tmUtilPaths + s.snapshotStorePaths + s.tmPrefPaths).prefix(12) {
                evidence.append(Evidence(type: "tm_local_snapshot_depth_path", path: path, detail: "TM local snapshot depth path"))
            }
            for n in s.notes.prefix(5) { evidence.append(Evidence(type: "tm_local_snapshot_depth_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never mounts snapshots for data theft or deletes backup catalogs."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "TM local snapshot depth with remote amplifier" : "Time Machine local snapshot residual depth",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1005", "T1530", "T1083"],
            remediation: [
                "Inventory and baseline TM local snapshot depth paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never mounts snapshots for data theft or deletes backup catalogs",
            ],
            falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
