import Foundation
import RootstockCore

/// Path-to-impact: LaunchServices QuarantineEvents DB residual depth.
public struct LsQuarantineDbDepthVector: Check {
    public static let id = "rootstock.vector.codesign.ls_quarantine_db_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.lsQuarantineDbDepth
        let a = s?.quarantineDbPaths.count ?? 0
        let b = s?.lsSupportPaths.count ?? 0
        let c = s?.quarantineToolHints.count ?? 0
        let surface = s?.quarantineDbSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.ls_quarantine_db_depth"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "ls_quarantine_db_depth_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.quarantineDbPaths + s.lsSupportPaths + s.quarantineToolHints).prefix(12) {
                evidence.append(Evidence(type: "ls_quarantine_db_depth_path", path: path, detail: "LS QuarantineEvents depth path"))
            }
            for n in s.notes.prefix(5) { evidence.append(Evidence(type: "ls_quarantine_db_depth_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never deletes QuarantineEvents rows or clears LS quarantine history."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "LS QuarantineEvents depth with remote amplifier" : "LaunchServices QuarantineEvents DB residual depth",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1553.001", "T1074", "T1083"],
            remediation: [
                "Inventory and baseline LS QuarantineEvents depth paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never deletes QuarantineEvents rows or clears LS quarantine history",
            ],
            falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
