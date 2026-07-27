import Foundation
import RootstockCore

/// Path-to-impact: Emond legacy rules residual depth.
public struct EmondLegacyDepthVector: Check {
    public static let id = "rootstock.vector.persist.emond_legacy_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.emondLegacyDepth
        let a = s?.emondBinaryPaths.count ?? 0
        let b = s?.emondRulePaths.count ?? 0
        let c = s?.emondSupportPaths.count ?? 0
        let surface = s?.emondSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.emond_legacy_depth"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "emond_legacy_depth_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.emondBinaryPaths + s.emondRulePaths + s.emondSupportPaths).prefix(12) {
                evidence.append(Evidence(type: "emond_legacy_depth_path", path: path, detail: "Emond legacy depth path"))
            }
            for n in s.notes.prefix(5) { evidence.append(Evidence(type: "emond_legacy_depth_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never installs emond rules or enables the legacy event monitor daemon."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Emond legacy depth with remote amplifier" : "Emond legacy rules residual depth",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1546.014", "T1546", "T1059"],
            remediation: [
                "Inventory and baseline Emond legacy depth paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never installs emond rules or enables the legacy event monitor daemon",
            ],
            falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
