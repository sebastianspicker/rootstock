import Foundation
import RootstockCore

/// Path-to-impact: Cron / at job dual-use residual depth.
public struct CronAtJobDepthVector: Check {
    public static let id = "rootstock.vector.persist.cron_at_job_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.cronAtJobDepth
        let a = s?.cronBinaryPaths.count ?? 0
        let b = s?.crontabPaths.count ?? 0
        let c = s?.atJobPaths.count ?? 0
        let surface = s?.cronAtSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.cron_at_job_depth"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "cron_at_job_depth_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.cronBinaryPaths + s.crontabPaths + s.atJobPaths).prefix(12) {
                evidence.append(Evidence(type: "cron_at_job_depth_path", path: path, detail: "Cron/at job depth path"))
            }
            for n in s.notes.prefix(5) { evidence.append(Evidence(type: "cron_at_job_depth_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never installs cron or at jobs outside the lab root."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Cron/at job depth with remote amplifier" : "Cron / at job dual-use residual depth",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1053.003", "T1053", "T1543"],
            remediation: [
                "Inventory and baseline Cron/at job depth paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never installs cron or at jobs outside the lab root",
            ],
            falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
