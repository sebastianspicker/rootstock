import Foundation
import RootstockCore

/// Path-to-impact: Gatekeeper assessment / syspolicyd history depth.
public struct GatekeeperAssessmentHistoryVector: Check {
    public static let id = "rootstock.vector.codesign.gk_assessment_history"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.gatekeeperAssessmentHistory
        let a = s?.syspolicydPaths.count ?? 0
        let b = s?.assessmentDbPaths.count ?? 0
        let c = s?.spctlToolPaths.count ?? 0
        let surface = s?.assessmentSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.gatekeeper_assessment_history"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "gk_assessment_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.syspolicydPaths + s.assessmentDbPaths + s.spctlToolPaths).prefix(12) {
                evidence.append(Evidence(type: "gk_assessment_path", path: path, detail: "Gatekeeper assessment history path"))
            }
            for n in s.notes.prefix(6) { evidence.append(Evidence(type: "gk_assessment_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never clears Gatekeeper assessments or disables syspolicyd."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Gatekeeper assessment history with remote access amplifier" : "Gatekeeper assessment / syspolicyd history depth",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1553.001", "T1204", "T1562"],
            remediation: [
                "Inventory and baseline Gatekeeper assessment history paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never clears Gatekeeper assessments or disables syspolicyd",
            ],
            falsePositiveNotes: "Stock macOS paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
