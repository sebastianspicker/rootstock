import Foundation
import RootstockCore

/// Path-to-impact: Automator workflow delivery residual.
public struct AutomatorWorkflowVector: Check {
    public static let id = "rootstock.vector.delivery.automator_workflow"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.automatorWorkflow
        let a = s?.automatorAppPaths.count ?? 0
        let b = s?.workflowSamplePaths.count ?? 0
        let c = s?.actionLibraryPaths.count ?? 0
        let surface = s?.workflowSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.automator_workflow"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "automator_workflow_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.automatorAppPaths + s.workflowSamplePaths + s.actionLibraryPaths).prefix(12) {
                evidence.append(Evidence(type: "automator_workflow_path", path: path, detail: "Automator workflow delivery path"))
            }
            for n in s.notes.prefix(5) { evidence.append(Evidence(type: "automator_workflow_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never executes Automator workflows or plants malicious .workflow bundles."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Automator workflow delivery with remote amplifier" : "Automator workflow delivery residual",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1059", "T1204", "T1546"],
            remediation: [
                "Inventory and baseline Automator workflow delivery paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never executes Automator workflows or plants malicious .workflow bundles",
            ],
            falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
