import Foundation
import RootstockCore

/// Path-to-impact: Reminders cloud path residual plane.
public struct RemindersCloudPathVector: Check {
    public static let id = "rootstock.vector.data.reminders_cloud_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.remindersCloudPath
        let a = s?.remindersAppPaths.count ?? 0
        let b = s?.remindersStorePaths.count ?? 0
        let c = s?.remindersPrefPaths.count ?? 0
        let surface = s?.remindersCloudSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.reminders_cloud_path"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "reminders_cloud_path_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.remindersAppPaths + s.remindersStorePaths + s.remindersPrefPaths).prefix(10) {
                evidence.append(Evidence(type: "reminders_cloud_path_path", path: path, detail: "Reminders cloud path path"))
            }
            for n in s.notes.prefix(4) { evidence.append(Evidence(type: "reminders_cloud_path_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never reads reminder titles/bodies or exports Reminders databases."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Reminders cloud path with remote amplifier" : "Reminders cloud path residual plane",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1005", "T1213", "T1083"],
            remediation: [
                "Inventory and baseline Reminders cloud path paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never reads reminder titles/bodies or exports Reminders databases",
            ],
            falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
