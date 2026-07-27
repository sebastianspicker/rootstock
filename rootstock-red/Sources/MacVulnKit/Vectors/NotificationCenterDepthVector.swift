import Foundation
import RootstockCore

/// Path-to-impact: Notification Center residual depth.
public struct NotificationCenterDepthVector: Check {
    public static let id = "rootstock.vector.data.notification_center_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.notificationCenterDepth
        let a = s?.notificationFrameworkPaths.count ?? 0
        let b = s?.notificationStorePaths.count ?? 0
        let c = s?.notificationPrefPaths.count ?? 0
        let surface = s?.notificationSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.notification_center_depth"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "notification_center_depth_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.notificationFrameworkPaths + s.notificationStorePaths + s.notificationPrefPaths).prefix(10) {
                evidence.append(Evidence(type: "notification_center_depth_path", path: path, detail: "Notification Center depth path"))
            }
            for n in s.notes.prefix(4) { evidence.append(Evidence(type: "notification_center_depth_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never dumps notification body contents or forges notification payloads."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Notification Center depth with remote amplifier" : "Notification Center residual depth",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1518", "T1083", "T1005"],
            remediation: [
                "Inventory and baseline Notification Center depth paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never dumps notification body contents or forges notification payloads",
            ],
            falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
