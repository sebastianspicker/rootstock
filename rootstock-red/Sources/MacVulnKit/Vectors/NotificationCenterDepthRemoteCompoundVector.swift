import Foundation
import RootstockCore

/// Wave-16 compound: Notification Center depth × remote/FDA path-to-impact.
public struct NotificationCenterDepthRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.data.notification_center_depth_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.notificationCenterDepth
        let a = s?.notificationFrameworkPaths.count ?? 0
        let b = s?.notificationStorePaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        let sensorThin = state.esf?.clientPaths.isEmpty == true || state.securityProducts.filter(\.present).isEmpty
        guard remote || fda || sensorThin || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "notification_center_depth_compound", detail: "a=\(a) b=\(b) remote=\(remote) fda=\(fda) sensorThin=\(sensorThin)"),
        ]
        if let s {
            for path in (s.notificationFrameworkPaths + s.notificationStorePaths).prefix(6) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Notification Center depth compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never dumps notification body contents or forges notification payloads."))
        let severity: Severity = (remote && fda) ? .high : ((remote || fda || sensorThin) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Notification Center depth × remote compound" : "Notification Center depth × impact compound",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1518", "T1083", "T1005"],
            remediation: [
                "Prioritize hosts co-locating Notification Center depth with remote/FDA amplifiers",
                "Use Wave-16 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ],
            falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first.",
            dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]
        )]
    }
}
