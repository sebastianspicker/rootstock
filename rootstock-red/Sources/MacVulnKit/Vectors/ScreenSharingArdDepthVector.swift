import Foundation
import RootstockCore

/// Path-to-impact: Screen Sharing / ARD residual depth.
public struct ScreenSharingArdDepthVector: Check {
    public static let id = "rootstock.vector.network.screen_sharing_ard_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.screenSharingArdDepth
        let a = s?.screenSharingAppPaths.count ?? 0
        let b = s?.ardAgentPaths.count ?? 0
        let c = s?.remoteMgmtPrefPaths.count ?? 0
        let surface = s?.ardSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.screen_sharing_ard_depth"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "screen_sharing_ard_depth_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.screenSharingAppPaths + s.ardAgentPaths + s.remoteMgmtPrefPaths).prefix(12) {
                evidence.append(Evidence(type: "screen_sharing_ard_depth_path", path: path, detail: "Screen Sharing ARD depth path"))
            }
            for n in s.notes.prefix(5) { evidence.append(Evidence(type: "screen_sharing_ard_depth_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never enables Screen Sharing or ARD, never connects to remote desktops."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Screen Sharing ARD depth with remote amplifier" : "Screen Sharing / ARD residual depth",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1021", "T1219", "T1133"],
            remediation: [
                "Inventory and baseline Screen Sharing ARD depth paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never enables Screen Sharing or ARD, never connects to remote desktops",
            ],
            falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
