import Foundation
import RootstockCore

/// Path-to-impact: iMessage / Messages path collection plane.
public struct ImessagePathPlaneVector: Check {
    public static let id = "rootstock.vector.data.imessage_path_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.imessagePathPlane
        let a = s?.messagesAppPaths.count ?? 0
        let b = s?.messagesDbPaths.count ?? 0
        let c = s?.messagesPrefPaths.count ?? 0
        let surface = s?.imessageSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.imessage_path_plane"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "imessage_path_plane_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.messagesAppPaths + s.messagesDbPaths + s.messagesPrefPaths).prefix(10) {
                evidence.append(Evidence(type: "imessage_path_plane_path", path: path, detail: "iMessage path plane path"))
            }
            for n in s.notes.prefix(4) { evidence.append(Evidence(type: "imessage_path_plane_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never reads Messages database contents or exports chat transcripts."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "iMessage path plane with remote amplifier" : "iMessage / Messages path collection plane",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1114", "T1005", "T1539"],
            remediation: [
                "Inventory and baseline iMessage path plane paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never reads Messages database contents or exports chat transcripts",
            ],
            falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
