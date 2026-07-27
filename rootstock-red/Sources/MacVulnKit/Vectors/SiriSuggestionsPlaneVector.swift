import Foundation
import RootstockCore

/// Path-to-impact: Siri / Suggestions data-access residual.
public struct SiriSuggestionsPlaneVector: Check {
    public static let id = "rootstock.vector.data.siri_suggestions_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.siriSuggestionsPlane
        let a = s?.siriFrameworkPaths.count ?? 0
        let b = s?.suggestionsStorePaths.count ?? 0
        let c = s?.siriPrefPaths.count ?? 0
        let surface = s?.siriSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.siri_suggestions_plane"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "siri_suggestions_plane_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.siriFrameworkPaths + s.suggestionsStorePaths + s.siriPrefPaths).prefix(10) {
                evidence.append(Evidence(type: "siri_suggestions_plane_path", path: path, detail: "Siri Suggestions residual path"))
            }
            for n in s.notes.prefix(4) { evidence.append(Evidence(type: "siri_suggestions_plane_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never dumps Siri transcripts or Suggestions databases contents."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Siri Suggestions residual with remote amplifier" : "Siri / Suggestions data-access residual",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1005", "T1083", "T1213"],
            remediation: [
                "Inventory and baseline Siri Suggestions residual paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never dumps Siri transcripts or Suggestions databases contents",
            ],
            falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
