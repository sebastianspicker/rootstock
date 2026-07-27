import Foundation
import RootstockCore

/// Path-to-impact: Notes.app metadata collection path plane.
public struct NotesMetadataPlaneVector: Check {
    public static let id = "rootstock.vector.data.notes_metadata_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.notesMetadataPlane
        let a = s?.notesAppPaths.count ?? 0
        let b = s?.notesStorePaths.count ?? 0
        let c = s?.notesContainerPaths.count ?? 0
        let surface = s?.notesSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.notes_metadata_plane"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "notes_metadata_plane_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.notesAppPaths + s.notesStorePaths + s.notesContainerPaths).prefix(12) {
                evidence.append(Evidence(type: "notes_metadata_plane_path", path: path, detail: "Notes metadata plane path"))
            }
            for n in s.notes.prefix(5) { evidence.append(Evidence(type: "notes_metadata_plane_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never reads Notes body contents or exports note secrets."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Notes metadata plane with remote amplifier" : "Notes.app metadata collection path plane",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1005", "T1114", "T1552"],
            remediation: [
                "Inventory and baseline Notes metadata plane paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never reads Notes body contents or exports note secrets",
            ],
            falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
