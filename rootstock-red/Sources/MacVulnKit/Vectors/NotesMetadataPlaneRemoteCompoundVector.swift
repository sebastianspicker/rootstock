import Foundation
import RootstockCore

/// Wave-14 compound: Notes metadata plane × remote/FDA path-to-impact.
public struct NotesMetadataPlaneRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.data.notes_metadata_plane_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.notesMetadataPlane
        let a = s?.notesAppPaths.count ?? 0
        let b = s?.notesStorePaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        let sensorThin = state.esf?.clientPaths.isEmpty == true || state.securityProducts.filter(\.present).isEmpty
        guard remote || fda || sensorThin || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "notes_metadata_plane_compound", detail: "a=\(a) b=\(b) remote=\(remote) fda=\(fda) sensorThin=\(sensorThin)"),
        ]
        if let s {
            for path in (s.notesAppPaths + s.notesStorePaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Notes metadata plane compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never reads Notes body contents or exports note secrets."))
        let severity: Severity = (remote && fda) ? .high : ((remote || fda || sensorThin) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Notes metadata plane × remote compound" : "Notes metadata plane × impact compound",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1005", "T1114", "T1552"],
            remediation: [
                "Prioritize hosts co-locating Notes metadata plane with remote/FDA amplifiers",
                "Use Wave-14 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ],
            falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first.",
            dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]
        )]
    }
}
