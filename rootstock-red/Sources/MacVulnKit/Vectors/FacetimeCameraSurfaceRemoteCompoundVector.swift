import Foundation
import RootstockCore

/// Wave-16 compound: FaceTime camera dual-use × remote/FDA path-to-impact.
public struct FacetimeCameraSurfaceRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.data.facetime_camera_surface_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.facetimeCameraSurface
        let a = s?.facetimeAppPaths.count ?? 0
        let b = s?.avConferencePaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        let sensorThin = state.esf?.clientPaths.isEmpty == true || state.securityProducts.filter(\.present).isEmpty
        guard remote || fda || sensorThin || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "facetime_camera_surface_compound", detail: "a=\(a) b=\(b) remote=\(remote) fda=\(fda) sensorThin=\(sensorThin)"),
        ]
        if let s {
            for path in (s.facetimeAppPaths + s.avConferencePaths).prefix(6) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "FaceTime camera dual-use compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never activates camera/mic or dumps FaceTime call history contents."))
        let severity: Severity = (remote && fda) ? .high : ((remote || fda || sensorThin) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "FaceTime camera dual-use × remote compound" : "FaceTime camera dual-use × impact compound",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1125", "T1123", "T1113"],
            remediation: [
                "Prioritize hosts co-locating FaceTime camera dual-use with remote/FDA amplifiers",
                "Use Wave-16 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ],
            falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first.",
            dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]
        )]
    }
}
