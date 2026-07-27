import Foundation
import RootstockCore

/// Path-to-impact: FaceTime / camera pipeline dual-use surface.
public struct FacetimeCameraSurfaceVector: Check {
    public static let id = "rootstock.vector.data.facetime_camera_surface"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.facetimeCameraSurface
        let a = s?.facetimeAppPaths.count ?? 0
        let b = s?.avConferencePaths.count ?? 0
        let c = s?.facetimePrefPaths.count ?? 0
        let surface = s?.facetimeSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.facetime_camera_surface"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "facetime_camera_surface_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.facetimeAppPaths + s.avConferencePaths + s.facetimePrefPaths).prefix(10) {
                evidence.append(Evidence(type: "facetime_camera_surface_path", path: path, detail: "FaceTime camera dual-use path"))
            }
            for n in s.notes.prefix(4) { evidence.append(Evidence(type: "facetime_camera_surface_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never activates camera/mic or dumps FaceTime call history contents."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "FaceTime camera dual-use with remote amplifier" : "FaceTime / camera pipeline dual-use surface",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1125", "T1123", "T1113"],
            remediation: [
                "Inventory and baseline FaceTime camera dual-use paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never activates camera/mic or dumps FaceTime call history contents",
            ],
            falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
