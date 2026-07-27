import Foundation
import RootstockCore

/// Path-to-impact: HomeKit residual path plane.
public struct HomekitPathPlaneVector: Check {
    public static let id = "rootstock.vector.data.homekit_path_plane"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.homekitPathPlane
        let a = s?.homeAppPaths.count ?? 0
        let b = s?.homeKitStorePaths.count ?? 0
        let c = s?.homedPaths.count ?? 0
        let surface = s?.homekitSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.homekit_path_plane"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "homekit_path_plane_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.homeAppPaths + s.homeKitStorePaths + s.homedPaths).prefix(10) {
                evidence.append(Evidence(type: "homekit_path_plane_path", path: path, detail: "HomeKit path plane path"))
            }
            for n in s.notes.prefix(4) { evidence.append(Evidence(type: "homekit_path_plane_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never enumerates HomeKit accessory secrets or pairs devices."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "HomeKit path plane with remote amplifier" : "HomeKit residual path plane",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T0883", "T1005", "T1083"],
            remediation: [
                "Inventory and baseline HomeKit path plane paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never enumerates HomeKit accessory secrets or pairs devices",
            ],
            falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
