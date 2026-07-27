import Foundation
import RootstockCore

/// Path-to-impact: Spotlight importer residual depth.
public struct SpotlightImporterDepthVector: Check {
    public static let id = "rootstock.vector.data.spotlight_importer_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.spotlightImporterDepth
        let a = s?.metadataToolPaths.count ?? 0
        let b = s?.spotlightImporterPaths.count ?? 0
        let c = s?.mdsLaunchPaths.count ?? 0
        let surface = s?.spotlightImporterSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.spotlight_importer_depth"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "spotlight_importer_depth_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.metadataToolPaths + s.spotlightImporterPaths + s.mdsLaunchPaths).prefix(10) {
                evidence.append(Evidence(type: "spotlight_importer_depth_path", path: path, detail: "Spotlight importer depth path"))
            }
            for n in s.notes.prefix(4) { evidence.append(Evidence(type: "spotlight_importer_depth_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never installs malicious Spotlight importers or dumps mdworker index contents."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Spotlight importer depth with remote amplifier" : "Spotlight importer residual depth",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1083", "T1005", "T1213"],
            remediation: [
                "Inventory and baseline Spotlight importer depth paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never installs malicious Spotlight importers or dumps mdworker index contents",
            ],
            falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
