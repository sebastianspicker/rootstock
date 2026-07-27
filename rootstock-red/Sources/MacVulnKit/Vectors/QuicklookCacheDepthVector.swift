import Foundation
import RootstockCore

/// Path-to-impact: QuickLook thumbnail cache residual depth.
public struct QuicklookCacheDepthVector: Check {
    public static let id = "rootstock.vector.data.quicklook_cache_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.quicklookCacheDepth
        let a = s?.quicklookDaemonPaths.count ?? 0
        let b = s?.thumbnailCachePaths.count ?? 0
        let c = s?.qlmanagePaths.count ?? 0
        let surface = s?.quicklookSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.quicklook_cache_depth"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "quicklook_cache_depth_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.quicklookDaemonPaths + s.thumbnailCachePaths + s.qlmanagePaths).prefix(12) {
                evidence.append(Evidence(type: "quicklook_cache_depth_path", path: path, detail: "QuickLook cache depth path"))
            }
            for n in s.notes.prefix(5) { evidence.append(Evidence(type: "quicklook_cache_depth_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never dumps QuickLook thumbnail bitmap contents as secret material."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "QuickLook cache depth with remote amplifier" : "QuickLook thumbnail cache residual depth",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1005", "T1083", "T1552"],
            remediation: [
                "Inventory and baseline QuickLook cache depth paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never dumps QuickLook thumbnail bitmap contents as secret material",
            ],
            falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
