import Foundation
import RootstockCore

/// Wave-14 compound: QuickLook cache depth × remote/FDA path-to-impact.
public struct QuicklookCacheDepthRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.data.quicklook_cache_depth_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.quicklookCacheDepth
        let a = s?.quicklookDaemonPaths.count ?? 0
        let b = s?.thumbnailCachePaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        let sensorThin = state.esf?.clientPaths.isEmpty == true || state.securityProducts.filter(\.present).isEmpty
        guard remote || fda || sensorThin || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "quicklook_cache_depth_compound", detail: "a=\(a) b=\(b) remote=\(remote) fda=\(fda) sensorThin=\(sensorThin)"),
        ]
        if let s {
            for path in (s.quicklookDaemonPaths + s.thumbnailCachePaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "QuickLook cache depth compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never dumps QuickLook thumbnail bitmap contents as secret material."))
        let severity: Severity = (remote && fda) ? .high : ((remote || fda || sensorThin) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "QuickLook cache depth × remote compound" : "QuickLook cache depth × impact compound",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1005", "T1083", "T1552"],
            remediation: [
                "Prioritize hosts co-locating QuickLook cache depth with remote/FDA amplifiers",
                "Use Wave-14 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ],
            falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first.",
            dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]
        )]
    }
}
