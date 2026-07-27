import Foundation
import RootstockCore

/// Path-to-impact: App sandbox container residual depth.
public struct SandboxContainerDepthVector: Check {
    public static let id = "rootstock.vector.sandbox.sandbox_container_depth"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.sandboxContainerDepth
        let a = s?.containerRootPaths.count ?? 0
        let b = s?.sandboxProfilePaths.count ?? 0
        let c = s?.seatbeltSupportPaths.count ?? 0
        let surface = s?.sandboxSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.sandbox_container_depth"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "sandbox_container_depth_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.containerRootPaths + s.sandboxProfilePaths + s.seatbeltSupportPaths).prefix(12) {
                evidence.append(Evidence(type: "sandbox_container_depth_path", path: path, detail: "Sandbox container depth path"))
            }
            for n in s.notes.prefix(5) { evidence.append(Evidence(type: "sandbox_container_depth_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never breaks app sandbox or forges container entitlements."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Sandbox container depth with remote amplifier" : "App sandbox container residual depth",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1611", "T1083", "T1005"],
            remediation: [
                "Inventory and baseline Sandbox container depth paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never breaks app sandbox or forges container entitlements",
            ],
            falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
