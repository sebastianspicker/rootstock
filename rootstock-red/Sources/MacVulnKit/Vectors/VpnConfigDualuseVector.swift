import Foundation
import RootstockCore

/// Path-to-impact: VPN configuration dual-use residual surface.
public struct VpnConfigDualuseVector: Check {
    public static let id = "rootstock.vector.network.vpn_config_dualuse"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.vpnConfigDualuse
        let a = s?.vpnFrameworkPaths.count ?? 0
        let b = s?.vpnPrefPaths.count ?? 0
        let c = s?.vpnToolPaths.count ?? 0
        let surface = s?.vpnSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.vpn_config_dualuse"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "vpn_config_dualuse_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.vpnFrameworkPaths + s.vpnPrefPaths + s.vpnToolPaths).prefix(12) {
                evidence.append(Evidence(type: "vpn_config_dualuse_path", path: path, detail: "VPN config dual-use path"))
            }
            for n in s.notes.prefix(5) { evidence.append(Evidence(type: "vpn_config_dualuse_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never installs VPN profiles or rewrites network extension VPN configs."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "VPN config dual-use with remote amplifier" : "VPN configuration dual-use residual surface",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1133", "T1572", "T1048"],
            remediation: [
                "Inventory and baseline VPN config dual-use paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never installs VPN profiles or rewrites network extension VPN configs",
            ],
            falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
