import Foundation
import RootstockCore

/// Path-to-impact: DNS resolver / mDNSResponder dual-use surface.
public struct DnsResolverDualuseVector: Check {
    public static let id = "rootstock.vector.network.dns_resolver_dualuse"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.dnsResolverDualuse
        let a = s?.mdnsResponderPaths.count ?? 0
        let b = s?.resolverConfigPaths.count ?? 0
        let c = s?.dnsToolPaths.count ?? 0
        let surface = s?.dnsSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.dns_resolver_dualuse"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "dns_resolver_dualuse_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.mdnsResponderPaths + s.resolverConfigPaths + s.dnsToolPaths).prefix(12) {
                evidence.append(Evidence(type: "dns_resolver_dualuse_path", path: path, detail: "DNS resolver dual-use path"))
            }
            for n in s.notes.prefix(5) { evidence.append(Evidence(type: "dns_resolver_dualuse_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never rewrites resolver config or poisons DNS caches."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "DNS resolver dual-use with remote amplifier" : "DNS resolver / mDNSResponder dual-use surface",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1071.004", "T1568", "T1040"],
            remediation: [
                "Inventory and baseline DNS resolver dual-use paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never rewrites resolver config or poisons DNS caches",
            ],
            falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
