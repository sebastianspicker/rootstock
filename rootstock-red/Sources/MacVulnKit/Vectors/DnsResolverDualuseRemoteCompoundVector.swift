import Foundation
import RootstockCore

/// Wave-14 compound: DNS resolver dual-use × remote/FDA path-to-impact.
public struct DnsResolverDualuseRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.network.dns_resolver_dualuse_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.dnsResolverDualuse
        let a = s?.mdnsResponderPaths.count ?? 0
        let b = s?.resolverConfigPaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        let sensorThin = state.esf?.clientPaths.isEmpty == true || state.securityProducts.filter(\.present).isEmpty
        guard remote || fda || sensorThin || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "dns_resolver_dualuse_compound", detail: "a=\(a) b=\(b) remote=\(remote) fda=\(fda) sensorThin=\(sensorThin)"),
        ]
        if let s {
            for path in (s.mdnsResponderPaths + s.resolverConfigPaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "DNS resolver dual-use compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never rewrites resolver config or poisons DNS caches."))
        let severity: Severity = (remote && fda) ? .high : ((remote || fda || sensorThin) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "DNS resolver dual-use × remote compound" : "DNS resolver dual-use × impact compound",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1071.004", "T1568", "T1040"],
            remediation: [
                "Prioritize hosts co-locating DNS resolver dual-use with remote/FDA amplifiers",
                "Use Wave-14 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ],
            falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first.",
            dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]
        )]
    }
}
