import Foundation
import RootstockCore

/// Wave-16 compound: File Provider domain × remote/FDA path-to-impact.
public struct FileproviderDomainRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.data.fileprovider_domain_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.fileproviderDomain
        let a = s?.fileProviderFrameworkPaths.count ?? 0
        let b = s?.cloudStoragePaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        let sensorThin = state.esf?.clientPaths.isEmpty == true || state.securityProducts.filter(\.present).isEmpty
        guard remote || fda || sensorThin || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "fileprovider_domain_compound", detail: "a=\(a) b=\(b) remote=\(remote) fda=\(fda) sensorThin=\(sensorThin)"),
        ]
        if let s {
            for path in (s.fileProviderFrameworkPaths + s.cloudStoragePaths).prefix(6) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "File Provider domain compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never registers malicious File Provider domains or exfiltrates provider caches."))
        let severity: Severity = (remote && fda) ? .high : ((remote || fda || sensorThin) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "File Provider domain × remote compound" : "File Provider domain × impact compound",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1080", "T1530", "T1005"],
            remediation: [
                "Prioritize hosts co-locating File Provider domain with remote/FDA amplifiers",
                "Use Wave-16 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ],
            falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first.",
            dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]
        )]
    }
}
