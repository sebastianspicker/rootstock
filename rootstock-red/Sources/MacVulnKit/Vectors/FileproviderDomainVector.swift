import Foundation
import RootstockCore

/// Path-to-impact: File Provider domain residual surface.
public struct FileproviderDomainVector: Check {
    public static let id = "rootstock.vector.data.fileprovider_domain"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.fileproviderDomain
        let a = s?.fileProviderFrameworkPaths.count ?? 0
        let b = s?.cloudStoragePaths.count ?? 0
        let c = s?.fileProviderLaunchPaths.count ?? 0
        let surface = s?.fileProviderSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.fileprovider_domain"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "fileprovider_domain_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.fileProviderFrameworkPaths + s.cloudStoragePaths + s.fileProviderLaunchPaths).prefix(10) {
                evidence.append(Evidence(type: "fileprovider_domain_path", path: path, detail: "File Provider domain path"))
            }
            for n in s.notes.prefix(4) { evidence.append(Evidence(type: "fileprovider_domain_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never registers malicious File Provider domains or exfiltrates provider caches."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "File Provider domain with remote amplifier" : "File Provider domain residual surface",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1080", "T1530", "T1005"],
            remediation: [
                "Inventory and baseline File Provider domain paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never registers malicious File Provider domains or exfiltrates provider caches",
            ],
            falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
