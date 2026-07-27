import Foundation
import RootstockCore

/// Path-to-impact: Keychain ACL path residual surface.
public struct KeychainAclPathVector: Check {
    public static let id = "rootstock.vector.data.keychain_acl_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.keychainAclPath
        let a = s?.keychainDbPaths.count ?? 0
        let b = s?.securityToolPaths.count ?? 0
        let c = s?.keychainSupportPaths.count ?? 0
        let surface = s?.keychainAclSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.keychain_acl_path"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "keychain_acl_path_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.keychainDbPaths + s.securityToolPaths + s.keychainSupportPaths).prefix(12) {
                evidence.append(Evidence(type: "keychain_acl_path_path", path: path, detail: "Keychain ACL path plane path"))
            }
            for n in s.notes.prefix(5) { evidence.append(Evidence(type: "keychain_acl_path_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never dumps keychain items, passwords, or private keys."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Keychain ACL path plane with remote amplifier" : "Keychain ACL path residual surface",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1555.001", "T1555", "T1003"],
            remediation: [
                "Inventory and baseline Keychain ACL path plane paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never dumps keychain items, passwords, or private keys",
            ],
            falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
