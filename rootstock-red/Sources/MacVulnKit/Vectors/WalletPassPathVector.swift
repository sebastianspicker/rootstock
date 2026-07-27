import Foundation
import RootstockCore

/// Path-to-impact: Wallet / pass residual path plane.
public struct WalletPassPathVector: Check {
    public static let id = "rootstock.vector.data.wallet_pass_path"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.walletPassPath
        let a = s?.walletAppPaths.count ?? 0
        let b = s?.passesStorePaths.count ?? 0
        let c = s?.passdPaths.count ?? 0
        let surface = s?.walletSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.wallet_pass_path"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "wallet_pass_path_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.walletAppPaths + s.passesStorePaths + s.passdPaths).prefix(10) {
                evidence.append(Evidence(type: "wallet_pass_path_path", path: path, detail: "Wallet pass path path"))
            }
            for n in s.notes.prefix(4) { evidence.append(Evidence(type: "wallet_pass_path_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never dumps pass contents, payment tokens, or card data."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Wallet pass path with remote amplifier" : "Wallet / pass residual path plane",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1005", "T1555", "T1083"],
            remediation: [
                "Inventory and baseline Wallet pass path paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never dumps pass contents, payment tokens, or card data",
            ],
            falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
