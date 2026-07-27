/// Cluster/check: TCCPreflightCheck - multi-signal posture ranking for assess pipeline.
import Foundation
import RootstockCore

public struct TCCPreflightCheck: Check {
    public static let id = "rootstock.check.tcc.preflight_summary"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard let tcc = state.tcc else { return [] }

        var evidence = tcc.notes.map { Evidence(type: "tcc_note", detail: $0) }
        evidence.append(Evidence(type: "probe", detail: "method=\(tcc.probeMethod)"))

        let fdaDetail: String
        let title: String
        let severity: Severity
        let confidence: Confidence
        var remediation: [String] = [
            "Non-prompting assess probes only - Rootstock Red will not trigger TCC dialogs in audit mode",
            "Map TCC domains (FDA, Screen Recording, Accessibility) before deeper collection",
        ]

        switch tcc.fullDiskAccessLikely {
        case .some(true):
            fdaDetail = "fullDiskAccessLikely=true"
            title = "TCC preflight: Full Disk Access appears granted (heuristic)"
            severity = .info
            confidence = .medium
            remediation.insert(
                "FDA-capable context increases sensitivity of path reads; keep scope ROE-bound",
                at: 0
            )
        case .some(false):
            fdaDetail = "fullDiskAccessLikely=false"
            title = "TCC preflight: Full Disk Access not indicated"
            severity = .info
            confidence = .low
            remediation.insert(
                "Without FDA, many user TCC-protected paths will be denied - treat denials as data",
                at: 0
            )
        case .none:
            fdaDetail = "fullDiskAccessLikely=unknown"
            title = "TCC preflight: FDA status unknown (non-prompting probe)"
            severity = .info
            confidence = .low
            remediation.insert(
                "FDA unknown - do not assume access; collectors record TCC denials in deniedCollectors",
                at: 0
            )
        }
        evidence.append(Evidence(type: "fda", detail: fdaDetail))

        if !state.deniedCollectors.isEmpty {
            evidence.append(
                Evidence(
                    type: "denied_collectors",
                    detail: state.deniedCollectors.sorted().joined(separator: ",")
                )
            )
        }

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: severity,
                confidence: confidence,
                category: .tcc,
                evidence: evidence,
                attackTechniques: ["T1069", "T1005"],
                remediation: remediation,
                falsePositiveNotes:
                    "User TCC.db readability and path heuristics are incomplete on enterprise fleets; "
                    + "false positives/negatives expected without Privacy Preferences Policy Control (PPPC) context",
                dryRunSafe: true,
                opsecScore: 12,
                tccDomains: ["FullDiskAccess"],
                esfExpected: ["OPEN"]
            ),
        ]
    }
}
