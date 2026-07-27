import Foundation
import RootstockCore

/// Path-to-impact: Full Disk Access / TCC posture as a data-access and lateral pivot.
///
/// Emits one ranked vector with ATT&CK mappings, non-prompting probes, and
/// remediation. It does not dump TCC databases.
public struct TCCFDAPermissionPivotVector: Check {
    public static let id = "rootstock.vector.tcc.fda_permission_pivot"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard let tcc = state.tcc else { return [] }

        let fda = tcc.fullDiskAccessLikely
        let denied = state.deniedCollectors
        let notes = tcc.notes

        // Fire when FDA is indicated, explicitly false with denials (friction pivot),
        // or unknown with supporting high-value path signals.
        let hasCredOrBrowser =
            state.credPaths.contains(where: \.exists)
            || state.browserMeta.contains(where: \.exists)
        let hasSensitiveContext = hasCredOrBrowser || !denied.isEmpty

        switch fda {
        case .some(true):
            break // always path-to-impact when FDA likely
        case .some(false):
            guard hasSensitiveContext else { return [] }
        case .none:
            guard hasSensitiveContext else { return [] }
        }

        var evidence: [Evidence] = [
            Evidence(type: "probe", detail: "method=\(tcc.probeMethod)"),
            Evidence(
                type: "fda",
                detail: "fullDiskAccessLikely=\(fda.rootstockDescribe)"
            ),
        ]
        for note in notes.prefix(12) {
            evidence.append(Evidence(type: "tcc_note", detail: note))
        }
        if !denied.isEmpty {
            evidence.append(
                Evidence(
                    type: "denied_collectors",
                    detail: denied.sorted().joined(separator: ",")
                )
            )
        }
        if hasCredOrBrowser {
            evidence.append(
                Evidence(
                    type: "pivot_targets",
                    detail:
                        "credPathsPresent=\(state.credPaths.filter(\.exists).count) "
                        + "browserMetaPresent=\(state.browserMeta.filter(\.exists).count) "
                        + "(path metadata only - no secret/cookie material)"
                )
            )
        }

        let severity: Severity
        let confidence: Confidence
        let title: String
        let opsec: Int
        switch fda {
        case .some(true):
            severity = .high
            confidence = .medium
            title = "TCC pivot: Full Disk Access likely - broad user-data access surface"
            opsec = 35
        case .some(false):
            severity = .medium
            confidence = .medium
            title = "TCC friction pivot: FDA not indicated while sensitive paths/collectors constrained"
            opsec = 22
        case .none:
            severity = .low
            confidence = .low
            title = "TCC posture unknown with sensitive path-to-impact signals present"
            opsec = 18
        }

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: severity,
                confidence: confidence,
                category: .tcc,
                evidence: evidence,
                attackTechniques: ["T1069", "T1005", "T1530", "T1083"],
                remediation: [
                    "Revoke unexpected Full Disk Access grants in System Settings → Privacy & Security",
                    "Prefer PPPC configuration profiles for enterprise allowlists over ad-hoc FDA",
                    "Treat FDA-capable tools as high-value; monitor OPEN of TCC-protected roots",
                    "OPSEC: Rootstock Red uses non-prompting probes only - never force TCC dialogs in assess",
                ],
                falsePositiveNotes:
                    "FDA heuristics (path listability) are incomplete; enterprise PPPC/MDM may grant "
                    + "or deny outside user TCC.db visibility. Presence of deniedCollectors is expected without FDA.",
                dryRunSafe: true,
                opsecScore: opsec,
                tccDomains: ["FullDiskAccess"],
                esfExpected: ["OPEN"]
            ),
        ]
    }

}
