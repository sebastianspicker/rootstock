import Foundation
import RootstockCore

/// Path-to-impact: multi-domain TCC permission graph depth (beyond FDA-only).
///
/// Research basis: SwiftBelt domain probes; Screen/AX/Automation research.
/// Safety and behavior: graph of domain signals with compound severity; no TCC.db dump; no prompts.
public struct TCCPermissionGraphDepthVector: Check {
    public static let id = "rootstock.vector.tcc.permission_graph_depth"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        guard let tcc = state.tcc else { return [] }
        let signals = tcc.domainSignals
        // Need multi-domain graph (not just FDA pivot - that is a separate vector).
        guard signals.count >= 2 || state.collectorNotes["collect.tcc_permission_graph"] != nil else {
            return []
        }

        let joined = signals.joined(separator: ";")
        let fdaLikely = tcc.fullDiskAccessLikely == true
            || signals.contains { $0.localizedCaseInsensitiveContains("FullDiskAccess=likely") }
        let automation = signals.contains { $0.localizedCaseInsensitiveContains("Automation=osascript_present") }
        let screen = signals.contains {
            $0.localizedCaseInsensitiveContains("ScreenCapture=tool_present")
                || $0.localizedCaseInsensitiveContains("screen_recording=tool_present")
        }
        let filesFolders = signals.contains {
            $0.contains("FilesAndFolders=") && !$0.contains("none_listable")
        }

        // Path-to-impact: require compound of ≥2 interesting domains or FDA+another.
        let interestingCount =
            (fdaLikely ? 1 : 0)
            + (automation ? 1 : 0)
            + (screen ? 1 : 0)
            + (filesFolders ? 1 : 0)
        guard interestingCount >= 2 || (fdaLikely && !signals.isEmpty) || signals.count >= 4 else {
            return []
        }

        var evidence: [Evidence] = [
            Evidence(type: "probe", detail: "method=\(tcc.probeMethod)"),
            Evidence(type: "domain_graph", detail: joined.isEmpty ? "(from notes)" : joined),
        ]
        for sig in signals.prefix(16) {
            evidence.append(Evidence(type: "domain_signal", detail: sig))
        }
        for note in tcc.notes.prefix(10) {
            evidence.append(Evidence(type: "tcc_note", detail: note))
        }
        if state.browserMeta.contains(where: \.exists) || state.credPaths.contains(where: \.exists) {
            evidence.append(
                Evidence(
                    type: "pivot_targets",
                    detail:
                        "browserMetaPresent=\(state.browserMeta.filter(\.exists).count) "
                        + "credPathsPresent=\(state.credPaths.filter(\.exists).count) "
                        + "(metadata only - no secret material)"
                )
            )
        }

        var domains: [String] = []
        if fdaLikely { domains.append("FullDiskAccess") }
        if automation { domains.append("Automation") }
        if screen { domains.append("ScreenCapture") }
        if filesFolders { domains.append("FilesAndFolders") }

        let severity: Severity
        let title: String
        if fdaLikely && (automation || screen) {
            severity = .high
            title = "TCC graph depth: FDA plus Automation/Screen domain signals"
        } else if interestingCount >= 3 {
            severity = .medium
            title = "TCC graph depth: multi-domain permission surface (\(interestingCount) domains)"
        } else {
            severity = .low
            title = "TCC permission graph surface (\(signals.count) domain signals)"
        }

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: severity,
                confidence: .medium,
                category: .tcc,
                evidence: evidence,
                attackTechniques: ["T1069", "T1005", "T1113", "T1059.002", "T1083"],
                remediation: [
                    "Review System Settings → Privacy & Security grants per domain (FDA, Automation, Screen, AX)",
                    "Deploy PPPC profiles for enterprise allowlists; revoke unexpected grants",
                    "Treat multi-domain grant combinations as higher impact than single booleans",
                    "OPSEC: assess uses non-prompting probes only - never force TCC dialogs",
                ],
                falsePositiveNotes:
                    "Domain signals are heuristics (tool presence / path listability), not live TCC.db grants. "
                    + "MDM PPPC may grant outside user-visible settings.",
                dryRunSafe: true,
                opsecScore: fdaLikely ? 38 : 24,
                tccDomains: domains.isEmpty ? ["FullDiskAccess"] : domains,
                esfExpected: ["OPEN"]
            ),
        ]
    }
}
