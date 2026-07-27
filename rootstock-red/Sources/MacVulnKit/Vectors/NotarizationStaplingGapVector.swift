import Foundation
import RootstockCore

/// Path-to-impact: notarization / stapling trust-depth gap.
///
/// Research basis: Gatekeeper + notarization checklists.
/// Safety and behavior: distinct from GK on/off; compounds delivery artifacts; no bypass pack.
public struct NotarizationStaplingGapVector: Check {
    public static let id = "rootstock.vector.notarization.stapling_gap"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let ns = state.notarizationStapling
        let tools = ns?.toolingPaths.count ?? 0
        let delivery = ns?.unstapledOrAdHocHints.count ?? 0
        let note = state.collectorNotes["collect.notarization_stapling"] != nil
        let gkOff = state.protections?.gatekeeperEnabled == false
        let unsigned = state.codesignSamples.filter { $0.signed == false }.count
        let quarantineNote = state.collectorNotes.keys.contains { $0.contains("quarantine") }

        let surface = tools > 0 || delivery > 0 || note || unsigned > 0
        guard surface else { return [] }

        // Path-to-impact: delivery artifacts, GK off, unsigned samples, or quarantine compound
        let pathToImpact =
            delivery > 0
            || gkOff
            || unsigned > 0
            || quarantineNote
            || (tools > 0 && (state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true))
        guard pathToImpact else { return [] }

        var evidence: [Evidence] = [
            Evidence(
                type: "notarization_summary",
                detail:
                    "tooling=\(tools) deliveryHints=\(delivery) unsignedSamples=\(unsigned) "
                    + "gatekeeperEnabled=\((state.protections?.gatekeeperEnabled).rootstockDescribe) "
                    + "assessmentTools=\((ns?.assessmentToolsPresent).rootstockDescribe)"
            ),
        ]
        if let ns {
            for path in (ns.toolingPaths + ns.unstapledOrAdHocHints).prefix(12) {
                evidence.append(Evidence(type: "notarization_path", path: path, detail: "tooling or delivery hint"))
            }
            for n in ns.notes.prefix(6) {
                evidence.append(Evidence(type: "notarization_note", detail: n))
            }
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Assess never forges notarization tickets, strips staples, or provides Gatekeeper bypass recipes."
            )
        )

        let severity: Severity
        if gkOff && (delivery > 0 || unsigned > 0) {
            severity = .medium
        } else if delivery >= 3 || unsigned >= 2 {
            severity = .medium
        } else {
            severity = .low
        }

        return [
            Finding(
                id: Self.id,
                title: gkOff
                    ? "Notarization/stapling trust-depth gap with Gatekeeper disabled"
                    : "Notarization / stapling / delivery-trust surface",
                severity: severity,
                confidence: .low,
                category: .codesign,
                evidence: evidence,
                attackTechniques: ["T1553.001", "T1204.002", "T1036"],
                remediation: [
                    "Require Developer ID + notarization + stapling for fleet software distribution",
                    "Block ad-hoc unsigned tools on managed endpoints where policy requires it",
                    "Educate users on unsolicited DMG/PKG from Downloads",
                    "OPSEC: this finding ranks delivery trust - it is not a bypass toolkit",
                ],
                falsePositiveNotes:
                    "Downloads folders commonly hold archives. Prefer compounds with GK-off or unsigned samples.",
                dryRunSafe: true,
                opsecScore: 16,
                esfExpected: ["OPEN"]
            ),
        ]
    }

}
