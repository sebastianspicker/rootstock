import Foundation
import RootstockCore

/// Wave-10 compound depth: third-party extractor × quarantine / Gatekeeper posture.
///
/// Research basis: Unit 42 / Jamf archive extractor Gatekeeper non-inheritance research.
/// Safety and behavior: extractor × (GK-off | quarantine hits | archive drops); never strips quarantine.
public struct ExtractorQuarantineCompoundVector: Check {
    public static let id = "rootstock.vector.codesign.extractor_quarantine_compound"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let aq = state.archiveQuarantineExtractor
        let third = aq?.thirdPartyExtractorPaths.count ?? 0
        let stock = aq?.stockExtractorPaths.count ?? 0
        let drops = aq?.archiveDropHints.count ?? 0

        // Extractor plane: third-party paths non-empty OR extractorSurfacePresent.
        let extractorPresent = third >= 1 || aq?.extractorSurfacePresent == true
        guard extractorPresent else { return [] }

        let gkOff = state.protections?.gatekeeperEnabled == false
        let quarantineHits =
            state.collectorNotes.keys.contains { $0.contains("quarantine") }
            || state.collectorNotes["codesign.quarantine_hits"] != nil
        let dropHintsPresent = drops >= 1

        // Compound gate: extractor plane AND (GK off OR quarantine hits OR archive drop hints).
        guard gkOff || quarantineHits || dropHintsPresent else { return [] }

        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true

        var evidence: [Evidence] = [
            Evidence(
                type: "extractor_quarantine_compound_summary",
                detail:
                    "thirdParty=\(third) stock=\(stock) drops=\(drops) "
                    + "gkOff=\(gkOff) quarantineHits=\(quarantineHits) remote=\(remote)"
            ),
        ]
        if let aq {
            for path in aq.thirdPartyExtractorPaths.prefix(8) {
                evidence.append(
                    Evidence(type: "third_party_extractor", path: path, detail: "quarantine non-inheritance risk class")
                )
            }
            for path in aq.archiveDropHints.prefix(4) {
                evidence.append(Evidence(type: "archive_drop_hint", path: path, detail: "drop/download path"))
            }
            for n in aq.notes.prefix(4) {
                evidence.append(Evidence(type: "extractor_note", detail: n))
            }
        }
        if quarantineHits {
            evidence.append(
                Evidence(
                    type: "compound_quarantine_note",
                    detail: "collectorNotes include quarantine-related keys (path/meta only)"
                )
            )
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Assess never strips com.apple.quarantine, never crafts clever archives, "
                    + "never delivers Gatekeeper bypass recipes. Path-to-impact narrative only."
            )
        )

        let severity: Severity
        if third >= 1 && gkOff && remote {
            severity = .high
        } else if third >= 1 && (gkOff || quarantineHits) {
            severity = .medium
        } else {
            severity = .low
        }

        return [
            Finding(
                id: Self.id,
                title: gkOff
                    ? "Third-party archive extractors compound with Gatekeeper-off posture"
                    : "Archive extractor × quarantine / drop-hint compound",
                severity: severity,
                confidence: .medium,
                category: .misconfig,
                evidence: evidence,
                attackTechniques: ["T1204", "T1553.001", "T1036"],
                remediation: [
                    "Prefer Archive Utility / managed extractors that preserve quarantine attributes",
                    "Train users against unpacking untrusted archives with third-party tools when GK is weak",
                    "Monitor process trees where extractors write into Downloads then spawn unsigned apps",
                    "OPSEC: Rootstock Red does not strip quarantine xattrs or craft bypass archives",
                ],
                falsePositiveNotes:
                    "Stock tar/unzip ship with macOS. Elevate when third-party extractors co-present "
                    + "with Gatekeeper-off, quarantine collector hits, or archive drop paths.",
                dryRunSafe: true,
                opsecScore: 20,
                esfExpected: ["OPEN", "WRITE", "EXEC"]
            ),
        ]
    }
}
