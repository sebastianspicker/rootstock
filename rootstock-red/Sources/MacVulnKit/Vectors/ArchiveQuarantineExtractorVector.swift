import Foundation
import RootstockCore

/// Path-to-impact: third-party archive extractor quarantine non-inheritance surface.
///
/// Research basis: Unit 42 / Jamf archive extractor Gatekeeper research.
/// Safety and behavior: typed compound with GK/remote; never strips quarantine or crafts bypass archives.
public struct ArchiveQuarantineExtractorVector: Check {
    public static let id = "rootstock.vector.codesign.archive_quarantine_extractor"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let aq = state.archiveQuarantineExtractor
        let third = aq?.thirdPartyExtractorPaths.count ?? 0
        let stock = aq?.stockExtractorPaths.count ?? 0
        let drops = aq?.archiveDropHints.count ?? 0
        let surface = aq?.extractorSurfacePresent == true || third > 0 || stock >= 3
        let note = state.collectorNotes["collect.archive_quarantine_extractor"] != nil

        guard surface || note else { return [] }
        guard third >= 1 || stock >= 2 else { return [] }

        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        let gkOff = state.protections?.gatekeeperEnabled == false

        var evidence: [Evidence] = [
            Evidence(
                type: "extractor_summary",
                detail:
                    "thirdParty=\(third) stock=\(stock) drops=\(drops) remote=\(remote) gkOff=\(gkOff)"
            ),
        ]
        if let aq {
            for path in (aq.thirdPartyExtractorPaths + aq.stockExtractorPaths).prefix(12) {
                evidence.append(Evidence(type: "extractor_path", path: path, detail: "archive extractor"))
            }
            for n in aq.notes.prefix(6) {
                evidence.append(Evidence(type: "extractor_note", detail: n))
            }
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Assess never strips com.apple.quarantine, never crafts clever archives, "
                    + "never delivers Gatekeeper bypass recipes."
            )
        )

        let severity: Severity
        if third >= 1 && (gkOff || remote) {
            severity = .high
        } else if third >= 1 || (stock >= 3 && gkOff) {
            severity = .medium
        } else {
            severity = .low
        }

        return [
            Finding(
                id: Self.id,
                title: third >= 1
                    ? "Third-party archive extractors expand quarantine non-inheritance surface"
                    : "Archive extractor / quarantine inheritance posture",
                severity: severity,
                confidence: .medium,
                category: .misconfig,
                evidence: evidence,
                attackTechniques: ["T1204", "T1553.001", "T1036"],
                remediation: [
                    "Prefer Archive Utility / managed extractors that preserve quarantine attributes",
                    "Train users against unpacking untrusted archives from email/web with third-party tools",
                    "Monitor process trees where extractors write into Downloads then spawn unsigned apps",
                    "OPSEC: Rootstock Red does not craft bypass archives or strip quarantine xattrs",
                ],
                falsePositiveNotes:
                    "Stock tar/unzip/ditto ship with macOS. Elevate priority when third-party extractors "
                    + "co-present with Gatekeeper-off or remote access.",
                dryRunSafe: true,
                opsecScore: 18,
                esfExpected: ["OPEN", "WRITE", "EXEC"]
            ),
        ]
    }
}
