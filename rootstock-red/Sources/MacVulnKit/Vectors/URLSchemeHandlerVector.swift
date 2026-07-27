import Foundation
import RootstockCore

/// Path-to-impact: custom URL scheme / document-handler delivery surface.
///
/// Research basis: LS handlers / CFBundleURLTypes delivery themes (2025–26).
/// Safety and behavior: opener × LaunchServices compounds; never registers schemes.
public struct URLSchemeHandlerVector: Check {
    public static let id = "rootstock.vector.delivery.url_scheme_handler"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let uh = state.urlSchemeHandler
        let ls = uh?.launchServicesPaths.count ?? 0
        let urlTypes = uh?.urlTypePlistPaths.count ?? 0
        let openers = uh?.openerBinaryPaths.count ?? 0
        let docs = uh?.documentHandlerPaths.count ?? 0
        let surface = uh?.handlerSurfacePresent == true || ls + urlTypes + openers >= 3
        let note = state.collectorNotes["collect.url_scheme_handler"] != nil
        guard surface || note else { return [] }
        guard ls >= 1 || (openers >= 2 && urlTypes >= 1) else { return [] }

        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        let gkOff = state.protections?.gatekeeperEnabled == false

        var evidence: [Evidence] = [
            Evidence(
                type: "url_scheme_summary",
                detail:
                    "launchServices=\(ls) urlTypes=\(urlTypes) docs=\(docs) openers=\(openers) "
                    + "remote=\(remote) gkOff=\(gkOff)"
            ),
        ]
        if let uh {
            for path in (uh.launchServicesPaths + uh.urlTypePlistPaths + uh.openerBinaryPaths).prefix(12) {
                evidence.append(Evidence(type: "handler_path", path: path, detail: "URL/document handler path"))
            }
            for n in uh.notes.prefix(6) {
                evidence.append(Evidence(type: "handler_note", detail: n))
            }
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Assess never registers CFBundleURLTypes, never rewrites LaunchServices handlers, "
                    + "and never crafts malicious URL schemes."
            )
        )

        let severity: Severity
        if remote && (gkOff || openers >= 3) && ls >= 1 {
            severity = .high
        } else if remote || gkOff || (ls >= 1 && openers >= 2) {
            severity = .medium
        } else {
            severity = .low
        }

        return [
            Finding(
                id: Self.id,
                title: remote
                    ? "URL scheme / document-handler surface with remote access amplifier"
                    : "Custom URL scheme / document-handler delivery surface",
                severity: severity,
                confidence: .medium,
                category: .misconfig,
                evidence: evidence,
                attackTechniques: ["T1204", "T1546", "T1559"],
                remediation: [
                    "Inventory non-default CFBundleURLTypes / document handlers via MDM compliance checks",
                    "Monitor LaunchServices handler changes after software installs",
                    "Restrict untrusted apps that register custom URL schemes",
                    "OPSEC: Rootstock Red does not register schemes or rewrite handlers",
                ],
                falsePositiveNotes:
                    "Safari/Terminal/open exist on typical Macs. Elevate when handler DB co-presents with remote access or Gatekeeper-off.",
                dryRunSafe: true,
                opsecScore: 24,
                esfExpected: ["OPEN", "EXEC"]
            ),
        ]
    }
}
