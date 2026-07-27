import Foundation
import RootstockCore

/// Path-to-impact: browser extension dual-use persistence / collection plane.
///
/// Research basis: broad-permission extension persistence (2025–26 browser malware).
/// Safety and behavior: multi-browser path plane + FDA/remote; never dumps extension secrets.
public struct BrowserExtensionDualUseVector: Check {
    public static let id = "rootstock.vector.persist.browser_extension_dualuse"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let be = state.browserExtensionDualUse
        let chromium = be?.chromiumExtensionPaths.count ?? 0
        let safari = be?.safariExtensionPaths.count ?? 0
        let prefs = be?.preferencePaths.count ?? 0
        let total = chromium + safari
        let surface = be?.extensionSurfacePresent == true || total >= 1 || prefs >= 2
        let note = state.collectorNotes["collect.browser_extension_dualuse"] != nil
        guard surface || note else { return [] }
        guard total >= 1 || prefs >= 2 else { return [] }

        let fda = state.tcc?.fullDiskAccessLikely == true
        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true

        var evidence: [Evidence] = [
            Evidence(
                type: "browser_extension_summary",
                detail:
                    "chromium=\(chromium) safari=\(safari) prefs=\(prefs) fda=\(fda) remote=\(remote)"
            ),
        ]
        if let be {
            for path in (be.chromiumExtensionPaths + be.safariExtensionPaths + be.preferencePaths).prefix(12) {
                evidence.append(Evidence(type: "extension_path", path: path, detail: "extension dual-use path (meta only)"))
            }
            for n in be.notes.prefix(6) {
                evidence.append(Evidence(type: "extension_note", detail: n))
            }
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Assess never dumps extension storage, cookies, tokens, or passwords from browser profiles."
            )
        )

        let severity: Severity
        if fda && total >= 2 && remote {
            severity = .high
        } else if fda || (chromium >= 1 && safari >= 1) || total >= 2 {
            severity = .medium
        } else {
            severity = .low
        }

        return [
            Finding(
                id: Self.id,
                title: fda
                    ? "Browser extension dual-use plane under likely Full Disk Access"
                    : "Browser extension dual-use persistence / collection plane",
                severity: severity,
                confidence: .medium,
                category: .misconfig,
                evidence: evidence,
                attackTechniques: ["T1176", "T1555.003", "T1005"],
                remediation: [
                    "Inventory browser extensions via MDM/EDR; remove unapproved extensions",
                    "Restrict enterprise extension allowlists; monitor broad host/permission grants",
                    "Correlate extension install times with phishing delivery",
                    "OPSEC: Rootstock Red does not dump extension secrets or cookies",
                ],
                falsePositiveNotes:
                    "Enterprise browsers often ship approved extensions. Elevate multi-browser roots under FDA/remote.",
                dryRunSafe: true,
                opsecScore: 26,
                esfExpected: ["OPEN", "READ"]
            ),
        ]
    }
}
