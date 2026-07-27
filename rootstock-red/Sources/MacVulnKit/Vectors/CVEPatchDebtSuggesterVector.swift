import Foundation
import RootstockCore

/// CVE / patch-debt suggester - exploitability context, not an exploit pack.
///
/// Research basis: PEASS version checks; compliance "days behind" scanners.
/// Safety and behavior: typed PatchDebtState; major-version lag + SUS presence; low confidence by
/// default; never downloads or runs exploits; language is suggester-only.
public struct CVEPatchDebtSuggesterVector: Check {
    public static let id = "rootstock.vector.cve.patch_debt_suggester"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let debt = state.patchDebt
        let hostVersion = debt?.osVersion ?? state.host?.osVersion
        guard hostVersion != nil || debt != nil else { return [] }

        let lag = debt?.majorVersionLag ?? 0
        let sus = debt?.softwareUpdatePlistPresent
        let forceNote = state.collectorNotes["cve.patch_debt"] != nil
        var parsedMajor: Int?
        if let v = hostVersion?.split(separator: ".").first, let m = Int(v) {
            parsedMajor = m
        }
        let effectiveLag: Int = {
            if lag > 0 { return lag }
            if let m = parsedMajor {
                return max(0, PatchDebtCollectorKnownCurrent.major - m)
            }
            return 0
        }()

        let fireLag = effectiveLag >= 1 || forceNote
        let fireHygiene =
            debt != nil
            && sus == false
            && (state.network?.remoteLoginSSH == true || state.identity?.adBound == true)
        guard fireLag || fireHygiene else { return [] }

        var evidence: [Evidence] = [
            Evidence(
                type: "os",
                detail:
                    "osVersion=\(hostVersion ?? "unknown") "
                    + "build=\(debt?.osBuild ?? state.host?.osBuild ?? "unknown") "
                    + "majorVersionLag=\(effectiveLag)"
            ),
            Evidence(
                type: "suggester_honesty",
                detail:
                    "This finding is patch-debt context only. It does not prove a specific CVE "
                    + "is exploitable on this host and does not include exploit code."
            ),
        ]
        if let debt {
            evidence.append(
                Evidence(
                    type: "sus",
                    detail: "softwareUpdatePlistPresent=\(debt.softwareUpdatePlistPresent.rootstockDescribe)"
                )
            )
            for hint in debt.lastUpdateHints.prefix(8) {
                evidence.append(Evidence(type: "update_hint", detail: hint))
            }
            for note in debt.notes.prefix(10) {
                evidence.append(Evidence(type: "note", detail: note))
            }
        }
        if remoteOrIdentity(state) {
            evidence.append(
                Evidence(
                    type: "compound",
                    detail: "Remote and/or enterprise identity increases priority of patch hygiene"
                )
            )
        }

        // Class-level suggestions (not CVE IDs with false certainty).
        if effectiveLag >= 2 {
            evidence.append(
                Evidence(
                    type: "class_suggestion",
                    detail:
                        "Multi-major lag may increase exposure to historical local-privilege and "
                        + "sandbox escape classes already patched on current majors - verify with "
                        + "vendor advisories for this exact build."
                )
            )
        } else if effectiveLag == 1 {
            evidence.append(
                Evidence(
                    type: "class_suggestion",
                    detail:
                        "One major behind baseline: prioritize security updates; map build to "
                        + "Apple security updates before assuming exploitability."
                )
            )
        }

        let severity: Severity
        let title: String
        if effectiveLag >= 2 {
            severity = .medium
            title = "Patch-debt suggester: OS major lag \(effectiveLag) (CVE class context only)"
        } else if effectiveLag == 1 {
            severity = .low
            title = "Patch-debt suggester: OS one major behind baseline"
        } else {
            severity = .low
            title = "Patch-debt suggester: update hygiene gap (SUS prefs absent)"
        }

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: severity,
                confidence: .low,
                category: .cve,
                evidence: evidence,
                attackTechniques: ["T1082", "T1203", "T1068"],
                remediation: [
                    "Apply latest security updates via MDM / Software Update for this hardware class",
                    "Map ProductBuildVersion to Apple security content before claiming exploitability",
                    "Prioritize internet-facing and remotely accessible hosts first",
                    "OPSEC: assess does not fetch exploit PoCs or weaponize CVEs",
                ],
                falsePositiveNotes:
                    "Known-current major baseline is product-maintained and may lag Apple's newest release. "
                    + "Managed freeze windows can intentionally lag majors.",
                dryRunSafe: true,
                opsecScore: 8,
                esfExpected: ["OPEN"],
                osRange: hostVersion
            ),
        ]
    }

    private func remoteOrIdentity(_ state: CollectedState) -> Bool {
        state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
            || state.identity?.adBound == true
            || state.identity?.platformSSO == true
    }

}

/// Mirrors `PatchDebtCollector.knownCurrentMajor` for evaluate() without importing MacEnumKit cycles.
enum PatchDebtCollectorKnownCurrent {
    static let major = 15
}
