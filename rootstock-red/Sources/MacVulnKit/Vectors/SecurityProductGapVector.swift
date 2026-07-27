import Foundation
import RootstockCore

/// Path-to-impact: missing or thin security-product / EDR coverage with elevated host surface.
///
/// Research basis: PEASS “security software” noise + red-team OPSEC product discovery.
/// Safety and behavior: fires only with supporting path-to-impact (remote/weak prot/inject/high-value);
/// honest that path heuristics miss many agents; not a claim of “undetectable.”
public struct SecurityProductGapVector: Check {
    public static let id = "rootstock.vector.edr.security_product_gap"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let present = state.securityProducts.filter(\.present)
        let absentCatalog = state.securityProducts.filter { !$0.present }

        // Gap = no present products, or only zero present while catalog was probed empty.
        let noCoverage = present.isEmpty
        // Thin coverage: collector ran but found nothing present (explicit empty or all false).
        guard noCoverage || state.securityProducts.isEmpty else {
            // Products present - only fire if all known are absent and notes claim gap (skip).
            return []
        }

        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
            || state.network?.fileSharingSMB == true
        let weakProt =
            state.protections?.sipEnabled == false
            || state.protections?.gatekeeperEnabled == false
            || state.protections?.fileVaultOn == false
        let inject = state.injectabilityHits.contains { !$0.riskFlags.isEmpty }
        let highValue =
            state.credPaths.contains(where: \.exists)
            || state.browserMeta.contains(where: \.exists)
            || state.identity?.adBound == true
            || state.identity?.platformSSO == true

        // Require supporting surface so home Macs without EDR aren't pure rainbow.
        guard remote || weakProt || inject || highValue else { return [] }

        var evidence: [Evidence] = [
            Evidence(
                type: "edr_summary",
                detail:
                    "securityProductsPresent=\(present.count) catalogEntries=\(state.securityProducts.count) "
                    + "absentNamed=\(absentCatalog.count) (path heuristic only)"
            ),
        ]
        for p in state.securityProducts.prefix(20) {
            evidence.append(
                Evidence(
                    type: "product_probe",
                    path: p.path,
                    detail: "name=\(p.name) present=\(p.present)"
                )
            )
        }
        if remote {
            evidence.append(Evidence(type: "supporting", detail: "remote/sharing posture elevated"))
        }
        if weakProt {
            evidence.append(Evidence(type: "supporting", detail: "protections weak/disabled"))
        }
        if inject {
            evidence.append(Evidence(type: "supporting", detail: "injectability risk flags present"))
        }
        if highValue {
            evidence.append(Evidence(type: "supporting", detail: "high-value identity/cred/browser surface"))
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Missing path hits ≠ no EDR (system extensions, hidden agents, MDM-managed tools common)"
            )
        )

        let severity: Severity = (remote && weakProt) || (noCoverage && inject) ? .medium : .low
        let title: String
        if noCoverage && remote {
            title = "EDR/security-product gap: no path hits with remote access surface"
        } else if noCoverage && weakProt {
            title = "EDR/security-product gap: no path hits with weak protections"
        } else {
            title = "EDR/security-product coverage thin or undetected with supporting attack surface"
        }

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: severity,
                confidence: .low,
                category: .securityProduct,
                evidence: evidence,
                attackTechniques: ["T1518.001", "T1562.001", "T1082"],
                remediation: [
                    "Confirm endpoint security via MDM inventory and System Extension lists - not only path probes",
                    "Deploy managed EDR/XDR on high-value and remotely accessible hosts",
                    "Treat assess OPSEC carefully when coverage is unknown (assume ESF consumers exist)",
                    "OPSEC: this finding is a coverage gap signal for operators, not a stealth claim",
                ],
                falsePositiveNotes:
                    "Many commercial agents use non-catalog paths or pure system extensions. "
                    + "False negatives expected; verify with enterprise inventory before remediating.",
                dryRunSafe: true,
                opsecScore: 12,
                esfExpected: ["OPEN"]
            ),
        ]
    }
}
