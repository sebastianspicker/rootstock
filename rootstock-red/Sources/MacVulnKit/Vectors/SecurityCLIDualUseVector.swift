import Foundation
import RootstockCore

/// Path-to-impact: high-utility security/trust CLI dual-use surface (security, codesign, spctl, xattr).
///
/// Research basis: LOOBins security(1) / codesign recon; public macOS trust-chain tooling themes.
/// Safety and behavior: requires ≥2 high-utility CLIs or security+codesign pair; ranks quieter planner alts.
public struct SecurityCLIDualUseVector: Check {
    public static let id = "rootstock.vector.lool.security_cli_dual_use"
    public static let cost: CollectorCost = .low

    /// High-utility security/trust CLIs for dual-use ranking.
    private static let securityCLINames: Set<String> = [
        "security", "codesign", "spctl", "xattr",
    ]

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let present = state.loobins.filter {
            $0.present && Self.securityCLINames.contains($0.name.lowercased())
        }
        let names = Set(present.map { $0.name.lowercased() })

        let hasSecurity = names.contains("security")
        let hasCodesign = names.contains("codesign")
        let pair = hasSecurity && hasCodesign
        let cluster = present.count >= 2

        guard pair || cluster else { return [] }

        var evidence: [Evidence] = [
            Evidence(
                type: "summary",
                detail:
                    "securityCLIs=\(present.map(\.name).sorted().joined(separator: ",")) "
                    + "count=\(present.count) security+codesign=\(pair)"
            ),
        ]
        if pair {
            evidence.append(
                Evidence(
                    type: "chain",
                    detail:
                        "security + codesign both present - classic trust/keychain recon dual-use pair"
                )
            )
        }
        for bin in present.sorted(by: { $0.name < $1.name }).prefix(10) {
            evidence.append(
                Evidence(
                    type: "security_cli",
                    path: bin.path,
                    detail: "\(bin.name) tactics=\(bin.tactics.joined(separator: ","))"
                )
            )
        }

        // Prefer quieter planner alternatives as evidence (discovery / execute ranking).
        let quieter = state.lolPlans
            .filter {
                $0.goal == "discovery" || $0.goal == "execute"
                    || Self.securityCLINames.contains($0.name.lowercased())
            }
            .sorted { $0.noiseScore < $1.noiseScore }
        if quieter.isEmpty {
            evidence.append(
                Evidence(
                    type: "planner",
                    detail: "lolPlans empty - rank stock CLI presence only; prefer low-noise discovery later"
                )
            )
        } else {
            let summary = quieter.prefix(8).map { "\($0.name)@\($0.noiseScore)/\($0.goal)" }
                .joined(separator: ", ")
            evidence.append(
                Evidence(
                    type: "quieter_alternatives",
                    detail: "planner quieter-first: \(summary)"
                )
            )
            for entry in quieter.prefix(10) {
                evidence.append(
                    Evidence(
                        type: "plan_entry",
                        path: entry.path,
                        detail:
                            "goal=\(entry.goal) noise=\(entry.noiseScore) · \(entry.rankReason)"
                    )
                )
            }
        }

        evidence.append(
            Evidence(
                type: "opsec_honesty",
                detail:
                    "security/codesign/spctl/xattr are stock dual-use tools - assess inventories only; "
                    + "does not dump keychains, strip quarantine, or disable Gatekeeper"
            )
        )

        let severity: Severity = pair && present.count >= 3 ? .medium : .low
        let title: String
        if pair && names.contains("spctl") {
            title = "Security CLI dual-use: security + codesign + spctl trust-chain toolkit"
        } else if pair {
            title = "Security CLI dual-use: security + codesign pair present"
        } else {
            title =
                "Security CLI dual-use surface (\(present.count): "
                + present.map(\.name).sorted().joined(separator: ", ") + ")"
        }

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: severity,
                confidence: .high,
                category: .lool,
                evidence: evidence,
                attackTechniques: ["T1518", "T1082", "T1553"],
                remediation: [
                    "For authorized recon prefer quieter planner discovery bins over security dump-* patterns",
                    "Monitor anomalous security(1)/codesign/spctl process trees and Gatekeeper policy changes",
                    "Alert on mass xattr quarantine clears and unexpected spctl --master-disable class activity",
                    "OPSEC: dual-use CLI presence is expected on macOS; rank quieter alternatives first",
                ],
                falsePositiveNotes:
                    "security, codesign, spctl, and xattr ship with macOS. Finding is dual-use chain ranking, "
                    + "not malware or misconfiguration by itself.",
                dryRunSafe: true,
                opsecScore: pair ? 28 : 22,
                esfExpected: ["OPEN", "EXEC"]
            ),
        ]
    }
}
