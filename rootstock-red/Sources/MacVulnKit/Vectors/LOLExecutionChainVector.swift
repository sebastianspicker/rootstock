import Foundation
import RootstockCore

/// Living-off-the-land execution chain: high-utility bins + quieter planner alternatives.
public struct LOLExecutionChainVector: Check {
    public static let id = "rootstock.vector.lool.execution_chain"
    public static let cost: CollectorCost = .low

    /// Dual-use binaries that commonly form execution / persist chains.
    private static let highUtilityNames: Set<String> = [
        "osascript", "launchctl", "screencapture", "security", "sqlite3", "mdfind",
    ]

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let present = state.loobins.filter(\.present)
        let presentNames = Set(present.map { $0.name.lowercased() })
        let highUtility = present.filter { Self.highUtilityNames.contains($0.name.lowercased()) }

        let hasOsascript = presentNames.contains("osascript")
        let hasLaunchctl = presentNames.contains("launchctl")
        let chainPair = hasOsascript && hasLaunchctl
        let hasHighUtilityCluster = highUtility.count >= 2

        // Prefer planner-backed evidence; fall back to raw inventory.
        let plans = state.lolPlans
        guard chainPair || hasHighUtilityCluster || (!plans.isEmpty && !highUtility.isEmpty) else {
            return []
        }

        var evidence: [Evidence] = []
        if chainPair {
            evidence.append(
                Evidence(
                    type: "chain",
                    detail: "osascript + launchctl both present - classic execute → persist chain"
                )
            )
        }

        for bin in highUtility.prefix(15) {
            evidence.append(
                Evidence(
                    type: "high_utility_loobin",
                    path: bin.path,
                    detail: "\(bin.name) tactics=\(bin.tactics.joined(separator: ","))"
                )
            )
        }

        // Quieter alternatives from planner ranking (noise ascending).
        let quieter = plans
            .filter { $0.goal == "discovery" || $0.goal == "execute" || $0.goal == "persist" }
            .sorted { $0.noiseScore < $1.noiseScore }
        if quieter.isEmpty {
            evidence.append(
                Evidence(
                    type: "planner",
                    detail: "lolPlans empty - prefer inventory noise heuristics over loud bins"
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

        // Loud members of the chain for OPSEC honesty.
        let loudPlans = plans.filter { $0.noiseScore >= 70 }.sorted { $0.noiseScore > $1.noiseScore }
        if !loudPlans.isEmpty {
            evidence.append(
                Evidence(
                    type: "loud_bins",
                    detail:
                        "high noise in chain: "
                        + loudPlans.prefix(5).map { "\($0.name)@\($0.noiseScore)" }
                        .joined(separator: ", ")
                )
            )
        }

        let severity: Severity = chainPair ? .medium : .low
        let title: String
        if chainPair {
            title = "LOL execution chain: osascript + launchctl (prefer quieter planner bins)"
        } else {
            title =
                "LOL high-utility surface (\(highUtility.count) dual-use bins) with planner alternatives"
        }

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: severity,
                confidence: .high,
                category: .lool,
                evidence: evidence,
                attackTechniques: ["T1059.002", "T1059", "T1543.001", "T1218"],
                remediation: [
                    "For authorized discovery, prefer lower-noise planner entries (system_profiler/mdfind/codesign)",
                    "Avoid osascript/screencapture without consent - TCC + high ESF noise",
                    "Monitor launchctl load/bootstrap and osascript process trees via EDR",
                    "OPSEC: chain findings rank quieter LOOBins first; do not default to rainbow dumps",
                ],
                falsePositiveNotes:
                    "Stock Apple dual-use binaries are expected; finding is chain utility, not malware",
                dryRunSafe: true,
                opsecScore: chainPair ? 55 : 35,
                tccDomains: hasOsascript ? ["Automation"] : [],
                esfExpected: ["OPEN", "EXEC"]
            ),
        ]
    }
}
