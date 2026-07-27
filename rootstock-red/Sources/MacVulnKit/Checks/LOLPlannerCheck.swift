import Foundation
import RootstockCore

/// Surfaces ranked LOOBin plans (noise-ascending) for assess purple-team notes.
public struct LOLPlannerCheck: Check {
    public static let id = "rootstock.check.lool.planner"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let plans = state.lolPlans
        guard !plans.isEmpty else {
            // Inventory may exist without plan goals matching present bins.
            guard !state.loobins.isEmpty else { return [] }
            return [
                Finding(
                    id: "\(Self.id).empty",
                    title: "LOL planner produced no ranked entries",
                    severity: .info,
                    confidence: .low,
                    category: .lool,
                    evidence: [
                        Evidence(
                            type: "note",
                            detail:
                                "loobins=\(state.loobins.count) present=\(state.loobins.filter(\.present).count); "
                                + "no discovery/persist/execute plan rows"
                        ),
                    ],
                    attackTechniques: ["T1218"],
                    remediation: ["Expand LOOBin catalog tactics mapping"],
                    dryRunSafe: true,
                    opsecScore: 4
                ),
            ]
        }

        let byGoal = Dictionary(grouping: plans, by: \.goal)
        var evidence: [Evidence] = []
        for goal in ["discovery", "persist", "execute", "exfil", "download"] {
            guard let rows = byGoal[goal], !rows.isEmpty else { continue }
            let summary = rows
                .sorted { $0.noiseScore < $1.noiseScore }
                .prefix(5)
                .map { "\($0.name)@\($0.noiseScore)" }
                .joined(separator: ", ")
            evidence.append(
                Evidence(type: "plan_goal", detail: "\(goal): \(summary)")
            )
        }
        for entry in plans.prefix(25) {
            let tcc = entry.tccImpact.isEmpty ? "none" : entry.tccImpact.joined(separator: ",")
            evidence.append(
                Evidence(
                    type: "plan_entry",
                    path: entry.path,
                    detail:
                        "goal=\(entry.goal) noise=\(entry.noiseScore) tcc=\(tcc) · \(entry.rankReason)"
                )
            )
        }

        let quietest = plans.min(by: { $0.noiseScore < $1.noiseScore })
        let loudest = plans.max(by: { $0.noiseScore < $1.noiseScore })
        let title =
            "LOL planner: \(plans.count) ranked entries "
            + "(quietest \(quietest?.name ?? "?")@\(quietest?.noiseScore ?? 0), "
            + "loudest \(loudest?.name ?? "?")@\(loudest?.noiseScore ?? 0))"

        var techniques = Set(["T1218", "T1059", "T1082"])
        if plans.contains(where: { $0.goal == "persist" }) {
            techniques.insert("T1543.001")
        }
        if plans.contains(where: { !$0.tccImpact.isEmpty }) {
            techniques.insert("T1222")
        }

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: .info,
                confidence: .high,
                category: .lool,
                evidence: evidence,
                attackTechniques: Array(techniques).sorted(),
                remediation: [
                    "Prefer quieter LOOBins for lab discovery (lower noiseScore)",
                    "Avoid high-TCC tools (screencapture / osascript) without consent",
                ],
                falsePositiveNotes: "Ranking is heuristic; not an execution plan or endorsement",
                dryRunSafe: true,
                opsecScore: 6,
                esfExpected: []
            ),
        ]
    }
}
