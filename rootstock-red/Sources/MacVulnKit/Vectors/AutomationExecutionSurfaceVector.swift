import Foundation
import RootstockCore

/// Path-to-impact: AppleScript/Automation / AppleEvents execution surface (TCC-honest).
///
/// Research basis: LOOBins osascript, PersistentJXA, Empire OSX scripting modules.
/// Safety and behavior: ranks quieter planner alternatives; never claims silent Automation; no JXA runtime.
public struct AutomationExecutionSurfaceVector: Check {
    public static let id = "rootstock.vector.tcc.automation_execution_surface"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let osa = state.loobins.first {
            $0.present && $0.name.lowercased() == "osascript"
        }
        let autoPlans = state.lolPlans.filter {
            $0.tccImpact.contains { $0.localizedCaseInsensitiveContains("automation") }
                || $0.name.lowercased() == "osascript"
                || $0.goal == "execute"
        }
        let hasAutomationTCC = autoPlans.contains {
            $0.tccImpact.contains { $0.localizedCaseInsensitiveContains("automation") }
        }

        guard osa != nil || hasAutomationTCC || autoPlans.contains(where: { $0.name.lowercased() == "osascript" })
        else { return [] }

        var evidence: [Evidence] = [
            Evidence(
                type: "summary",
                detail:
                    "osascriptPresent=\(osa != nil) automationTaggedPlans=\(autoPlans.filter { !$0.tccImpact.isEmpty }.count) "
                    + "executePlans=\(autoPlans.filter { $0.goal == "execute" }.count)"
            ),
        ]
        if let osa {
            evidence.append(
                Evidence(
                    type: "loobin",
                    path: osa.path,
                    detail: "osascript tactics=\(osa.tactics.joined(separator: ","))"
                )
            )
        }
        let quieter = state.lolPlans
            .filter { $0.goal == "execute" || $0.goal == "discovery" }
            .sorted { $0.noiseScore < $1.noiseScore }
        for entry in quieter.prefix(8) {
            evidence.append(
                Evidence(
                    type: "planner_alt",
                    path: entry.path,
                    detail: "\(entry.name) noise=\(entry.noiseScore) tcc=\(entry.tccImpact.joined(separator: ",")) · \(entry.rankReason)"
                )
            )
        }
        evidence.append(
            Evidence(
                type: "tcc_honesty",
                detail:
                    "Automation/AppleEvents often prompts the user on modern macOS - "
                    + "silent JXA execution claims are false without prior TCC grants"
            )
        )

        let loud = autoPlans.contains { $0.noiseScore >= 70 || $0.name.lowercased() == "osascript" }
        let severity: Severity = loud ? .medium : .low
        let title: String
        if osa != nil && loud {
            title = "Automation execution surface: osascript present (high user-prompt / TCC risk)"
        } else {
            title = "Automation / AppleEvents execution surface with planner alternatives"
        }

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: severity,
                confidence: .high,
                category: .tcc,
                evidence: evidence,
                attackTechniques: ["T1059.002", "T1059", "T1559"],
                remediation: [
                    "Prefer quieter LOOBin planner entries over osascript for authorized discovery",
                    "Review Automation TCC grants in System Settings → Privacy & Security",
                    "Monitor osascript process trees and AppleEvents via EDR/ESF",
                    "OPSEC: Automation is user-visible noise - Rootstock Red does not run JXA payloads in assess",
                ],
                falsePositiveNotes:
                    "osascript ships with macOS; presence is expected. Finding is dual-use ranking, not malware.",
                dryRunSafe: true,
                opsecScore: loud ? 60 : 35,
                tccDomains: ["Automation"],
                esfExpected: ["OPEN", "EXEC", "USER_PROMPT"]
            ),
        ]
    }
}
