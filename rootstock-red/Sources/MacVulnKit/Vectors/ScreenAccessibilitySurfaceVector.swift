import Foundation
import RootstockCore

/// Path-to-impact: Screen Recording / Accessibility TCC dual-use surface (non-prompting).
///
/// Research basis: LOOBins screencapture; public TCC screen/accessibility abuse themes.
/// Safety and behavior: notes + planner tccImpact + loobin presence only; never prompts TCC dialogs.
public struct ScreenAccessibilitySurfaceVector: Check {
    public static let id = "rootstock.vector.tcc.screen_accessibility_surface"
    public static let cost: CollectorCost = .low

    private static let screenKeywords = [
        "screen recording", "screen_recording", "screencapture", "screen capture",
        "capture screen", "display capture",
    ]
    private static let accessibilityKeywords = [
        "accessibility", "ax_", "trusted accessibility", "assistive",
    ]

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        var evidence: [Evidence] = []
        var signals: [String] = []

        // Collector force for tests / future collectors.
        var forceNotes: [String] = []
        if let note = state.collectorNotes["tcc.screen_accessibility"] {
            forceNotes = note.split(separator: "|").map {
                String($0).trimmingCharacters(in: .whitespaces)
            }.filter { !$0.isEmpty }
            signals.append("collector_force")
            for n in forceNotes.prefix(12) {
                evidence.append(Evidence(type: "collector_note", detail: n))
            }
        }

        // TCC state notes looking for screen / accessibility keywords.
        let tccNotes = state.tcc?.notes ?? []
        let matchedNotes = tccNotes.filter { note in
            let lower = note.lowercased()
            return Self.screenKeywords.contains { lower.contains($0) }
                || Self.accessibilityKeywords.contains { lower.contains($0) }
        }
        if !matchedNotes.isEmpty {
            signals.append("tcc_notes")
            for note in matchedNotes.prefix(12) {
                evidence.append(Evidence(type: "tcc_note", detail: note))
            }
        }

        // lolPlans with Screen Recording / Accessibility TCC impact.
        let impactPlans = state.lolPlans.filter { plan in
            plan.tccImpact.contains { impact in
                let lower = impact.lowercased()
                return lower.contains("screen") || lower.contains("accessibility")
            }
        }
        if !impactPlans.isEmpty {
            signals.append("lol_plans_tcc")
            for plan in impactPlans.prefix(10) {
                evidence.append(
                    Evidence(
                        type: "planner_tcc",
                        path: plan.path,
                        detail:
                            "\(plan.name) noise=\(plan.noiseScore) "
                            + "tcc=\(plan.tccImpact.joined(separator: ",")) · \(plan.rankReason)"
                    )
                )
            }
        }

        // screencapture LOOBin present.
        let screencapture = state.loobins.first {
            $0.present && $0.name.lowercased() == "screencapture"
        }
        if let sc = screencapture {
            signals.append("screencapture_loobin")
            evidence.append(
                Evidence(
                    type: "loobin",
                    path: sc.path,
                    detail: "screencapture tactics=\(sc.tactics.joined(separator: ","))"
                )
            )
        }

        guard !signals.isEmpty else { return [] }

        // Quieter alternatives for discovery-style goals (OPSEC ranking).
        let quieter = state.lolPlans
            .filter { $0.goal == "discovery" || $0.goal == "execute" }
            .sorted { $0.noiseScore < $1.noiseScore }
        for entry in quieter.prefix(6) {
            evidence.append(
                Evidence(
                    type: "planner_alt",
                    path: entry.path,
                    detail:
                        "\(entry.name) noise=\(entry.noiseScore) "
                        + "tcc=\(entry.tccImpact.joined(separator: ","))"
                )
            )
        }

        evidence.insert(
            Evidence(
                type: "summary",
                detail:
                    "signals=\(signals.joined(separator: ",")) "
                    + "tccNoteHits=\(matchedNotes.count) impactPlans=\(impactPlans.count) "
                    + "screencapture=\(screencapture != nil) forced=\(!forceNotes.isEmpty) "
                    + "(non-prompting - no TCC dialogs forced)"
            ),
            at: 0
        )
        evidence.append(
            Evidence(
                type: "tcc_honesty",
                detail:
                    "Screen Recording and Accessibility often require user prompts or prior grants; "
                    + "Rootstock Red assess uses non-prompting inventory only"
            )
        )

        let multi = signals.count >= 2 || (!forceNotes.isEmpty && screencapture != nil)
        let severity: Severity = multi ? .medium : .low
        let title: String
        if screencapture != nil && (!impactPlans.isEmpty || !matchedNotes.isEmpty) {
            title = "Screen/Accessibility TCC surface: screencapture + TCC impact signals"
        } else if screencapture != nil {
            title = "Screen capture dual-use surface: screencapture present (TCC-honest)"
        } else if !forceNotes.isEmpty {
            title = "Screen/Accessibility surface: collector-forced TCC signals"
        } else {
            title = "Screen Recording / Accessibility TCC surface signals present"
        }

        var tccDomains: [String] = []
        if screencapture != nil
            || impactPlans.contains(where: {
                $0.tccImpact.contains { $0.localizedCaseInsensitiveContains("screen") }
            })
            || matchedNotes.contains(where: { $0.localizedCaseInsensitiveContains("screen") })
        {
            tccDomains.append("ScreenRecording")
        }
        if impactPlans.contains(where: {
            $0.tccImpact.contains { $0.localizedCaseInsensitiveContains("accessibility") }
        })
            || matchedNotes.contains(where: {
                $0.localizedCaseInsensitiveContains("accessibility")
            })
        {
            tccDomains.append("Accessibility")
        }
        if tccDomains.isEmpty {
            tccDomains = ["ScreenRecording", "Accessibility"]
        }

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: severity,
                confidence: multi ? .medium : .low,
                category: .tcc,
                evidence: evidence,
                attackTechniques: ["T1113", "T1056.002", "T1222"],
                remediation: [
                    "Review Screen Recording and Accessibility grants in System Settings → Privacy & Security",
                    "Prefer PPPC profiles for approved assistive / remote-support tools only",
                    "Monitor screencapture and Accessibility API abuse via EDR/ESF",
                    "OPSEC: assess is non-prompting - never force Screen Recording / Accessibility dialogs",
                ],
                falsePositiveNotes:
                    "screencapture ships with macOS; presence alone is dual-use ranking, not malware. "
                    + "TCC grant state is not fully enumerable without privileged/TCC.db access.",
                dryRunSafe: true,
                opsecScore: multi ? 45 : 30,
                tccDomains: tccDomains,
                esfExpected: ["OPEN", "EXEC", "USER_PROMPT"]
            ),
        ]
    }
}
