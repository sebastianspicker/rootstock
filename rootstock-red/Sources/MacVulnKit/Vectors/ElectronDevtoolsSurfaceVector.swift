import Foundation
import RootstockCore

/// Path-to-impact: Electron / Chromium devtools and inspect-style LOOL surface.
///
/// Research basis: DEF CON / public Electron+TCC research themes; LOOBins dual-use apps.
/// Safety and behavior: runningApps + path heuristics only; no remote-debug attach; ATT&CK + OPSEC.
public struct ElectronDevtoolsSurfaceVector: Check {
    public static let id = "rootstock.vector.lool.electron_devtools_surface"
    public static let cost: CollectorCost = .low

    private static let electronHints = [
        "electron", "chrome", "chromium", "code", "slack", "discord", "teams",
        "figma", "notion", "spotify", "whatsapp", "signal",
    ]

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let apps = state.runningApps
        let hits = apps.filter { app in
            let blob = (app.name + " " + (app.bundleIdentifier ?? "") + " " + (app.path ?? "")).lowercased()
            return Self.electronHints.contains { blob.contains($0) }
        }

        // Also honor collector notes for synthetic / deeper process arg scans (future).
        var noteHits: [String] = []
        if let note = state.collectorNotes["lool.electron_devtools"] {
            noteHits = note.split(separator: "|").map { String($0).trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
        }

        guard !hits.isEmpty || !noteHits.isEmpty else { return [] }

        var evidence: [Evidence] = [
            Evidence(
                type: "summary",
                detail:
                    "electronLikeRunning=\(hits.count) noteSignals=\(noteHits.count) "
                    + "(no --inspect attach performed)"
            ),
        ]
        for app in hits.prefix(20) {
            evidence.append(
                Evidence(
                    type: "running_app",
                    path: app.path,
                    detail: "name=\(app.name) bundle=\(app.bundleIdentifier ?? "none")"
                )
            )
        }
        for n in noteHits.prefix(10) {
            evidence.append(Evidence(type: "devtools_signal", detail: n))
        }
        evidence.append(
            Evidence(
                type: "technique_note",
                detail:
                    "Public research shows Electron inspect/remote-debug flags can expand attack surface "
                    + "and interact with TCC-sensitive apps - Rootstock only inventories dual-use surface"
            )
        )

        let compoundFDA = state.tcc?.fullDiskAccessLikely == true
        if compoundFDA {
            evidence.append(
                Evidence(type: "compound_fda", detail: "FDA-likely context increases data impact of compromised Electron apps")
            )
        }

        let severity: Severity = (!noteHits.isEmpty || (hits.count >= 3 && compoundFDA)) ? .medium : .low
        let title: String
        if !noteHits.isEmpty {
            title = "Electron/devtools LOOL surface: explicit inspect/debug signals (\(noteHits.count))"
        } else {
            title = "Electron-like application surface (\(hits.count) running dual-use apps)"
        }

        return [
            Finding(
                id: Self.id,
                title: title,
                severity: severity,
                confidence: noteHits.isEmpty ? .low : .medium,
                category: .lool,
                evidence: evidence,
                attackTechniques: ["T1218", "T1059", "T1559", "T1083"],
                remediation: [
                    "Disable developer/remote-debug flags on production Electron deployments",
                    "Keep collaboration apps patched; limit FDA grants to least privilege",
                    "Monitor unusual --inspect / remote-debugging-port process arguments via EDR",
                    "OPSEC: assess does not attach debuggers or inject into Electron renderers",
                ],
                falsePositiveNotes:
                    "Chrome/Slack/VS Code are common. Presence alone is not malicious; noteSignals indicate stronger evidence.",
                dryRunSafe: true,
                opsecScore: 25,
                esfExpected: ["OPEN", "EXEC"]
            ),
        ]
    }
}
