import Foundation
import RootstockCore

/// Path-to-impact: Shell plugin manager dual-use residual.
public struct ShellPluginManagerVector: Check {
    public static let id = "rootstock.vector.persist.shell_plugin_manager"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.shellPluginManager
        let a = s?.omzPaths.count ?? 0
        let b = s?.pluginDirPaths.count ?? 0
        let c = s?.shellInitPaths.count ?? 0
        let surface = s?.shellPluginSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.shell_plugin_manager"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "shell_plugin_manager_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.omzPaths + s.pluginDirPaths + s.shellInitPaths).prefix(12) {
                evidence.append(Evidence(type: "shell_plugin_manager_path", path: path, detail: "Shell plugin manager dual-use path"))
            }
            for n in s.notes.prefix(5) { evidence.append(Evidence(type: "shell_plugin_manager_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never installs oh-my-zsh plugins or rewrites shell init for persistence."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Shell plugin manager dual-use with remote amplifier" : "Shell plugin manager dual-use residual",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1546.004", "T1059.004", "T1546"],
            remediation: [
                "Inventory and baseline Shell plugin manager dual-use paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never installs oh-my-zsh plugins or rewrites shell init for persistence",
            ],
            falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
