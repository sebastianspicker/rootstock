import Foundation
import RootstockCore

/// Path-to-impact: Finder Sync extension dual-use surface.
public struct FinderSyncExtensionVector: Check {
    public static let id = "rootstock.vector.persist.finder_sync_extension"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.finderSyncExtension
        let a = s?.finderSyncFrameworkPaths.count ?? 0
        let b = s?.appScriptPaths.count ?? 0
        let c = s?.finderPrefPaths.count ?? 0
        let surface = s?.finderSyncSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.finder_sync_extension"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "finder_sync_extension_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.finderSyncFrameworkPaths + s.appScriptPaths + s.finderPrefPaths).prefix(10) {
                evidence.append(Evidence(type: "finder_sync_extension_path", path: path, detail: "Finder Sync dual-use path"))
            }
            for n in s.notes.prefix(4) { evidence.append(Evidence(type: "finder_sync_extension_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never installs Finder Sync extensions or rewrites Finder preferences for abuse."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Finder Sync dual-use with remote amplifier" : "Finder Sync extension dual-use surface",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1546", "T1176", "T1059"],
            remediation: [
                "Inventory and baseline Finder Sync dual-use paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never installs Finder Sync extensions or rewrites Finder preferences for abuse",
            ],
            falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
