import Foundation
import RootstockCore

/// Path-to-impact: Software Update catalog residual surface.
public struct SoftwareupdateCatalogVector: Check {
    public static let id = "rootstock.vector.persist.softwareupdate_catalog"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.softwareupdateCatalog
        let a = s?.softwareUpdateToolPaths.count ?? 0
        let b = s?.softwareUpdatePrefPaths.count ?? 0
        let c = s?.softwareUpdateDaemonPaths.count ?? 0
        let surface = s?.softwareUpdateSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.softwareupdate_catalog"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "softwareupdate_catalog_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.softwareUpdateToolPaths + s.softwareUpdatePrefPaths + s.softwareUpdateDaemonPaths).prefix(10) {
                evidence.append(Evidence(type: "softwareupdate_catalog_path", path: path, detail: "Software Update catalog path"))
            }
            for n in s.notes.prefix(4) { evidence.append(Evidence(type: "softwareupdate_catalog_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never points SUS catalogs at attacker mirrors or tampers with update plists."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Software Update catalog with remote amplifier" : "Software Update catalog residual surface",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1072", "T1195", "T1553"],
            remediation: [
                "Inventory and baseline Software Update catalog paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never points SUS catalogs at attacker mirrors or tampers with update plists",
            ],
            falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
