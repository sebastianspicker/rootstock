import Foundation
import RootstockCore

/// Path-to-impact: Font validation / ATS dual-use surface.
public struct FontValidationDualuseVector: Check {
    public static let id = "rootstock.vector.delivery.font_validation_dualuse"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.fontValidationDualuse
        let a = s?.fontToolPaths.count ?? 0
        let b = s?.atsSupportPaths.count ?? 0
        let c = s?.userFontPaths.count ?? 0
        let surface = s?.fontSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.font_validation_dualuse"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "font_validation_dualuse_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.fontToolPaths + s.atsSupportPaths + s.userFontPaths).prefix(12) {
                evidence.append(Evidence(type: "font_validation_dualuse_path", path: path, detail: "Font validation dual-use path"))
            }
            for n in s.notes.prefix(5) { evidence.append(Evidence(type: "font_validation_dualuse_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never installs malicious fonts or disables font validation."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Font validation dual-use with remote amplifier" : "Font validation / ATS dual-use surface",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1204", "T1189", "T1059"],
            remediation: [
                "Inventory and baseline Font validation dual-use paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never installs malicious fonts or disables font validation",
            ],
            falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
