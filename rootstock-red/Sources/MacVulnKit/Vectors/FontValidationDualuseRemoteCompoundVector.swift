import Foundation
import RootstockCore

/// Wave-14 compound: Font validation dual-use × remote/FDA path-to-impact.
public struct FontValidationDualuseRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.delivery.font_validation_dualuse_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.fontValidationDualuse
        let a = s?.fontToolPaths.count ?? 0
        let b = s?.atsSupportPaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        let sensorThin = state.esf?.clientPaths.isEmpty == true || state.securityProducts.filter(\.present).isEmpty
        guard remote || fda || sensorThin || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "font_validation_dualuse_compound", detail: "a=\(a) b=\(b) remote=\(remote) fda=\(fda) sensorThin=\(sensorThin)"),
        ]
        if let s {
            for path in (s.fontToolPaths + s.atsSupportPaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Font validation dual-use compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never installs malicious fonts or disables font validation."))
        let severity: Severity = (remote && fda) ? .high : ((remote || fda || sensorThin) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Font validation dual-use × remote compound" : "Font validation dual-use × impact compound",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1204", "T1189", "T1059"],
            remediation: [
                "Prioritize hosts co-locating Font validation dual-use with remote/FDA amplifiers",
                "Use Wave-14 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ],
            falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first.",
            dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]
        )]
    }
}
