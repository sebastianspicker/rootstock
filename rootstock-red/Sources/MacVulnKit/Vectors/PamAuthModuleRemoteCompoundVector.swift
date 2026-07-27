import Foundation
import RootstockCore

/// Wave-14 compound: PAM auth module surface × remote/FDA path-to-impact.
public struct PamAuthModuleRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.auth.pam_auth_module_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.pamAuthModule
        let a = s?.pamConfigPaths.count ?? 0
        let b = s?.pamModulePaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        let sensorThin = state.esf?.clientPaths.isEmpty == true || state.securityProducts.filter(\.present).isEmpty
        guard remote || fda || sensorThin || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "pam_auth_module_compound", detail: "a=\(a) b=\(b) remote=\(remote) fda=\(fda) sensorThin=\(sensorThin)"),
        ]
        if let s {
            for path in (s.pamConfigPaths + s.pamModulePaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "PAM auth module surface compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never installs PAM modules or modifies /etc/pam.d."))
        let severity: Severity = (remote && fda) ? .high : ((remote || fda || sensorThin) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "PAM auth module surface × remote compound" : "PAM auth module surface × impact compound",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1556", "T1543", "T1078"],
            remediation: [
                "Prioritize hosts co-locating PAM auth module surface with remote/FDA amplifiers",
                "Use Wave-14 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ],
            falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first.",
            dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]
        )]
    }
}
