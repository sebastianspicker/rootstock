import Foundation
import RootstockCore

/// Wave-15 compound: Python runtime dual-use × remote/FDA path-to-impact.
public struct PythonRuntimeDualuseRemoteCompoundVector: Check {
    public static let id = "rootstock.vector.lool.python_runtime_dualuse_remote_compound"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.pythonRuntimeDualuse
        let a = s?.pythonBinaryPaths.count ?? 0
        let b = s?.sitePackagePaths.count ?? 0
        guard a >= 1, b >= 1 || a >= 2 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        let sensorThin = state.esf?.clientPaths.isEmpty == true || state.securityProducts.filter(\.present).isEmpty
        guard remote || fda || sensorThin || a + b >= 3 else { return [] }
        var evidence: [Evidence] = [
            Evidence(type: "python_runtime_dualuse_compound", detail: "a=\(a) b=\(b) remote=\(remote) fda=\(fda) sensorThin=\(sensorThin)"),
        ]
        if let s {
            for path in (s.pythonBinaryPaths + s.sitePackagePaths).prefix(8) {
                evidence.append(Evidence(type: "compound_path", path: path, detail: "Python runtime dual-use compound"))
            }
        }
        evidence.append(Evidence(type: "honesty", detail: "never executes third-party Python payloads or drops malicious site-packages."))
        let severity: Severity = (remote && fda) ? .high : ((remote || fda || sensorThin) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Python runtime dual-use × remote compound" : "Python runtime dual-use × impact compound",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1059.006", "T1059", "T1204"],
            remediation: [
                "Prioritize hosts co-locating Python runtime dual-use with remote/FDA amplifiers",
                "Use Wave-15 lab plans under ROE for purple validation",
                "OPSEC: path-to-impact ranking only - not an auto-exploit chain",
            ],
            falsePositiveNotes: "Developer hosts may co-locate dual-use paths; rank production remote hosts first.",
            dryRunSafe: true, opsecScore: 27, esfExpected: ["OPEN", "EXEC", "READ"]
        )]
    }
}
