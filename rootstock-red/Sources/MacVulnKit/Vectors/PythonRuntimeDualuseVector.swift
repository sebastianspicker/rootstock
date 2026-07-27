import Foundation
import RootstockCore

/// Path-to-impact: Python runtime dual-use residual surface.
public struct PythonRuntimeDualuseVector: Check {
    public static let id = "rootstock.vector.lool.python_runtime_dualuse"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.pythonRuntimeDualuse
        let a = s?.pythonBinaryPaths.count ?? 0
        let b = s?.sitePackagePaths.count ?? 0
        let c = s?.pythonFrameworkPaths.count ?? 0
        let surface = s?.pythonSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.python_runtime_dualuse"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "python_runtime_dualuse_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.pythonBinaryPaths + s.sitePackagePaths + s.pythonFrameworkPaths).prefix(12) {
                evidence.append(Evidence(type: "python_runtime_dualuse_path", path: path, detail: "Python runtime dual-use path"))
            }
            for n in s.notes.prefix(5) { evidence.append(Evidence(type: "python_runtime_dualuse_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never executes third-party Python payloads or drops malicious site-packages."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Python runtime dual-use with remote amplifier" : "Python runtime dual-use residual surface",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1059.006", "T1059", "T1204"],
            remediation: [
                "Inventory and baseline Python runtime dual-use paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never executes third-party Python payloads or drops malicious site-packages",
            ],
            falsePositiveNotes: "Stock paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
