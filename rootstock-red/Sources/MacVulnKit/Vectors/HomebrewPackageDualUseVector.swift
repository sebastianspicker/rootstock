import Foundation
import RootstockCore

/// Path-to-impact: Homebrew / third-party package manager dual-use.
public struct HomebrewPackageDualUseVector: Check {
    public static let id = "rootstock.vector.dev.homebrew_package_dualuse"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let s = state.homebrewPackageDualUse
        let a = s?.brewBinaryPaths.count ?? 0
        let b = s?.cellarPaths.count ?? 0
        let c = s?.tapPaths.count ?? 0
        let surface = s?.packageSurfacePresent == true || a + b + c >= 2
        let note = state.collectorNotes["collect.homebrew_package_dualuse"] != nil
        guard surface || note else { return [] }
        guard a >= 1 || b >= 1 else { return [] }
        let remote = state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true
        let fda = state.tcc?.fullDiskAccessLikely == true
        var evidence: [Evidence] = [
            Evidence(type: "homebrew_pkg_summary", detail: "a=\(a) b=\(b) c=\(c) remote=\(remote) fda=\(fda)"),
        ]
        if let s {
            for path in (s.brewBinaryPaths + s.cellarPaths + s.tapPaths).prefix(12) {
                evidence.append(Evidence(type: "homebrew_pkg_path", path: path, detail: "Homebrew package dual-use path"))
            }
            for n in s.notes.prefix(6) { evidence.append(Evidence(type: "homebrew_pkg_note", detail: n)) }
        }
        evidence.append(Evidence(type: "honesty", detail: "Assess never installs packages or modifies Homebrew formulae."))
        let severity: Severity = (remote && fda && a + b >= 3) ? .high : ((remote || fda || a + b >= 2) ? .medium : .low)
        return [Finding(
            id: Self.id,
            title: remote ? "Homebrew package dual-use with remote access amplifier" : "Homebrew / third-party package manager dual-use",
            severity: severity, confidence: .medium, category: .misconfig, evidence: evidence,
            attackTechniques: ["T1072", "T1546", "T1059"],
            remediation: [
                "Inventory and baseline Homebrew package dual-use paths via MDM/EDR",
                "Correlate unexpected co-presence with delivery timelines",
                "Prioritize hosts with remote/FDA amplifiers",
                "OPSEC: Rootstock Red never installs packages or modifies Homebrew formulae",
            ],
            falsePositiveNotes: "Stock macOS paths often exist. Elevate multi-path co-presence with remote/FDA.",
            dryRunSafe: true, opsecScore: 25, esfExpected: ["OPEN", "READ", "EXEC"]
        )]
    }
}
