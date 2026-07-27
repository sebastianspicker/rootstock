import Foundation
import RootstockCore

/// Path-to-impact: developer toolchain as dual-use compile / sign / debug surface.
///
/// Research basis: PEASS/LOOBins "dev tools" themes; clang/swift/codesign dual-use catalogs.
/// Safety and behavior: typed DeveloperToolchainState × inject compound; never runs compilers or signs payloads.
public struct DeveloperToolchainDualUseVector: Check {
    public static let id = "rootstock.vector.dev.toolchain_dual_use"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let dev = state.developerToolchain
        let xcode = dev?.xcodePresent == true
        let clt = dev?.commandLineToolsPresent == true
        let dualUse = dev?.dualUseBinaries ?? []
        let toolchainPaths = dev?.toolchainPaths ?? []

        // Also accept collector-note driven presence for fixture flexibility
        let notePresent = state.collectorNotes["collect.developer_toolchain"]?
            .contains("xcode=true") == true
            || state.collectorNotes["collect.developer_toolchain"]?
                .contains("clt=true") == true
            || state.collectorNotes["dev.toolchain_present"] != nil

        let surface = xcode || clt || dualUse.count >= 2 || notePresent || !toolchainPaths.isEmpty
        guard surface else { return [] }

        let injectRisk = state.injectabilityHits.contains { hit in
            hit.getTaskAllow == true
                || hit.hardenedRuntime == false
                || hit.disableLibraryValidation == true
                || !hit.riskFlags.isEmpty
        }
        let highValue =
            state.identity?.adBound == true
            || state.identity?.platformSSO == true
            || state.credPaths.contains(where: \.exists)

        var evidence: [Evidence] = [
            Evidence(
                type: "toolchain_summary",
                detail:
                    "xcode=\((dev?.xcodePresent).rootstockDescribe) "
                    + "clt=\((dev?.commandLineToolsPresent).rootstockDescribe) "
                    + "dualUseBins=\(dualUse.count) toolchainPaths=\(toolchainPaths.count)"
            ),
        ]
        for path in (toolchainPaths + dualUse).prefix(12) {
            evidence.append(Evidence(type: "toolchain_path", path: path, detail: "dual-use toolchain path"))
        }
        if let notes = dev?.notes {
            for note in notes.prefix(8) {
                evidence.append(Evidence(type: "dev_note", detail: note))
            }
        }
        if injectRisk {
            evidence.append(
                Evidence(
                    type: "compound_inject",
                    detail:
                        "injectabilityHits=\(state.injectabilityHits.count) "
                        + "(get-task-allow / HR-off / LV-off compound)"
                )
            )
        }
        if highValue {
            evidence.append(
                Evidence(
                    type: "compound_high_value",
                    detail:
                        "adBound=\((state.identity?.adBound).rootstockDescribe) "
                        + "platformSSO=\((state.identity?.platformSSO).rootstockDescribe) "
                        + "credPaths=\(state.credPaths.filter(\.exists).count)"
                )
            )
        }
        evidence.append(
            Evidence(
                type: "honesty",
                detail:
                    "Toolchain presence is legitimate on developer workstations. "
                    + "Finding is path-to-impact for dual-use abuse potential - not malware detection."
            )
        )

        let severity: Severity = (injectRisk && (xcode || clt || dualUse.count >= 3)) ? .medium : .low

        return [
            Finding(
                id: Self.id,
                title: injectRisk
                    ? "Developer toolchain dual-use surface compounds with injectability signals"
                    : "Developer toolchain dual-use surface (Xcode/CLT/compile-sign bins)",
                severity: severity,
                confidence: .low,
                category: .codesign,
                evidence: evidence,
                attackTechniques: ["T1059", "T1127", "T1553.002", "T1588.002"],
                remediation: [
                    "Limit Xcode/CLT install on non-developer high-value hosts via MDM",
                    "Monitor codesign / clang / lldb execution on production endpoints",
                    "Prefer signed CI builders over interactive toolchain on identity-joined laptops when possible",
                    "OPSEC: Rootstock Red never invokes compilers or signs payloads",
                ],
                falsePositiveNotes:
                    "Developer Macs legitimately host full toolchains; prioritize compounds with inject/identity.",
                dryRunSafe: true,
                opsecScore: 22,
                esfExpected: ["EXEC", "OPEN"]
            ),
        ]
    }

}
