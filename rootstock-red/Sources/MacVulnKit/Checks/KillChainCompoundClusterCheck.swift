import Foundation
import RootstockCore

/// Multi-plane kill-chain compound ranking (Wave-7).
///
/// Research basis: engagement narrative ranking across foothold/trust/privilege/collection.
/// Safety and behavior: deterministic compounds over CollectedState; not automated exploit orchestration.
public struct KillChainCompoundClusterCheck: Check {
    public static let id = "rootstock.check.vuln.kill_chain_compound_cluster"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let planes = Self.planeSignals(state: state)
        guard planes.count >= 3 else {
            // Still emit a lighter compound when 2 high-value planes co-occur with remote
            if planes.count >= 2 && planes.contains("remote") {
                return [Self.compoundFinding(planes: planes, state: state)]
            }
            return []
        }
        return [Self.compoundFinding(planes: planes, state: state)]
    }

    /// Stable plane labels for ranking (deterministic order).
    private static func planeSignals(state: CollectedState) -> [String] {
        var planes: [String] = []

        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        if remote { planes.append("remote") }

        if state.protections?.sipEnabled == false
            || state.protections?.gatekeeperEnabled == false
        {
            planes.append("protections_weak")
        }

        if state.tcc?.fullDiskAccessLikely == true
            || (state.tcc?.domainSignals.count ?? 0) >= 3
        {
            planes.append("tcc_depth")
        }

        if !(state.injectabilityHits.filter { !$0.riskFlags.isEmpty }.isEmpty)
            || state.codesignSamples.contains(where: { $0.getTaskAllow == true })
        {
            planes.append("inject_trust")
        }

        if (state.appSandboxEntitlements?.appSamples.count ?? 0) > 0
            || (state.appSandboxEntitlements?.unsandboxedRiskPaths.count ?? 0) > 0
            || state.collectorNotes["collect.app_sandbox_entitlements"] != nil
        {
            planes.append("sandbox_thick_client")
        }

        if (state.notarizationStapling?.unstapledOrAdHocHints.count ?? 0) > 0
            || state.collectorNotes["collect.notarization_stapling"] != nil
        {
            planes.append("notarization_delivery")
        }

        if state.virtualizationContainers?.dualUsePresent == true
            || (state.virtualizationContainers?.containerToolPaths.count ?? 0) > 0
            || (state.virtualizationContainers?.hypervisorAppPaths.count ?? 0) > 0
        {
            planes.append("virt_dual_use")
        }

        if state.continuityAirDrop?.proximitySurfacePresent == true
            || (state.continuityAirDrop?.airdropPrefPaths.count ?? 0) > 0
        {
            planes.append("proximity")
        }

        let fvOn = state.fileVaultEscrow?.fileVaultOn ?? state.protections?.fileVaultOn
        if fvOn == false
            || (state.fileVaultEscrow?.escrowPathHints.count ?? 0) > 0
            || state.collectorNotes["collect.filevault_escrow"] != nil
        {
            planes.append("filevault_escrow")
        }

        if state.esf?.clientPaths.isEmpty == true
            || (state.securityProducts.filter(\.present).isEmpty
                && state.collectorNotes["collect.esf_endpoint_security"] != nil)
        {
            planes.append("sensor_gap")
        }

        if state.credPaths.contains(where: \.exists)
            || state.browserMeta.contains(where: \.exists)
        {
            planes.append("collection_paths")
        }

        if state.developerToolchain?.xcodePresent == true
            || !(state.developerToolchain?.dualUseBinaries.isEmpty ?? true)
        {
            planes.append("dev_toolchain")
        }

        return planes
    }

    private static func compoundFinding(planes: [String], state: CollectedState) -> Finding {
        let sorted = planes.sorted()
        let severity: Severity
        if sorted.contains("remote") && sorted.contains("protections_weak") && sorted.count >= 4 {
            severity = .high
        } else if sorted.contains("remote") && sorted.count >= 3 {
            severity = .medium
        } else if sorted.count >= 5 {
            severity = .medium
        } else {
            severity = .low
        }

        let stageHints = stageLabels(for: sorted)

        return Finding(
            id: "\(id).multi_plane",
            title:
                "Kill-chain compound: \(sorted.count) posture planes co-occur "
                + "(\(sorted.prefix(5).joined(separator: ", "))\(sorted.count > 5 ? ", …" : ""))",
            severity: severity,
            confidence: .low,
            category: .misconfig,
            evidence: [
                Evidence(
                    type: "planes",
                    detail: "planes=\(sorted.joined(separator: "|")) count=\(sorted.count)"
                ),
                Evidence(
                    type: "stage_labels",
                    detail: "stages=\(stageHints.joined(separator: "|")) (labels only - not auto-exploit)"
                ),
                Evidence(
                    type: "host",
                    detail:
                        "host=\(state.host?.hostname ?? "unknown") "
                        + "user=\(state.host?.username ?? "unknown")"
                ),
                Evidence(
                    type: "honesty",
                    detail:
                        "Kill-chain ranking is path-to-impact narrative for operators. "
                        + "Rootstock Red does not orchestrate multi-stage implants or 0-day packs."
                ),
            ],
            attackTechniques: ["T1082", "T1016", "T1021", "T1553"],
            remediation: [
                "Prioritize remediation of co-occurring high-severity planes (remote + protections + sensor gap)",
                "Close remote access before addressing lower-tier inventory findings",
                "Use lab plans under ROE for purple validation of expected telemetry",
                "OPSEC: treat multi-plane compounds as engagement narrative, not an exploit script",
            ],
            falsePositiveNotes:
                "Developer workstations may legitimately co-locate many planes. Rank production/tier-0 hosts first.",
            dryRunSafe: true,
            opsecScore: 22,
            esfExpected: ["OPEN", "EXEC"]
        )
    }

    private static func stageLabels(for planes: [String]) -> [String] {
        var stages: [String] = []
        if planes.contains("remote") || planes.contains("proximity") {
            stages.append("foothold_adjacent")
        }
        if planes.contains("inject_trust")
            || planes.contains("sandbox_thick_client")
            || planes.contains("notarization_delivery")
            || planes.contains("protections_weak")
        {
            stages.append("trust_gap")
        }
        if planes.contains("tcc_depth") || planes.contains("dev_toolchain") || planes.contains("virt_dual_use") {
            stages.append("privilege_or_capability")
        }
        if planes.contains("collection_paths") || planes.contains("filevault_escrow") {
            stages.append("collection_impact")
        }
        if planes.contains("sensor_gap") {
            stages.append("detection_gap")
        }
        return stages.isEmpty ? ["posture_inventory"] : stages
    }
}
