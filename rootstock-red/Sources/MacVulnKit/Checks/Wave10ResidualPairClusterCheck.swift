import Foundation
import RootstockCore

/// Multi-plane Wave-10 residual pair compound ranking (installer × extractor × stealer × visibility).
///
/// Research basis: engagement narrative across residual red↔blue pair themes.
/// Safety and behavior: deterministic compounds over CollectedState; not automated exploit orchestration.
public struct Wave10ResidualPairClusterCheck: Check {
    public static let id = "rootstock.check.vuln.wave10_residual_pair_cluster"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let planes = Self.pairPlanes(state: state)
        // Rank when ≥2 of the 4 residual pair planes are present.
        guard planes.count >= 2 else { return [] }
        return [Self.compoundFinding(planes: planes, state: state)]
    }

    /// The four residual pair planes only (no amplifiers counted toward the ≥2 gate).
    private static func pairPlanes(state: CollectedState) -> [String] {
        var planes: [String] = []

        let pk = state.packageKitInstallerDesign
        if pk?.designSurfacePresent == true
            || ((pk?.installerServicePaths.count ?? 0) >= 1
                && (pk?.receiptAndHistoryPaths.count ?? 0) >= 1)
            || (pk?.installerServicePaths.count ?? 0) > 0
            || (pk?.receiptAndHistoryPaths.count ?? 0) >= 1
        {
            planes.append("installer_design")
        }

        let aq = state.archiveQuarantineExtractor
        if aq?.extractorSurfacePresent == true
            || (aq?.thirdPartyExtractorPaths.count ?? 0) > 0
            || (aq?.stockExtractorPaths.count ?? 0) >= 3
        {
            planes.append("archive_extractor")
        }

        let sp = state.infoStealerPathPlane
        let total =
            (sp?.browserAdjacentPaths.count ?? 0)
            + (sp?.messagingAndVaultPaths.count ?? 0)
            + (sp?.walletAndSyncPaths.count ?? 0)
        if sp?.collectionSurfacePresent == true
            || total >= 3
            || ((sp?.browserAdjacentPaths.count ?? 0) >= 1
                && (sp?.messagingAndVaultPaths.count ?? 0) >= 1)
        {
            planes.append("stealer_paths")
        }

        let vd = state.tccEsfVisibilityDepth
        if vd?.visibilitySurfacePresent == true
            || (vd?.tccDbPathHits.count ?? 0) > 0
            || (vd?.visibilityToolPaths.count ?? 0) > 0
            || vd?.visibilityDepth == "thin"
            || vd?.visibilityDepth == "partial"
        {
            planes.append("visibility_depth")
        }

        return planes
    }

    private static func amplifiers(state: CollectedState) -> [String] {
        var amps: [String] = []
        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        if remote { amps.append("remote") }
        if state.tcc?.fullDiskAccessLikely == true { amps.append("fda") }
        if state.protections?.sipEnabled == false { amps.append("sip_off") }
        if state.protections?.gatekeeperEnabled == false { amps.append("gk_off") }
        if let esf = state.esf, esf.clientPaths.isEmpty { amps.append("sensor_gap") }
        if state.securityProducts.filter(\.present).isEmpty { amps.append("products_absent") }
        return amps
    }

    private static func compoundFinding(planes: [String], state: CollectedState) -> Finding {
        let sorted = planes.sorted()
        let amps = amplifiers(state: state).sorted()
        let severity: Severity
        if sorted.contains("stealer_paths")
            && sorted.contains("visibility_depth")
            && amps.contains("fda")
            && amps.contains("remote")
        {
            severity = .high
        } else if sorted.count >= 3 || (sorted.count >= 2 && amps.count >= 2) {
            severity = .medium
        } else {
            severity = .low
        }

        let stageHints = stageLabels(for: sorted, amps: amps)

        return Finding(
            id: "\(id).multi_plane",
            title:
                "Wave-10 residual-pair compound: \(sorted.count) planes "
                + "(\(sorted.joined(separator: ", ")))",
            severity: severity,
            confidence: .low,
            category: .misconfig,
            evidence: [
                Evidence(
                    type: "planes",
                    detail: "planes=\(sorted.joined(separator: "|")) count=\(sorted.count)"
                ),
                Evidence(
                    type: "amplifiers",
                    detail:
                        amps.isEmpty
                        ? "amplifiers=none"
                        : "amplifiers=\(amps.joined(separator: "|")) count=\(amps.count)"
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
                        "Wave-10 residual-pair ranking is path-to-impact narrative for operators. "
                        + "Rootstock Red does not build pkgs, craft Gatekeeper bypass archives, "
                        + "dump stealer secrets, dump TCC.db, or strip quarantine."
                ),
            ],
            attackTechniques: ["T1546", "T1553.001", "T1555", "T1562.001"],
            remediation: [
                "Prioritize hosts co-locating installer-design + stealer-paths + visibility-depth planes",
                "Close remote access and harden package/archive workflows before lower-tier inventory",
                "Use Wave-9 lab plans under ROE for purple validation of expected telemetry",
                "OPSEC: treat multi-plane compounds as engagement narrative, not an exploit script",
            ],
            falsePositiveNotes:
                "Developer workstations may legitimately co-locate many residual pair planes. "
                + "Rank production hosts with remote/FDA amplifiers first.",
            dryRunSafe: true,
            opsecScore: 26,
            esfExpected: ["OPEN", "EXEC", "READ"]
        )
    }

    private static func stageLabels(for planes: [String], amps: [String]) -> [String] {
        var stages: [String] = []
        if planes.contains("archive_extractor") || amps.contains("gk_off") {
            stages.append("delivery_trust")
        }
        if planes.contains("installer_design") {
            stages.append("persistence_design")
        }
        if planes.contains("stealer_paths") || amps.contains("fda") {
            stages.append("collection_impact")
        }
        if planes.contains("visibility_depth") || amps.contains("sensor_gap") {
            stages.append("detection_gap")
        }
        if amps.contains("remote") {
            stages.append("lateral_path")
        }
        return stages.isEmpty ? ["posture_inventory"] : stages
    }
}
