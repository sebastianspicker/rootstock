import Foundation
import RootstockCore

/// Multi-plane Wave-9 installer × collection × visibility compound ranking.
///
/// Research basis: engagement narrative across installer design, extractors, stealer paths, visibility, MDM parse.
/// Safety and behavior: deterministic compounds over CollectedState; not automated exploit orchestration.
public struct Wave9InstallerCollectionClusterCheck: Check {
    public static let id = "rootstock.check.vuln.wave9_installer_collection_cluster"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let planes = Self.planeSignals(state: state)
        guard planes.count >= 2 else { return [] }
        return [Self.compoundFinding(planes: planes, state: state)]
    }

    private static func planeSignals(state: CollectedState) -> [String] {
        var planes: [String] = []

        let pk = state.packageKitInstallerDesign
        if pk?.designSurfacePresent == true
            || (pk?.installerServicePaths.count ?? 0) > 0
            || (pk?.receiptAndHistoryPaths.count ?? 0) >= 1
            || (pk?.toolingPaths.count ?? 0) >= 2
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
        if sp?.collectionSurfacePresent == true
            || ((sp?.browserAdjacentPaths.count ?? 0)
                + (sp?.messagingAndVaultPaths.count ?? 0)
                + (sp?.walletAndSyncPaths.count ?? 0)) >= 4
        {
            planes.append("stealer_paths")
        }

        let vd = state.tccEsfVisibilityDepth
        if vd?.visibilitySurfacePresent == true
            || (vd?.tccDbPathHits.count ?? 0) > 0
            || (vd?.visibilityToolPaths.count ?? 0) > 0
        {
            planes.append("visibility_depth")
        }

        let mp = state.mdmProfileParseDepth
        if (mp?.parsedProfileCount ?? 0) > 0
            || (mp?.examinedProfilePaths.count ?? 0) > 0
        {
            planes.append("profile_parse")
        }

        // Cross-wave amplifiers (typed only)
        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        if remote { planes.append("remote") }

        if state.tcc?.fullDiskAccessLikely == true {
            planes.append("fda")
        }

        if let esf = state.esf, esf.clientPaths.isEmpty {
            planes.append("sensor_gap")
        }

        return planes
    }

    private static func compoundFinding(planes: [String], state: CollectedState) -> Finding {
        let sorted = planes.sorted()
        let severity: Severity
        if sorted.contains("stealer_paths") && sorted.contains("fda") && sorted.count >= 4 {
            severity = .high
        } else if sorted.contains("installer_design") && sorted.contains("remote") && sorted.count >= 3 {
            severity = .medium
        } else if sorted.count >= 4 {
            severity = .medium
        } else {
            severity = .low
        }

        let stageHints = stageLabels(for: sorted)

        return Finding(
            id: "\(id).multi_plane",
            title:
                "Wave-9 installer×collection compound: \(sorted.count) planes "
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
                        "Wave-9 compound ranking is path-to-impact narrative for operators. "
                        + "Rootstock Red does not build pkgs, craft Gatekeeper bypass archives, "
                        + "dump stealer secrets, dump TCC.db, or install profiles."
                ),
            ],
            attackTechniques: ["T1546", "T1553.001", "T1555", "T1562.001"],
            remediation: [
                "Prioritize co-occurring installer-design + stealer-paths + FDA/remote planes on tier-0 hosts",
                "Close remote access and harden package/archive user workflows before lower-tier inventory",
                "Use Wave-9 lab plans under ROE for purple validation of expected telemetry",
                "OPSEC: treat multi-plane compounds as engagement narrative, not an exploit script",
            ],
            falsePositiveNotes:
                "Developer workstations may legitimately co-locate many Wave-9 planes. Rank production hosts first.",
            dryRunSafe: true,
            opsecScore: 24,
            esfExpected: ["OPEN", "EXEC", "READ"]
        )
    }

    private static func stageLabels(for planes: [String]) -> [String] {
        var stages: [String] = []
        if planes.contains("archive_extractor") {
            stages.append("delivery_trust")
        }
        if planes.contains("installer_design") {
            stages.append("persistence_design")
        }
        if planes.contains("stealer_paths") || planes.contains("fda") {
            stages.append("collection_impact")
        }
        if planes.contains("visibility_depth") || planes.contains("sensor_gap") {
            stages.append("detection_gap")
        }
        if planes.contains("profile_parse") {
            stages.append("config_abuse")
        }
        if planes.contains("remote") {
            stages.append("lateral_path")
        }
        return stages.isEmpty ? ["posture_inventory"] : stages
    }
}
