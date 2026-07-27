import Foundation
import RootstockCore

/// Multi-plane Wave-8 delivery × lateral compound ranking.
///
/// Research basis: engagement narrative across ClickFix delivery, RAE lateral, data-access, mgmt plane, SSH depth.
/// Safety and behavior: deterministic compounds over CollectedState; not automated exploit orchestration.
public struct Wave8DeliveryLateralClusterCheck: Check {
    public static let id = "rootstock.check.vuln.wave8_delivery_lateral_cluster"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let planes = Self.planeSignals(state: state)
        guard planes.count >= 2 else { return [] }
        return [Self.compoundFinding(planes: planes, state: state)]
    }

    private static func planeSignals(state: CollectedState) -> [String] {
        var planes: [String] = []

        // Wave-8 planes require typed posture evidence only.
        // Bare collectorNotes ("collector ran") must NOT invent co-present surfaces,
        // empty/false states stay silent so compounds stay honest.
        let click = state.clickFixTerminalDelivery
        if click?.deliverySurfacePresent == true
            || (click?.loaderBinaryPaths.count ?? 0) >= 2
            || (click?.terminalAppPaths.count ?? 0) + (click?.scriptEditorPaths.count ?? 0) >= 2
        {
            planes.append("clickfix_delivery")
        }

        let rae = state.remoteAppleEvents
        if rae?.remoteAutomationSurfacePresent == true
            || (rae?.remoteAEPrefPaths.count ?? 0) > 0
            || (rae?.eppcFrameworkPaths.count ?? 0) >= 2
        {
            planes.append("rae_lateral")
        }

        let spot = state.spotlightAICache
        if spot?.dataAccessSurfacePresent == true
            || (spot?.spotlightPaths.count ?? 0) > 0
            || (spot?.metadataFrameworkPaths.count ?? 0) > 0
            || (spot?.aiCachePathHints.count ?? 0) > 0
        {
            planes.append("spotlight_cache")
        }

        let mgmt = state.securityMgmtPlane
        if mgmt?.managementPlanePresent == true
            || (mgmt?.managementCLIPaths.count ?? 0) > 0
            || (mgmt?.privilegedHelperPaths.count ?? 0) > 0
        {
            planes.append("sec_mgmt_plane")
        }

        let tpi = state.thirdPartyTCCInheritance
        if tpi?.inheritanceSurfacePresent == true
            || (tpi?.thickClientAppPaths.count ?? 0) > 0
            || (tpi?.embeddedInterpreterPaths.count ?? 0) > 0
        {
            planes.append("tcc_inheritance")
        }

        let ssh = state.sshAgentKeyPath
        if ssh?.lateralPathSurfacePresent == true
            || (ssh?.keyPathHits.count ?? 0) > 0
            || (ssh?.agentSocketPaths.count ?? 0) > 0
        {
            planes.append("ssh_key_depth")
        }

        // Cross-wave amplifiers (typed signals only - not re-inventory of Wave-5–7)
        let remote =
            state.network?.remoteLoginSSH == true
            || state.network?.screenSharingARD == true
        if remote { planes.append("remote") }

        // Sensor gap: typed ESF posture with zero clients (not bare collectorNotes).
        if let esf = state.esf, esf.clientPaths.isEmpty {
            planes.append("sensor_gap")
        }

        if state.tcc?.fullDiskAccessLikely == true {
            planes.append("fda")
        }

        return planes
    }

    private static func compoundFinding(planes: [String], state: CollectedState) -> Finding {
        let sorted = planes.sorted()
        let severity: Severity
        if sorted.contains("clickfix_delivery") && sorted.contains("remote") && sorted.count >= 4 {
            severity = .high
        } else if sorted.contains("remote") && sorted.count >= 3 {
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
                "Wave-8 delivery×lateral compound: \(sorted.count) planes "
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
                        "Wave-8 compound ranking is path-to-impact narrative for operators. "
                        + "Rootstock Red does not orchestrate ClickFix, RAE lateral, EDR unload, "
                        + "or SSH key extraction."
                ),
            ],
            attackTechniques: ["T1204.002", "T1021", "T1005", "T1562.001"],
            remediation: [
                "Prioritize co-occurring delivery + remote + sensor-gap planes on tier-0 hosts",
                "Close remote access and harden paste-run user awareness before lower-tier inventory",
                "Use lab plans under ROE for purple validation of expected telemetry",
                "OPSEC: treat multi-plane compounds as engagement narrative, not an exploit script",
            ],
            falsePositiveNotes:
                "Developer workstations may legitimately co-locate many Wave-8 planes. Rank production hosts first.",
            dryRunSafe: true,
            opsecScore: 22,
            esfExpected: ["OPEN", "EXEC"]
        )
    }

    private static func stageLabels(for planes: [String]) -> [String] {
        var stages: [String] = []
        if planes.contains("clickfix_delivery") {
            stages.append("initial_access_delivery")
        }
        if planes.contains("rae_lateral") || planes.contains("ssh_key_depth") || planes.contains("remote") {
            stages.append("lateral_path")
        }
        if planes.contains("spotlight_cache") || planes.contains("fda") {
            stages.append("collection_impact")
        }
        if planes.contains("tcc_inheritance") {
            stages.append("capability_inheritance")
        }
        if planes.contains("sec_mgmt_plane") || planes.contains("sensor_gap") {
            stages.append("detection_gap")
        }
        return stages.isEmpty ? ["posture_inventory"] : stages
    }
}
