import Foundation
import RootstockCore

/// Multi-plane Wave-12 compound ranking (6 net-new themes beyond Wave-11).
///
/// Research basis: engagement narrative across Wave-12 red↔blue pair themes.
/// Safety and behavior: deterministic compounds over CollectedState; not automated exploit orchestration.
public struct Wave12MultiPlaneClusterCheck: Check {
    public static let id = "rootstock.check.vuln.wave12_multi_plane_cluster"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let planes = Self.pairPlanes(state: state)
        guard planes.count >= 2 else { return [] }
        return [Self.compoundFinding(planes: planes, state: state)]
    }

    private static func pairPlanes(state: CollectedState) -> [String] {
        var planes: [String] = []

        let webloc_inetloc = state.weblocInetlocDelivery
        if webloc_inetloc?.deliverySurfacePresent == true
            || ((webloc_inetloc?.weblocSamplePaths.count ?? 0) >= 1)
            || ((webloc_inetloc?.inetlocSamplePaths.count ?? 0) >= 1)
        {
            planes.append("webloc_inetloc")
        }

        let mail_rules = state.mailRulesAutomation
        if mail_rules?.rulesSurfacePresent == true
            || ((mail_rules?.mailAppPaths.count ?? 0) >= 1)
            || ((mail_rules?.rulesPlistPaths.count ?? 0) >= 1)
        {
            planes.append("mail_rules")
        }

        let unified_log = state.unifiedLogObservation
        if unified_log?.observationSurfacePresent == true
            || ((unified_log?.logToolPaths.count ?? 0) >= 1)
            || ((unified_log?.logarchiveHints.count ?? 0) >= 1)
        {
            planes.append("unified_log")
        }

        let dock_persist = state.dockPersistenceSurface
        if dock_persist?.dockSurfacePresent == true
            || ((dock_persist?.dockPlistPaths.count ?? 0) >= 1)
            || ((dock_persist?.recentItemsPaths.count ?? 0) >= 1)
        {
            planes.append("dock_persist")
        }

        let osascript_scpt = state.osascriptScptDelivery
        if osascript_scpt?.scptSurfacePresent == true
            || ((osascript_scpt?.osaToolPaths.count ?? 0) >= 1)
            || ((osascript_scpt?.scriptEditorPaths.count ?? 0) >= 1)
        {
            planes.append("osascript_scpt")
        }

        let network_share = state.networkShareMount
        if network_share?.shareSurfacePresent == true
            || ((network_share?.smbClientPaths.count ?? 0) >= 1)
            || ((network_share?.netAuthPaths.count ?? 0) >= 1)
        {
            planes.append("network_share")
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
        if sorted.count >= 4 && amps.contains("remote") && amps.contains("fda") {
            severity = .high
        } else if sorted.count >= 3 || (sorted.count >= 2 && amps.count >= 2) {
            severity = .medium
        } else {
            severity = .low
        }

        return Finding(
            id: "\(id).multi_plane",
            title:
                "Wave-12 multi-plane compound: \(sorted.count) planes "
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
                    detail: "stages=delivery|persist|visibility|lateral (labels only - not auto-exploit)"
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
                        "Wave-12 multi-plane ranking is path-to-impact narrative. "
                        + "Rootstock Red does not craft webloc lures, modify Mail rules, dump unified logs, "
                        + "edit Dock.plist, compile malicious scpt, or mount attacker shares."
                ),
            ],
            attackTechniques: ["T1204", "T1114", "T1059.002", "T1021.002", "T1547", "T1083"],
            remediation: [
                "Prioritize hosts co-locating multiple Wave-12 planes with remote/FDA amplifiers",
                "Close remote access before deep dual-use inventory",
                "Use Wave-12 lab plans under ROE for purple validation",
                "OPSEC: multi-plane compounds are engagement narrative, not exploit scripts",
            ],
            falsePositiveNotes:
                "Developer workstations may legitimately co-locate many Wave-12 planes. "
                + "Rank production hosts with remote/FDA amplifiers first.",
            dryRunSafe: true,
            opsecScore: 28,
            esfExpected: ["OPEN", "EXEC", "READ"]
        )
    }
}
