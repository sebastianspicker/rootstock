import Foundation
import RootstockCore

/// Multi-plane Wave-11 compound ranking (URL handlers × launchd overrides × browser extensions × Shortcuts).
///
/// Research basis: engagement narrative across Wave-11 red↔blue pair themes.
/// Safety and behavior: deterministic compounds over CollectedState; not automated exploit orchestration.
public struct Wave11MultiPlaneClusterCheck: Check {
    public static let id = "rootstock.check.vuln.wave11_multi_plane_cluster"
    public static let cost: CollectorCost = .low

    public init() {}

    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let planes = Self.pairPlanes(state: state)
        guard planes.count >= 2 else { return [] }
        return [Self.compoundFinding(planes: planes, state: state)]
    }

    private static func pairPlanes(state: CollectedState) -> [String] {
        var planes: [String] = []

        let uh = state.urlSchemeHandler
        if uh?.handlerSurfacePresent == true
            || (uh?.launchServicesPaths.count ?? 0) >= 1
            || ((uh?.openerBinaryPaths.count ?? 0) >= 2 && (uh?.urlTypePlistPaths.count ?? 0) >= 1)
        {
            planes.append("url_scheme_handler")
        }

        let lo = state.launchdOverrideDepth
        if lo?.overrideSurfacePresent == true
            || (lo?.overridePlistPaths.count ?? 0) >= 1
            || (lo?.securityDisabledHints.count ?? 0) >= 1
        {
            planes.append("launchd_override_depth")
        }

        let be = state.browserExtensionDualUse
        let extTotal = (be?.chromiumExtensionPaths.count ?? 0) + (be?.safariExtensionPaths.count ?? 0)
        if be?.extensionSurfacePresent == true
            || extTotal >= 1
            || (be?.preferencePaths.count ?? 0) >= 2
        {
            planes.append("browser_extension_dualuse")
        }

        let sa = state.shortcutsAppIntents
        if sa?.automationSurfacePresent == true
            || (sa?.shortcutsAppPaths.count ?? 0) >= 1
            || (sa?.appIntentsPaths.count ?? 0) >= 1
        {
            planes.append("shortcuts_app_intents")
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
        if sorted.contains("launchd_override_depth")
            && sorted.contains("browser_extension_dualuse")
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
                "Wave-11 multi-plane compound: \(sorted.count) planes "
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
                        "Wave-11 multi-plane ranking is path-to-impact narrative for operators. "
                        + "Rootstock Red does not register URL schemes, disable launchd security jobs, "
                        + "dump browser extension secrets, or run Shortcuts/App Intents."
                ),
            ],
            attackTechniques: ["T1204", "T1562.001", "T1176", "T1059"],
            remediation: [
                "Prioritize hosts co-locating launchd-override + browser-extension + remote amplifiers",
                "Close remote access and restore disabled security products before lower-tier inventory",
                "Use Wave-11 lab plans under ROE for purple validation of expected telemetry",
                "OPSEC: treat multi-plane compounds as engagement narrative, not an exploit script",
            ],
            falsePositiveNotes:
                "Developer workstations may legitimately co-locate many Wave-11 planes. "
                + "Rank production hosts with remote/FDA/SIP amplifiers first.",
            dryRunSafe: true,
            opsecScore: 28,
            esfExpected: ["OPEN", "EXEC", "READ", "WRITE"]
        )
    }

    private static func stageLabels(for planes: [String], amps: [String]) -> [String] {
        var stages: [String] = []
        if planes.contains("url_scheme_handler") || amps.contains("gk_off") {
            stages.append("delivery_handler")
        }
        if planes.contains("launchd_override_depth") || amps.contains("sensor_gap") {
            stages.append("defense_evasion")
        }
        if planes.contains("browser_extension_dualuse") || amps.contains("fda") {
            stages.append("collection_impact")
        }
        if planes.contains("shortcuts_app_intents") || amps.contains("remote") {
            stages.append("automation_lateral")
        }
        return stages.isEmpty ? ["posture_inventory"] : stages
    }
}
