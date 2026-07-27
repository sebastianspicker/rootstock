import Foundation
import RootstockCore

/// Multi-plane Wave-15 compound ranking (10 net-new themes beyond Wave-14).
public struct Wave15MultiPlaneClusterCheck: Check {
    public static let id = "rootstock.check.vuln.wave15_multi_plane_cluster"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let planes = Self.pairPlanes(state: state)
        guard planes.count >= 2 else { return [] }
        return [Self.compoundFinding(planes: planes, state: state)]
    }
    private static func pairPlanes(state: CollectedState) -> [String] {
        var planes: [String] = []

        let _photos_library_path = state.photosLibraryPath
        if _photos_library_path?.photosSurfacePresent == true
            || ((_photos_library_path?.photosAppPaths.count ?? 0) >= 1)
            || ((_photos_library_path?.photosLibraryPaths.count ?? 0) >= 1) {
            planes.append("photos_library_path")
        }

        let _vpn_config_dualuse = state.vpnConfigDualuse
        if _vpn_config_dualuse?.vpnSurfacePresent == true
            || ((_vpn_config_dualuse?.vpnFrameworkPaths.count ?? 0) >= 1)
            || ((_vpn_config_dualuse?.vpnPrefPaths.count ?? 0) >= 1) {
            planes.append("vpn_config_dualuse")
        }

        let _sandbox_container_depth = state.sandboxContainerDepth
        if _sandbox_container_depth?.sandboxSurfacePresent == true
            || ((_sandbox_container_depth?.containerRootPaths.count ?? 0) >= 1)
            || ((_sandbox_container_depth?.sandboxProfilePaths.count ?? 0) >= 1) {
            planes.append("sandbox_container_depth")
        }

        let _xpc_mach_service_depth = state.xpcMachServiceDepth
        if _xpc_mach_service_depth?.xpcMachSurfacePresent == true
            || ((_xpc_mach_service_depth?.xpcBootstrapPaths.count ?? 0) >= 1)
            || ((_xpc_mach_service_depth?.machServicePlistPaths.count ?? 0) >= 1) {
            planes.append("xpc_mach_service_depth")
        }

        let _tm_local_snapshot_depth = state.tmLocalSnapshotDepth
        if _tm_local_snapshot_depth?.tmSnapshotSurfacePresent == true
            || ((_tm_local_snapshot_depth?.tmUtilPaths.count ?? 0) >= 1)
            || ((_tm_local_snapshot_depth?.snapshotStorePaths.count ?? 0) >= 1) {
            planes.append("tm_local_snapshot_depth")
        }

        let _emond_legacy_depth = state.emondLegacyDepth
        if _emond_legacy_depth?.emondSurfacePresent == true
            || ((_emond_legacy_depth?.emondBinaryPaths.count ?? 0) >= 1)
            || ((_emond_legacy_depth?.emondRulePaths.count ?? 0) >= 1) {
            planes.append("emond_legacy_depth")
        }

        let _screen_sharing_ard_depth = state.screenSharingArdDepth
        if _screen_sharing_ard_depth?.ardSurfacePresent == true
            || ((_screen_sharing_ard_depth?.screenSharingAppPaths.count ?? 0) >= 1)
            || ((_screen_sharing_ard_depth?.ardAgentPaths.count ?? 0) >= 1) {
            planes.append("screen_sharing_ard_depth")
        }

        let _keychain_acl_path = state.keychainAclPath
        if _keychain_acl_path?.keychainAclSurfacePresent == true
            || ((_keychain_acl_path?.keychainDbPaths.count ?? 0) >= 1)
            || ((_keychain_acl_path?.securityToolPaths.count ?? 0) >= 1) {
            planes.append("keychain_acl_path")
        }

        let _python_runtime_dualuse = state.pythonRuntimeDualuse
        if _python_runtime_dualuse?.pythonSurfacePresent == true
            || ((_python_runtime_dualuse?.pythonBinaryPaths.count ?? 0) >= 1)
            || ((_python_runtime_dualuse?.sitePackagePaths.count ?? 0) >= 1) {
            planes.append("python_runtime_dualuse")
        }

        let _shell_plugin_manager = state.shellPluginManager
        if _shell_plugin_manager?.shellPluginSurfacePresent == true
            || ((_shell_plugin_manager?.omzPaths.count ?? 0) >= 1)
            || ((_shell_plugin_manager?.pluginDirPaths.count ?? 0) >= 1) {
            planes.append("shell_plugin_manager")
        }

        return planes
    }
    private static func amplifiers(state: CollectedState) -> [String] {
        var amps: [String] = []
        if state.network?.remoteLoginSSH == true || state.network?.screenSharingARD == true { amps.append("remote") }
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
        let severity: Severity = (sorted.count >= 5 && amps.contains("remote") && amps.contains("fda")) ? .high
            : ((sorted.count >= 3 || (sorted.count >= 2 && amps.count >= 2)) ? .medium : .low)
        return Finding(
            id: "\(id).multi_plane",
            title: "Wave-15 multi-plane compound: \(sorted.count) planes (\(sorted.joined(separator: ", ")))",
            severity: severity, confidence: .low, category: .misconfig,
            evidence: [
                Evidence(type: "planes", detail: "planes=\(sorted.joined(separator: "|")) count=\(sorted.count)"),
                Evidence(type: "amplifiers", detail: amps.isEmpty ? "amplifiers=none" : "amplifiers=\(amps.joined(separator: "|")) count=\(amps.count)"),
                Evidence(type: "stage_labels", detail: "stages=collection|remote|sandbox|lolbin|persist (labels only - not auto-exploit)"),
                Evidence(type: "host", detail: "host=\(state.host?.hostname ?? "unknown") user=\(state.host?.username ?? "unknown")"),
                Evidence(type: "honesty", detail: "Wave-15 multi-plane ranking is path-to-impact narrative. Rootstock Red does not dump Photos/keychain secrets, enable ARD/VPN, break sandbox, install emond/cron, or run Python/shell plugin payloads."),
            ],
            attackTechniques: ["T1005", "T1021", "T1555.001", "T1059.006", "T1546.004", "T1546.014"],
            remediation: [
                "Prioritize hosts co-locating multiple Wave-15 planes with remote/FDA amplifiers",
                "Close remote access before deep dual-use inventory",
                "Use Wave-15 lab plans under ROE for purple validation",
                "OPSEC: multi-plane compounds are engagement narrative, not exploit scripts",
            ],
            falsePositiveNotes: "Developer workstations may co-locate many Wave-15 planes. Rank production remote hosts first.",
            dryRunSafe: true, opsecScore: 28, esfExpected: ["OPEN", "EXEC", "READ"]
        )
    }
}
