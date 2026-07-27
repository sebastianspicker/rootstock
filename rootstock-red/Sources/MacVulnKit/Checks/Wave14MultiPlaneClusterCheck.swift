import Foundation
import RootstockCore

/// Multi-plane Wave-14 compound ranking (10 net-new themes beyond Wave-13).
public struct Wave14MultiPlaneClusterCheck: Check {
    public static let id = "rootstock.check.vuln.wave14_multi_plane_cluster"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let planes = Self.pairPlanes(state: state)
        guard planes.count >= 2 else { return [] }
        return [Self.compoundFinding(planes: planes, state: state)]
    }
    private static func pairPlanes(state: CollectedState) -> [String] {
        var planes: [String] = []

        let _automator_workflow = state.automatorWorkflow
        if _automator_workflow?.workflowSurfacePresent == true
            || ((_automator_workflow?.automatorAppPaths.count ?? 0) >= 1)
            || ((_automator_workflow?.workflowSamplePaths.count ?? 0) >= 1) {
            planes.append("automator_workflow")
        }

        let _icloud_drive_path = state.icloudDrivePath
        if _icloud_drive_path?.icloudPathSurfacePresent == true
            || ((_icloud_drive_path?.mobileDocumentsPaths.count ?? 0) >= 1)
            || ((_icloud_drive_path?.icloudDrivePaths.count ?? 0) >= 1) {
            planes.append("icloud_drive_path")
        }

        let _bluetooth_continuity_depth = state.bluetoothContinuityDepth
        if _bluetooth_continuity_depth?.btContinuitySurfacePresent == true
            || ((_bluetooth_continuity_depth?.bluetoothDaemonPaths.count ?? 0) >= 1)
            || ((_bluetooth_continuity_depth?.continuitySupportPaths.count ?? 0) >= 1) {
            planes.append("bluetooth_continuity_depth")
        }

        let _font_validation_dualuse = state.fontValidationDualuse
        if _font_validation_dualuse?.fontSurfacePresent == true
            || ((_font_validation_dualuse?.fontToolPaths.count ?? 0) >= 1)
            || ((_font_validation_dualuse?.atsSupportPaths.count ?? 0) >= 1) {
            planes.append("font_validation_dualuse")
        }

        let _quicklook_cache_depth = state.quicklookCacheDepth
        if _quicklook_cache_depth?.quicklookSurfacePresent == true
            || ((_quicklook_cache_depth?.quicklookDaemonPaths.count ?? 0) >= 1)
            || ((_quicklook_cache_depth?.thumbnailCachePaths.count ?? 0) >= 1) {
            planes.append("quicklook_cache_depth")
        }

        let _dns_resolver_dualuse = state.dnsResolverDualuse
        if _dns_resolver_dualuse?.dnsSurfacePresent == true
            || ((_dns_resolver_dualuse?.mdnsResponderPaths.count ?? 0) >= 1)
            || ((_dns_resolver_dualuse?.resolverConfigPaths.count ?? 0) >= 1) {
            planes.append("dns_resolver_dualuse")
        }

        let _ls_quarantine_db_depth = state.lsQuarantineDbDepth
        if _ls_quarantine_db_depth?.quarantineDbSurfacePresent == true
            || ((_ls_quarantine_db_depth?.quarantineDbPaths.count ?? 0) >= 1)
            || ((_ls_quarantine_db_depth?.lsSupportPaths.count ?? 0) >= 1) {
            planes.append("ls_quarantine_db_depth")
        }

        let _pam_auth_module = state.pamAuthModule
        if _pam_auth_module?.pamSurfacePresent == true
            || ((_pam_auth_module?.pamConfigPaths.count ?? 0) >= 1)
            || ((_pam_auth_module?.pamModulePaths.count ?? 0) >= 1) {
            planes.append("pam_auth_module")
        }

        let _cron_at_job_depth = state.cronAtJobDepth
        if _cron_at_job_depth?.cronAtSurfacePresent == true
            || ((_cron_at_job_depth?.cronBinaryPaths.count ?? 0) >= 1)
            || ((_cron_at_job_depth?.crontabPaths.count ?? 0) >= 1) {
            planes.append("cron_at_job_depth")
        }

        let _notes_metadata_plane = state.notesMetadataPlane
        if _notes_metadata_plane?.notesSurfacePresent == true
            || ((_notes_metadata_plane?.notesAppPaths.count ?? 0) >= 1)
            || ((_notes_metadata_plane?.notesStorePaths.count ?? 0) >= 1) {
            planes.append("notes_metadata_plane")
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
            title: "Wave-14 multi-plane compound: \(sorted.count) planes (\(sorted.joined(separator: ", ")))",
            severity: severity, confidence: .low, category: .misconfig,
            evidence: [
                Evidence(type: "planes", detail: "planes=\(sorted.joined(separator: "|")) count=\(sorted.count)"),
                Evidence(type: "amplifiers", detail: amps.isEmpty ? "amplifiers=none" : "amplifiers=\(amps.joined(separator: "|")) count=\(amps.count)"),
                Evidence(type: "stage_labels", detail: "stages=delivery|collection|auth|network|persist (labels only - not auto-exploit)"),
                Evidence(type: "host", detail: "host=\(state.host?.hostname ?? "unknown") user=\(state.host?.username ?? "unknown")"),
                Evidence(type: "honesty", detail: "Wave-14 multi-plane ranking is path-to-impact narrative. Rootstock Red does not execute Automator, dump iCloud/Notes contents, spoof Continuity, install fonts, rewrite DNS/PAM/cron, or clear QuarantineEvents."),
            ],
            attackTechniques: ["T1059", "T1530", "T1556", "T1053.003", "T1071.004", "T1553.001"],
            remediation: [
                "Prioritize hosts co-locating multiple Wave-14 planes with remote/FDA amplifiers",
                "Close remote access before deep dual-use inventory",
                "Use Wave-14 lab plans under ROE for purple validation",
                "OPSEC: multi-plane compounds are engagement narrative, not exploit scripts",
            ],
            falsePositiveNotes: "Developer workstations may co-locate many Wave-14 planes. Rank production remote hosts first.",
            dryRunSafe: true, opsecScore: 28, esfExpected: ["OPEN", "EXEC", "READ"]
        )
    }
}
