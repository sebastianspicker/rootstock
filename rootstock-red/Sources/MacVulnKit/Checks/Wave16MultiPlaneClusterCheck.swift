import Foundation
import RootstockCore

/// Multi-plane Wave-16 compound ranking (25 net-new themes / 50 red|blue half-pairs beyond Wave-15).
public struct Wave16MultiPlaneClusterCheck: Check {
    public static let id = "rootstock.check.vuln.wave16_multi_plane_cluster"
    public static let cost: CollectorCost = .low
    public init() {}
    public func evaluate(state: CollectedState, context: EvaluationContext) async throws -> [Finding] {
        let planes = Self.pairPlanes(state: state)
        guard planes.count >= 2 else { return [] }
        return [Self.compoundFinding(planes: planes, state: state)]
    }
    private static func pairPlanes(state: CollectedState) -> [String] {
        var planes: [String] = []

        let _airplay_receiver_surface = state.airplayReceiverSurface
        if _airplay_receiver_surface?.airplaySurfacePresent == true
            || ((_airplay_receiver_surface?.airplayDaemonPaths.count ?? 0) >= 1)
            || ((_airplay_receiver_surface?.airplayPrefPaths.count ?? 0) >= 1) {
            planes.append("airplay_receiver_surface")
        }

        let _handoff_clipboard_depth = state.handoffClipboardDepth
        if _handoff_clipboard_depth?.handoffSurfacePresent == true
            || ((_handoff_clipboard_depth?.handoffFrameworkPaths.count ?? 0) >= 1)
            || ((_handoff_clipboard_depth?.clipboardPathHits.count ?? 0) >= 1) {
            planes.append("handoff_clipboard_depth")
        }

        let _imessage_path_plane = state.imessagePathPlane
        if _imessage_path_plane?.imessageSurfacePresent == true
            || ((_imessage_path_plane?.messagesAppPaths.count ?? 0) >= 1)
            || ((_imessage_path_plane?.messagesDbPaths.count ?? 0) >= 1) {
            planes.append("imessage_path_plane")
        }

        let _facetime_camera_surface = state.facetimeCameraSurface
        if _facetime_camera_surface?.facetimeSurfacePresent == true
            || ((_facetime_camera_surface?.facetimeAppPaths.count ?? 0) >= 1)
            || ((_facetime_camera_surface?.avConferencePaths.count ?? 0) >= 1) {
            planes.append("facetime_camera_surface")
        }

        let _finder_sync_extension = state.finderSyncExtension
        if _finder_sync_extension?.finderSyncSurfacePresent == true
            || ((_finder_sync_extension?.finderSyncFrameworkPaths.count ?? 0) >= 1)
            || ((_finder_sync_extension?.appScriptPaths.count ?? 0) >= 1) {
            planes.append("finder_sync_extension")
        }

        let _fileprovider_domain = state.fileproviderDomain
        if _fileprovider_domain?.fileProviderSurfacePresent == true
            || ((_fileprovider_domain?.fileProviderFrameworkPaths.count ?? 0) >= 1)
            || ((_fileprovider_domain?.cloudStoragePaths.count ?? 0) >= 1) {
            planes.append("fileprovider_domain")
        }

        let _notification_center_depth = state.notificationCenterDepth
        if _notification_center_depth?.notificationSurfacePresent == true
            || ((_notification_center_depth?.notificationFrameworkPaths.count ?? 0) >= 1)
            || ((_notification_center_depth?.notificationStorePaths.count ?? 0) >= 1) {
            planes.append("notification_center_depth")
        }

        let _siri_suggestions_plane = state.siriSuggestionsPlane
        if _siri_suggestions_plane?.siriSurfacePresent == true
            || ((_siri_suggestions_plane?.siriFrameworkPaths.count ?? 0) >= 1)
            || ((_siri_suggestions_plane?.suggestionsStorePaths.count ?? 0) >= 1) {
            planes.append("siri_suggestions_plane")
        }

        let _spotlight_importer_depth = state.spotlightImporterDepth
        if _spotlight_importer_depth?.spotlightImporterSurfacePresent == true
            || ((_spotlight_importer_depth?.metadataToolPaths.count ?? 0) >= 1)
            || ((_spotlight_importer_depth?.spotlightImporterPaths.count ?? 0) >= 1) {
            planes.append("spotlight_importer_depth")
        }

        let _contacts_path_plane = state.contactsPathPlane
        if _contacts_path_plane?.contactsSurfacePresent == true
            || ((_contacts_path_plane?.contactsAppPaths.count ?? 0) >= 1)
            || ((_contacts_path_plane?.addressBookPaths.count ?? 0) >= 1) {
            planes.append("contacts_path_plane")
        }

        let _calendar_server_path = state.calendarServerPath
        if _calendar_server_path?.caldavSurfacePresent == true
            || ((_calendar_server_path?.caldavFrameworkPaths.count ?? 0) >= 1)
            || ((_calendar_server_path?.calendarsStorePaths.count ?? 0) >= 1) {
            planes.append("calendar_server_path")
        }

        let _reminders_cloud_path = state.remindersCloudPath
        if _reminders_cloud_path?.remindersCloudSurfacePresent == true
            || ((_reminders_cloud_path?.remindersAppPaths.count ?? 0) >= 1)
            || ((_reminders_cloud_path?.remindersStorePaths.count ?? 0) >= 1) {
            planes.append("reminders_cloud_path")
        }

        let _maps_location_path = state.mapsLocationPath
        if _maps_location_path?.mapsLocationSurfacePresent == true
            || ((_maps_location_path?.mapsAppPaths.count ?? 0) >= 1)
            || ((_maps_location_path?.mapsCachePaths.count ?? 0) >= 1) {
            planes.append("maps_location_path")
        }

        let _weather_widget_path = state.weatherWidgetPath
        if _weather_widget_path?.weatherSurfacePresent == true
            || ((_weather_widget_path?.weatherAppPaths.count ?? 0) >= 1)
            || ((_weather_widget_path?.weatherContainerPaths.count ?? 0) >= 1) {
            planes.append("weather_widget_path")
        }

        let _music_library_path = state.musicLibraryPath
        if _music_library_path?.musicSurfacePresent == true
            || ((_music_library_path?.musicAppPaths.count ?? 0) >= 1)
            || ((_music_library_path?.musicLibraryPaths.count ?? 0) >= 1) {
            planes.append("music_library_path")
        }

        let _books_path_plane = state.booksPathPlane
        if _books_path_plane?.booksSurfacePresent == true
            || ((_books_path_plane?.booksAppPaths.count ?? 0) >= 1)
            || ((_books_path_plane?.booksContainerPaths.count ?? 0) >= 1) {
            planes.append("books_path_plane")
        }

        let _podcasts_path_plane = state.podcastsPathPlane
        if _podcasts_path_plane?.podcastsSurfacePresent == true
            || ((_podcasts_path_plane?.podcastsAppPaths.count ?? 0) >= 1)
            || ((_podcasts_path_plane?.podcastsStorePaths.count ?? 0) >= 1) {
            planes.append("podcasts_path_plane")
        }

        let _tv_app_path_plane = state.tvAppPathPlane
        if _tv_app_path_plane?.tvSurfacePresent == true
            || ((_tv_app_path_plane?.tvAppPaths.count ?? 0) >= 1)
            || ((_tv_app_path_plane?.tvContainerPaths.count ?? 0) >= 1) {
            planes.append("tv_app_path_plane")
        }

        let _homekit_path_plane = state.homekitPathPlane
        if _homekit_path_plane?.homekitSurfacePresent == true
            || ((_homekit_path_plane?.homeAppPaths.count ?? 0) >= 1)
            || ((_homekit_path_plane?.homeKitStorePaths.count ?? 0) >= 1) {
            planes.append("homekit_path_plane")
        }

        let _health_path_plane = state.healthPathPlane
        if _health_path_plane?.healthSurfacePresent == true
            || ((_health_path_plane?.healthAppPaths.count ?? 0) >= 1)
            || ((_health_path_plane?.healthStorePaths.count ?? 0) >= 1) {
            planes.append("health_path_plane")
        }

        let _wallet_pass_path = state.walletPassPath
        if _wallet_pass_path?.walletSurfacePresent == true
            || ((_wallet_pass_path?.walletAppPaths.count ?? 0) >= 1)
            || ((_wallet_pass_path?.passesStorePaths.count ?? 0) >= 1) {
            planes.append("wallet_pass_path")
        }

        let _findmy_path_plane = state.findmyPathPlane
        if _findmy_path_plane?.findmySurfacePresent == true
            || ((_findmy_path_plane?.findMyAppPaths.count ?? 0) >= 1)
            || ((_findmy_path_plane?.findMyCachePaths.count ?? 0) >= 1) {
            planes.append("findmy_path_plane")
        }

        let _shortcuts_icloud_sync = state.shortcutsIcloudSync
        if _shortcuts_icloud_sync?.shortcutsIcloudSurfacePresent == true
            || ((_shortcuts_icloud_sync?.shortcutsAppPaths.count ?? 0) >= 1)
            || ((_shortcuts_icloud_sync?.shortcutsDbPaths.count ?? 0) >= 1) {
            planes.append("shortcuts_icloud_sync")
        }

        let _devicemanagement_profile = state.devicemanagementProfile
        if _devicemanagement_profile?.deviceMgmtSurfacePresent == true
            || ((_devicemanagement_profile?.profilesToolPaths.count ?? 0) >= 1)
            || ((_devicemanagement_profile?.managedPrefPaths.count ?? 0) >= 1) {
            planes.append("devicemanagement_profile")
        }

        let _softwareupdate_catalog = state.softwareupdateCatalog
        if _softwareupdate_catalog?.softwareUpdateSurfacePresent == true
            || ((_softwareupdate_catalog?.softwareUpdateToolPaths.count ?? 0) >= 1)
            || ((_softwareupdate_catalog?.softwareUpdatePrefPaths.count ?? 0) >= 1) {
            planes.append("softwareupdate_catalog")
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
        let severity: Severity = (sorted.count >= 6 && amps.contains("remote") && amps.contains("fda")) ? .high
            : ((sorted.count >= 3 || (sorted.count >= 2 && amps.count >= 2)) ? .medium : .low)
        return Finding(
            id: "\(id).multi_plane",
            title: "Wave-16 multi-plane compound: \(sorted.count) planes (\(sorted.joined(separator: ", ")))",
            severity: severity, confidence: .low, category: .misconfig,
            evidence: [
                Evidence(type: "planes", detail: "planes=\(sorted.joined(separator: "|")) count=\(sorted.count)"),
                Evidence(type: "amplifiers", detail: amps.isEmpty ? "amplifiers=none" : "amplifiers=\(amps.joined(separator: "|")) count=\(amps.count)"),
                Evidence(type: "stage_labels", detail: "stages=collection|privacy|mdm|media|automation (labels only - not auto-exploit)"),
                Evidence(type: "host", detail: "host=\(state.host?.hostname ?? "unknown") user=\(state.host?.username ?? "unknown")"),
                Evidence(type: "honesty", detail: "Wave-16 multi-plane ranking is path-to-impact narrative across 25 planes / 50 red|blue half-pairs. Rootstock Red does not dump app contents, location, Health/Wallet secrets, install MDM profiles, or rewrite Software Update catalogs."),
            ],
            attackTechniques: ["T1005", "T1083", "T1213", "T1484", "T1072", "T1115"],
            remediation: [
                "Prioritize hosts co-locating multiple Wave-16 planes with remote/FDA amplifiers",
                "Close remote access before deep dual-use inventory",
                "Use Wave-16 lab plans under ROE for purple validation",
                "OPSEC: multi-plane compounds are engagement narrative, not exploit scripts",
            ],
            falsePositiveNotes: "Consumer Macs co-locate many first-party app path planes. Rank production remote hosts with FDA amplifiers first.",
            dryRunSafe: true, opsecScore: 28, esfExpected: ["OPEN", "EXEC", "READ"]
        )
    }
}
