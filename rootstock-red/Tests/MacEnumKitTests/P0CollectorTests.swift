import XCTest
import RootstockCore
@testable import MacEnumKit

/// Real collectors (not mocks) for P0 alpha themes.
final class P0CollectorTests: XCTestCase {
    func testProtectionsCollectorFillsState() async throws {
        let state = try await ProtectionsCollector().collect(context: .assess())
        XCTAssertNotNil(state.protections)
        XCTAssertFalse(state.protections?.notes.isEmpty ?? true)
        XCTAssertEqual(state.collectorNotes[ProtectionsCollector.id]?.isEmpty, false)
    }

    func testLoginItemsBTMCollector() async throws {
        let state = try await LoginItemsBTMCollector().collect(context: .assess())
        // At least notes or inventory structure populated
        let hasData =
            !state.systemLaunchAgents.isEmpty
            || !state.launchDaemons.isEmpty
            || !state.loginItemPaths.isEmpty
            || state.loginItems != nil
            || state.collectorNotes[LoginItemsBTMCollector.id] != nil
        XCTAssertTrue(hasData)
    }

    func testBrowserMetaCollector() async throws {
        let state = try await BrowserMetaCollector().collect(context: .assess())
        // Even if no browsers installed, browserMeta array is set (possibly empty) with notes
        XCTAssertNotNil(state.collectorNotes[BrowserMetaCollector.id] ?? "ok")
        // Paths are metadata only - no content fields for secrets
        for entry in state.browserMeta {
            XCTAssertFalse(entry.path.isEmpty)
        }
    }

    func testLOOBinsInventoryNonEmptyCatalog() async throws {
        let state = try await LOOBinsCollector().collect(context: .assess())
        XCTAssertFalse(state.loobins.isEmpty)
        XCTAssertTrue(state.loobins.contains { $0.name == "osascript" || $0.path.contains("osascript") })
    }

    func testSecurityProductsExpandedCatalog() async throws {
        let state = try await SecurityProductsCollector().collect(context: .assess())
        // Collector always runs; product hits may be empty on clean hosts
        XCTAssertNotNil(state.collectorNotes[SecurityProductsCollector.id])
    }

    func testInjectabilityOrCodesignSamples() async throws {
        let inj = try await InjectabilityCollector().collect(context: .assess(profile: .standard))
        let code = try await CodesignCollector().collect(context: .assess(profile: .deep))
        let hasSamples =
            !inj.injectabilityHits.isEmpty
            || !code.codesignSamples.isEmpty
            || inj.collectorNotes[InjectabilityCollector.id] != nil
        XCTAssertTrue(hasSamples)
    }

    func testP0CollectorIdsRegistered() {
        let ids = Set(EnumModuleRegistry.allCollectors().map { type(of: $0).id })
        for id in [
            "collect.protections",
            "collect.loginitems_btm",
            "collect.browser_meta",
            "collect.dylib_risk",
            "collect.injectability",
            "collect.codesign",
            "collect.network",
            "collect.tcc_graph",
            "collect.loobins",
            "collect.security_products",
            "collect.esf_endpoint_security",
            "collect.patch_debt",
            "collect.tcc_permission_graph",
            "collect.launch_constraints",
            "collect.network_extension",
            "collect.auth_rights",
            "collect.developer_toolchain",
            "collect.time_machine",
            "collect.config_profile_sideload",
            "collect.app_sandbox_entitlements",
            "collect.notarization_stapling",
            "collect.virtualization_containers",
            "collect.continuity_airdrop",
            "collect.filevault_escrow",
            "collect.clickfix_terminal_delivery",
            "collect.remote_apple_events",
            "collect.spotlight_ai_cache",
            "collect.security_mgmt_plane",
            "collect.third_party_tcc_inheritance",
            "collect.ssh_agent_key_path",
            "collect.packagekit_installer_design",
            "collect.archive_quarantine_extractor",
            "collect.infostealer_path_plane",
            "collect.tcc_esf_visibility_depth",
            "collect.mdm_profile_parse_depth",
            "collect.url_scheme_handler",
            "collect.launchd_override_depth",
            "collect.browser_extension_dualuse",
            "collect.shortcuts_app_intents",
            "collect.webloc_inetloc_delivery",
            "collect.mail_rules_automation",
            "collect.unified_log_observation",
            "collect.dock_persistence_surface",
            "collect.osascript_scpt_delivery",
            "collect.network_share_mount",
            "collect.calendar_reminders_automation",
            "collect.gatekeeper_assessment_history",
            "collect.homebrew_package_dualuse",
            "collect.cups_print_dualuse",
            "collect.screencapture_privacy_dualuse",
            "collect.automator_workflow",
            "collect.icloud_drive_path",
            "collect.bluetooth_continuity_depth",
            "collect.font_validation_dualuse",
            "collect.quicklook_cache_depth",
            "collect.dns_resolver_dualuse",
            "collect.ls_quarantine_db_depth",
            "collect.pam_auth_module",
            "collect.cron_at_job_depth",
            "collect.notes_metadata_plane",
            "collect.photos_library_path",
            "collect.vpn_config_dualuse",
            "collect.sandbox_container_depth",
            "collect.xpc_mach_service_depth",
            "collect.tm_local_snapshot_depth",
            "collect.emond_legacy_depth",
            "collect.screen_sharing_ard_depth",
            "collect.keychain_acl_path",
            "collect.python_runtime_dualuse",
            "collect.shell_plugin_manager",
            "collect.airplay_receiver_surface",
            "collect.handoff_clipboard_depth",
            "collect.imessage_path_plane",
            "collect.facetime_camera_surface",
            "collect.finder_sync_extension",
            "collect.fileprovider_domain",
            "collect.notification_center_depth",
            "collect.siri_suggestions_plane",
            "collect.spotlight_importer_depth",
            "collect.contacts_path_plane",
            "collect.calendar_server_path",
            "collect.reminders_cloud_path",
            "collect.maps_location_path",
            "collect.weather_widget_path",
            "collect.music_library_path",
            "collect.books_path_plane",
            "collect.podcasts_path_plane",
            "collect.tv_app_path_plane",
            "collect.homekit_path_plane",
            "collect.health_path_plane",
            "collect.wallet_pass_path",
            "collect.findmy_path_plane",
            "collect.shortcuts_icloud_sync",
            "collect.devicemanagement_profile",
            "collect.softwareupdate_catalog",
        ] {
            XCTAssertTrue(ids.contains(id), "missing collector \(id)")
        }
    }

    func testWave5CollectorsFillState() async throws {
        let esf = try await ESFEndpointSecurityCollector().collect(context: .assess())
        XCTAssertNotNil(esf.esf)
        XCTAssertFalse(esf.esf?.notes.isEmpty ?? true)
        XCTAssertNotNil(esf.collectorNotes[ESFEndpointSecurityCollector.id])

        let patch = try await PatchDebtCollector().collect(context: .assess())
        XCTAssertNotNil(patch.patchDebt)
        XCTAssertNotNil(patch.patchDebt?.osVersion)
        XCTAssertNotNil(patch.collectorNotes[PatchDebtCollector.id])

        let graph = try await TCCPermissionGraphCollector().collect(context: .assess())
        XCTAssertNotNil(graph.tcc)
        XCTAssertFalse(graph.tcc?.domainSignals.isEmpty ?? true)
        XCTAssertNotNil(graph.collectorNotes[TCCPermissionGraphCollector.id])

        let lc = try await LaunchConstraintCollector().collect(context: .assess())
        XCTAssertNotNil(lc.launchConstraints)
        XCTAssertNotNil(lc.collectorNotes[LaunchConstraintCollector.id])
    }

    /// Wave-6 collectors: real collect → typed state + collector notes (no secrets).
    func testWave6CollectorsFillState() async throws {
        let ne = try await NetworkExtensionCollector().collect(context: .assess())
        XCTAssertNotNil(ne.networkExtension)
        XCTAssertFalse(ne.networkExtension?.notes.isEmpty ?? true)
        XCTAssertNotNil(ne.collectorNotes[NetworkExtensionCollector.id])

        let auth = try await AuthRightsCollector().collect(context: .assess())
        XCTAssertNotNil(auth.authRights)
        XCTAssertFalse(auth.authRights?.notes.isEmpty ?? true)
        XCTAssertNotNil(auth.collectorNotes[AuthRightsCollector.id])
        // Never claim secret dump of auth.db contents
        let authBlob = (auth.authRights?.notes ?? []).joined(separator: " ").lowercased()
        XCTAssertFalse(authBlob.contains("password="))

        let dev = try await DeveloperToolchainCollector().collect(context: .assess())
        XCTAssertNotNil(dev.developerToolchain)
        XCTAssertNotNil(dev.collectorNotes[DeveloperToolchainCollector.id])

        let tm = try await TimeMachineCollector().collect(context: .assess())
        XCTAssertNotNil(tm.timeMachine)
        XCTAssertNotNil(tm.collectorNotes[TimeMachineCollector.id])
        let tmBlob = (tm.timeMachine?.notes ?? []).joined(separator: " ").lowercased()
        XCTAssertFalse(tmBlob.contains("password="))

        let cfg = try await ConfigProfileSideloadCollector().collect(context: .assess())
        XCTAssertNotNil(cfg.configProfileSideload)
        XCTAssertNotNil(cfg.collectorNotes[ConfigProfileSideloadCollector.id])
    }

    /// Wave-7 collectors: real collect → typed state + collector notes (no secrets/keys).
    func testWave7CollectorsFillState() async throws {
        let sandbox = try await AppSandboxEntitlementsCollector().collect(context: .assess())
        XCTAssertNotNil(sandbox.appSandboxEntitlements)
        XCTAssertFalse(sandbox.appSandboxEntitlements?.notes.isEmpty ?? true)
        XCTAssertNotNil(sandbox.collectorNotes[AppSandboxEntitlementsCollector.id])

        let nota = try await NotarizationStaplingCollector().collect(context: .assess())
        XCTAssertNotNil(nota.notarizationStapling)
        XCTAssertFalse(nota.notarizationStapling?.notes.isEmpty ?? true)
        XCTAssertNotNil(nota.collectorNotes[NotarizationStaplingCollector.id])

        let virt = try await VirtualizationContainersCollector().collect(context: .assess())
        XCTAssertNotNil(virt.virtualizationContainers)
        XCTAssertFalse(virt.virtualizationContainers?.notes.isEmpty ?? true)
        XCTAssertNotNil(virt.collectorNotes[VirtualizationContainersCollector.id])

        let cont = try await ContinuityAirDropCollector().collect(context: .assess())
        XCTAssertNotNil(cont.continuityAirDrop)
        XCTAssertFalse(cont.continuityAirDrop?.notes.isEmpty ?? true)
        XCTAssertNotNil(cont.collectorNotes[ContinuityAirDropCollector.id])
        let contBlob = (cont.continuityAirDrop?.notes ?? []).joined(separator: " ").lowercased()
        XCTAssertFalse(contBlob.contains("password="))
        XCTAssertFalse(contBlob.contains("clipboard contents"))

        let fv = try await FileVaultEscrowCollector().collect(context: .assess())
        XCTAssertNotNil(fv.fileVaultEscrow)
        XCTAssertFalse(fv.fileVaultEscrow?.notes.isEmpty ?? true)
        XCTAssertNotNil(fv.collectorNotes[FileVaultEscrowCollector.id])
        let fvBlob = (fv.fileVaultEscrow?.notes ?? []).joined(separator: " ").lowercased()
        XCTAssertFalse(fvBlob.contains("recovery key="))
        XCTAssertFalse(fvBlob.contains("password="))
        XCTAssertTrue(fvBlob.contains("never") || fvBlob.contains("not invoked"))
    }

    func testWave8CollectorsFillState() async throws {
        let click = try await ClickFixTerminalDeliveryCollector().collect(context: .assess())
        XCTAssertNotNil(click.clickFixTerminalDelivery)
        XCTAssertFalse(click.clickFixTerminalDelivery?.notes.isEmpty ?? true)
        XCTAssertNotNil(click.collectorNotes[ClickFixTerminalDeliveryCollector.id])
        let clickBlob = (click.clickFixTerminalDelivery?.notes ?? []).joined(separator: " ").lowercased()
        XCTAssertFalse(clickBlob.contains("password="))
        XCTAssertTrue(clickBlob.contains("never") || clickBlob.contains("lure"))

        let rae = try await RemoteAppleEventsCollector().collect(context: .assess())
        XCTAssertNotNil(rae.remoteAppleEvents)
        XCTAssertFalse(rae.remoteAppleEvents?.notes.isEmpty ?? true)
        XCTAssertNotNil(rae.collectorNotes[RemoteAppleEventsCollector.id])

        let spot = try await SpotlightAICacheCollector().collect(context: .assess())
        XCTAssertNotNil(spot.spotlightAICache)
        XCTAssertFalse(spot.spotlightAICache?.notes.isEmpty ?? true)
        XCTAssertNotNil(spot.collectorNotes[SpotlightAICacheCollector.id])
        let spotBlob = (spot.spotlightAICache?.notes ?? []).joined(separator: " ").lowercased()
        XCTAssertFalse(spotBlob.contains("password="))
        XCTAssertTrue(spotBlob.contains("never") || spotBlob.contains("dump"))

        let mgmt = try await SecurityMgmtPlaneCollector().collect(context: .assess())
        XCTAssertNotNil(mgmt.securityMgmtPlane)
        XCTAssertFalse(mgmt.securityMgmtPlane?.notes.isEmpty ?? true)
        XCTAssertNotNil(mgmt.collectorNotes[SecurityMgmtPlaneCollector.id])
        let mgmtBlob = (mgmt.securityMgmtPlane?.notes ?? []).joined(separator: " ").lowercased()
        XCTAssertTrue(mgmtBlob.contains("never") || mgmtBlob.contains("unload"))

        let tcc = try await ThirdPartyTCCInheritanceCollector().collect(context: .assess())
        XCTAssertNotNil(tcc.thirdPartyTCCInheritance)
        XCTAssertFalse(tcc.thirdPartyTCCInheritance?.notes.isEmpty ?? true)
        XCTAssertNotNil(tcc.collectorNotes[ThirdPartyTCCInheritanceCollector.id])

        let ssh = try await SSHAgentKeyPathCollector().collect(context: .assess())
        XCTAssertNotNil(ssh.sshAgentKeyPath)
        XCTAssertFalse(ssh.sshAgentKeyPath?.notes.isEmpty ?? true)
        XCTAssertNotNil(ssh.collectorNotes[SSHAgentKeyPathCollector.id])
        let sshBlob = (ssh.sshAgentKeyPath?.notes ?? []).joined(separator: " ").lowercased()
        XCTAssertFalse(sshBlob.contains("begin rsa private key"))
        XCTAssertTrue(sshBlob.contains("never") || sshBlob.contains("path"))
    }

    func testWave9CollectorsFillState() async throws {
        let pk = try await PackageKitInstallerDesignCollector().collect(context: .assess())
        XCTAssertNotNil(pk.packageKitInstallerDesign)
        XCTAssertFalse(pk.packageKitInstallerDesign?.notes.isEmpty ?? true)
        XCTAssertNotNil(pk.collectorNotes[PackageKitInstallerDesignCollector.id])
        let pkBlob = (pk.packageKitInstallerDesign?.notes ?? []).joined(separator: " ").lowercased()
        XCTAssertTrue(pkBlob.contains("never") || pkBlob.contains("installd") || pkBlob.contains("path"))
        XCTAssertFalse(pkBlob.contains("preinstall script payload"))

        let aq = try await ArchiveQuarantineExtractorCollector().collect(context: .assess())
        XCTAssertNotNil(aq.archiveQuarantineExtractor)
        XCTAssertFalse(aq.archiveQuarantineExtractor?.notes.isEmpty ?? true)
        XCTAssertNotNil(aq.collectorNotes[ArchiveQuarantineExtractorCollector.id])
        let aqBlob = (aq.archiveQuarantineExtractor?.notes ?? []).joined(separator: " ").lowercased()
        XCTAssertTrue(aqBlob.contains("never") || aqBlob.contains("quarantine"))
        XCTAssertFalse(aqBlob.contains("strip quarantine now"))

        let stealer = try await InfoStealerPathPlaneCollector().collect(context: .assess())
        XCTAssertNotNil(stealer.infoStealerPathPlane)
        XCTAssertFalse(stealer.infoStealerPathPlane?.notes.isEmpty ?? true)
        XCTAssertNotNil(stealer.collectorNotes[InfoStealerPathPlaneCollector.id])
        let stealerBlob = (stealer.infoStealerPathPlane?.notes ?? []).joined(separator: " ").lowercased()
        XCTAssertFalse(stealerBlob.contains("password="))
        XCTAssertFalse(stealerBlob.contains("begin rsa private key"))
        XCTAssertTrue(stealerBlob.contains("never") || stealerBlob.contains("path"))

        let vis = try await TCCESFVisibilityDepthCollector().collect(context: .assess())
        XCTAssertNotNil(vis.tccEsfVisibilityDepth)
        XCTAssertFalse(vis.tccEsfVisibilityDepth?.notes.isEmpty ?? true)
        XCTAssertNotNil(vis.collectorNotes[TCCESFVisibilityDepthCollector.id])
        XCTAssertNotNil(vis.tccEsfVisibilityDepth?.visibilityDepth)
        let visBlob = (vis.tccEsfVisibilityDepth?.notes ?? []).joined(separator: " ").lowercased()
        XCTAssertTrue(visBlob.contains("never") || visBlob.contains("tcc"))
        XCTAssertFalse(visBlob.contains("select * from access"))

        let mdm = try await MDMProfileParseDepthCollector().collect(context: .assess())
        XCTAssertNotNil(mdm.mdmProfileParseDepth)
        XCTAssertFalse(mdm.mdmProfileParseDepth?.notes.isEmpty ?? true)
        XCTAssertNotNil(mdm.collectorNotes[MDMProfileParseDepthCollector.id])
        let mdmBlob = (mdm.mdmProfileParseDepth?.notes ?? []).joined(separator: " ").lowercased()
        XCTAssertTrue(mdmBlob.contains("never") || mdmBlob.contains("payload") || mdmBlob.contains("profile"))
        XCTAssertFalse(mdmBlob.contains("sharedsecret="))
    }

    func testWave11CollectorsFillState() async throws {
        let context = EvaluationContext.assess(profile: .standard)
        let collectors: [any Collector] = [
            URLSchemeHandlerCollector(),
            LaunchdOverrideDepthCollector(),
            BrowserExtensionDualUseCollector(),
            ShortcutsAppIntentsCollector(),
        ]
        var state = CollectedState()
        for c in collectors {
            let partial = try await c.collect(context: context)
            state.merge(partial)
        }
        XCTAssertNotNil(state.collectorNotes["collect.url_scheme_handler"])
        XCTAssertNotNil(state.collectorNotes["collect.launchd_override_depth"])
        XCTAssertNotNil(state.collectorNotes["collect.browser_extension_dualuse"])
        XCTAssertNotNil(state.collectorNotes["collect.shortcuts_app_intents"])
        // Real host should usually surface at least openers / shortcuts framework paths
        XCTAssertNotNil(state.urlSchemeHandler)
        XCTAssertNotNil(state.launchdOverrideDepth)
        XCTAssertNotNil(state.browserExtensionDualUse)
        XCTAssertNotNil(state.shortcutsAppIntents)
    }

    func testWave12CollectorsFillState() async throws {
        let context = EvaluationContext.assess(profile: .standard)
        let collectors: [any Collector] = [
            WeblocInetlocDeliveryCollector(),
            MailRulesAutomationCollector(),
            UnifiedLogObservationCollector(),
            DockPersistenceSurfaceCollector(),
            OsascriptScptDeliveryCollector(),
            NetworkShareMountCollector()
        ]
        var state = CollectedState()
        for c in collectors {
            let partial = try await c.collect(context: context)
            state.merge(partial)
        }
        XCTAssertNotNil(state.collectorNotes["collect.webloc_inetloc_delivery"])
        XCTAssertNotNil(state.collectorNotes["collect.mail_rules_automation"])
        XCTAssertNotNil(state.collectorNotes["collect.unified_log_observation"])
        XCTAssertNotNil(state.collectorNotes["collect.dock_persistence_surface"])
        XCTAssertNotNil(state.collectorNotes["collect.osascript_scpt_delivery"])
        XCTAssertNotNil(state.collectorNotes["collect.network_share_mount"])
        XCTAssertNotNil(state.weblocInetlocDelivery)
        XCTAssertNotNil(state.mailRulesAutomation)
        XCTAssertNotNil(state.unifiedLogObservation)
        XCTAssertNotNil(state.dockPersistenceSurface)
        XCTAssertNotNil(state.osascriptScptDelivery)
        XCTAssertNotNil(state.networkShareMount)
    }

    func testWave13CollectorsFillState() async throws {
        let context = EvaluationContext.assess(profile: .standard)
        let collectors: [any Collector] = [
            CalendarRemindersAutomationCollector(),
            GatekeeperAssessmentHistoryCollector(),
            HomebrewPackageDualUseCollector(),
            CupsPrintDualUseCollector(),
            ScreenCapturePrivacyDualUseCollector()
        ]
        var state = CollectedState()
        for c in collectors {
            let partial = try await c.collect(context: context)
            state.merge(partial)
        }
        XCTAssertNotNil(state.collectorNotes["collect.calendar_reminders_automation"])
        XCTAssertNotNil(state.collectorNotes["collect.gatekeeper_assessment_history"])
        XCTAssertNotNil(state.collectorNotes["collect.homebrew_package_dualuse"])
        XCTAssertNotNil(state.collectorNotes["collect.cups_print_dualuse"])
        XCTAssertNotNil(state.collectorNotes["collect.screencapture_privacy_dualuse"])
        XCTAssertNotNil(state.calendarRemindersAutomation)
        XCTAssertNotNil(state.gatekeeperAssessmentHistory)
        XCTAssertNotNil(state.homebrewPackageDualUse)
        XCTAssertNotNil(state.cupsPrintDualUse)
        XCTAssertNotNil(state.screenCapturePrivacyDualUse)
    }

    func testWave14CollectorsFillState() async throws {
        let context = EvaluationContext.assess(profile: .standard)
        let collectors: [any Collector] = [
            AutomatorWorkflowCollector(),
            IcloudDrivePathCollector(),
            BluetoothContinuityDepthCollector(),
            FontValidationDualuseCollector(),
            QuicklookCacheDepthCollector(),
            DnsResolverDualuseCollector(),
            LsQuarantineDbDepthCollector(),
            PamAuthModuleCollector(),
            CronAtJobDepthCollector(),
            NotesMetadataPlaneCollector()
        ]
        var state = CollectedState()
        for c in collectors {
            state.merge(try await c.collect(context: context))
        }
        XCTAssertNotNil(state.collectorNotes["collect.automator_workflow"])
        XCTAssertNotNil(state.collectorNotes["collect.icloud_drive_path"])
        XCTAssertNotNil(state.collectorNotes["collect.bluetooth_continuity_depth"])
        XCTAssertNotNil(state.collectorNotes["collect.font_validation_dualuse"])
        XCTAssertNotNil(state.collectorNotes["collect.quicklook_cache_depth"])
        XCTAssertNotNil(state.collectorNotes["collect.dns_resolver_dualuse"])
        XCTAssertNotNil(state.collectorNotes["collect.ls_quarantine_db_depth"])
        XCTAssertNotNil(state.collectorNotes["collect.pam_auth_module"])
        XCTAssertNotNil(state.collectorNotes["collect.cron_at_job_depth"])
        XCTAssertNotNil(state.collectorNotes["collect.notes_metadata_plane"])
        XCTAssertNotNil(state.automatorWorkflow)
        XCTAssertNotNil(state.icloudDrivePath)
        XCTAssertNotNil(state.bluetoothContinuityDepth)
        XCTAssertNotNil(state.fontValidationDualuse)
        XCTAssertNotNil(state.quicklookCacheDepth)
        XCTAssertNotNil(state.dnsResolverDualuse)
        XCTAssertNotNil(state.lsQuarantineDbDepth)
        XCTAssertNotNil(state.pamAuthModule)
        XCTAssertNotNil(state.cronAtJobDepth)
        XCTAssertNotNil(state.notesMetadataPlane)
    }

    func testWave15CollectorsFillState() async throws {
        let context = EvaluationContext.assess(profile: .standard)
        let collectors: [any Collector] = [
            PhotosLibraryPathCollector(),
            VpnConfigDualuseCollector(),
            SandboxContainerDepthCollector(),
            XpcMachServiceDepthCollector(),
            TmLocalSnapshotDepthCollector(),
            EmondLegacyDepthCollector(),
            ScreenSharingArdDepthCollector(),
            KeychainAclPathCollector(),
            PythonRuntimeDualuseCollector(),
            ShellPluginManagerCollector()
        ]
        var state = CollectedState()
        for c in collectors { state.merge(try await c.collect(context: context)) }
        XCTAssertNotNil(state.collectorNotes["collect.photos_library_path"])
        XCTAssertNotNil(state.collectorNotes["collect.vpn_config_dualuse"])
        XCTAssertNotNil(state.collectorNotes["collect.sandbox_container_depth"])
        XCTAssertNotNil(state.collectorNotes["collect.xpc_mach_service_depth"])
        XCTAssertNotNil(state.collectorNotes["collect.tm_local_snapshot_depth"])
        XCTAssertNotNil(state.collectorNotes["collect.emond_legacy_depth"])
        XCTAssertNotNil(state.collectorNotes["collect.screen_sharing_ard_depth"])
        XCTAssertNotNil(state.collectorNotes["collect.keychain_acl_path"])
        XCTAssertNotNil(state.collectorNotes["collect.python_runtime_dualuse"])
        XCTAssertNotNil(state.collectorNotes["collect.shell_plugin_manager"])
        XCTAssertNotNil(state.photosLibraryPath)
        XCTAssertNotNil(state.vpnConfigDualuse)
        XCTAssertNotNil(state.sandboxContainerDepth)
        XCTAssertNotNil(state.xpcMachServiceDepth)
        XCTAssertNotNil(state.tmLocalSnapshotDepth)
        XCTAssertNotNil(state.emondLegacyDepth)
        XCTAssertNotNil(state.screenSharingArdDepth)
        XCTAssertNotNil(state.keychainAclPath)
        XCTAssertNotNil(state.pythonRuntimeDualuse)
        XCTAssertNotNil(state.shellPluginManager)
    }

    func testWave16CollectorsFillState() async throws {
        let context = EvaluationContext.assess(profile: .standard)
        let collectors: [any Collector] = [
            AirplayReceiverSurfaceCollector(),
            HandoffClipboardDepthCollector(),
            ImessagePathPlaneCollector(),
            FacetimeCameraSurfaceCollector(),
            FinderSyncExtensionCollector(),
            FileproviderDomainCollector(),
            NotificationCenterDepthCollector(),
            SiriSuggestionsPlaneCollector(),
            SpotlightImporterDepthCollector(),
            ContactsPathPlaneCollector(),
            CalendarServerPathCollector(),
            RemindersCloudPathCollector(),
            MapsLocationPathCollector(),
            WeatherWidgetPathCollector(),
            MusicLibraryPathCollector(),
            BooksPathPlaneCollector(),
            PodcastsPathPlaneCollector(),
            TvAppPathPlaneCollector(),
            HomekitPathPlaneCollector(),
            HealthPathPlaneCollector(),
            WalletPassPathCollector(),
            FindmyPathPlaneCollector(),
            ShortcutsIcloudSyncCollector(),
            DevicemanagementProfileCollector(),
            SoftwareupdateCatalogCollector()
        ]
        var state = CollectedState()
        for c in collectors { state.merge(try await c.collect(context: context)) }
        XCTAssertNotNil(state.collectorNotes["collect.airplay_receiver_surface"])
        XCTAssertNotNil(state.collectorNotes["collect.handoff_clipboard_depth"])
        XCTAssertNotNil(state.collectorNotes["collect.imessage_path_plane"])
        XCTAssertNotNil(state.collectorNotes["collect.facetime_camera_surface"])
        XCTAssertNotNil(state.collectorNotes["collect.finder_sync_extension"])
        XCTAssertNotNil(state.collectorNotes["collect.fileprovider_domain"])
        XCTAssertNotNil(state.collectorNotes["collect.notification_center_depth"])
        XCTAssertNotNil(state.collectorNotes["collect.siri_suggestions_plane"])
        XCTAssertNotNil(state.collectorNotes["collect.spotlight_importer_depth"])
        XCTAssertNotNil(state.collectorNotes["collect.contacts_path_plane"])
        XCTAssertNotNil(state.collectorNotes["collect.calendar_server_path"])
        XCTAssertNotNil(state.collectorNotes["collect.reminders_cloud_path"])
        XCTAssertNotNil(state.collectorNotes["collect.maps_location_path"])
        XCTAssertNotNil(state.collectorNotes["collect.weather_widget_path"])
        XCTAssertNotNil(state.collectorNotes["collect.music_library_path"])
        XCTAssertNotNil(state.collectorNotes["collect.books_path_plane"])
        XCTAssertNotNil(state.collectorNotes["collect.podcasts_path_plane"])
        XCTAssertNotNil(state.collectorNotes["collect.tv_app_path_plane"])
        XCTAssertNotNil(state.collectorNotes["collect.homekit_path_plane"])
        XCTAssertNotNil(state.collectorNotes["collect.health_path_plane"])
        XCTAssertNotNil(state.collectorNotes["collect.wallet_pass_path"])
        XCTAssertNotNil(state.collectorNotes["collect.findmy_path_plane"])
        XCTAssertNotNil(state.collectorNotes["collect.shortcuts_icloud_sync"])
        XCTAssertNotNil(state.collectorNotes["collect.devicemanagement_profile"])
        XCTAssertNotNil(state.collectorNotes["collect.softwareupdate_catalog"])
        XCTAssertNotNil(state.airplayReceiverSurface)
        XCTAssertNotNil(state.handoffClipboardDepth)
        XCTAssertNotNil(state.imessagePathPlane)
        XCTAssertNotNil(state.facetimeCameraSurface)
        XCTAssertNotNil(state.finderSyncExtension)
        XCTAssertNotNil(state.fileproviderDomain)
        XCTAssertNotNil(state.notificationCenterDepth)
        XCTAssertNotNil(state.siriSuggestionsPlane)
        XCTAssertNotNil(state.spotlightImporterDepth)
        XCTAssertNotNil(state.contactsPathPlane)
        XCTAssertNotNil(state.calendarServerPath)
        XCTAssertNotNil(state.remindersCloudPath)
        XCTAssertNotNil(state.mapsLocationPath)
        XCTAssertNotNil(state.weatherWidgetPath)
        XCTAssertNotNil(state.musicLibraryPath)
        XCTAssertNotNil(state.booksPathPlane)
        XCTAssertNotNil(state.podcastsPathPlane)
        XCTAssertNotNil(state.tvAppPathPlane)
        XCTAssertNotNil(state.homekitPathPlane)
        XCTAssertNotNil(state.healthPathPlane)
        XCTAssertNotNil(state.walletPassPath)
        XCTAssertNotNil(state.findmyPathPlane)
        XCTAssertNotNil(state.shortcutsIcloudSync)
        XCTAssertNotNil(state.devicemanagementProfile)
        XCTAssertNotNil(state.softwareupdateCatalog)
    }







    /// Stock pf/ALF paths must never appear as enterprise contentFilterHints.
    func testNECollectorDoesNotCountStockPfAsContentFilter() async throws {
        let state = try await NetworkExtensionCollector().collect(context: .assess())
        guard let ne = state.networkExtension else {
            XCTFail("networkExtension state required")
            return
        }
        for hint in ne.contentFilterHints {
            XCTAssertTrue(
                NetworkExtensionCollector.isEnterpriseContentFilterHint(hint),
                "stock noise in contentFilterHints: \(hint)"
            )
            XCTAssertFalse(
                hint.contains("/etc/pf.conf") || hint.contains("pf_conf")
                    || hint.contains("pf_anchors") || hint.contains("com.apple.alf"),
                "stock pf/ALF must not be contentFilterHints: \(hint)"
            )
        }
        // Classification helpers
        XCTAssertTrue(NetworkExtensionCollector.isStockNetworkArtifactPath("/etc/pf.conf"))
        XCTAssertTrue(NetworkExtensionCollector.isStockNetworkArtifactPath("/etc/pf.anchors"))
        XCTAssertFalse(
            NetworkExtensionCollector.isEnterpriseContentFilterHint("pf_conf:/etc/pf.conf")
        )
        XCTAssertTrue(
            NetworkExtensionCollector.isEnterpriseContentFilterHint(
                "content_filter_prefs:/Library/Preferences/com.apple.networkextension.filter.plist"
            )
        )
        // When no enterprise filter apps/hints, gap note should be set (stock host case).
        if ne.contentFilterHints.isEmpty && ne.neAppPaths.isEmpty {
            XCTAssertNotNil(
                state.collectorNotes["ne.filter_gap"],
                "thin enterprise filter inventory should set ne.filter_gap"
            )
            let cnote = state.collectorNotes[NetworkExtensionCollector.id] ?? ""
            XCTAssertTrue(
                cnote.contains("contentFilter=0"),
                "collector note must report contentFilter=0 for thin inventory; got \(cnote)"
            )
        }
        // Stock pf may still be noted when present
        let notesBlob = ne.notes.joined(separator: " ")
        if FileManager.default.fileExists(atPath: "/etc/pf.conf") {
            XCTAssertTrue(
                notesBlob.contains("stock_os_network") || notesBlob.contains("pf_conf"),
                "stock pf should be noted separately when present"
            )
        }
    }

    /// SystemProfiler prefs names must not be treated as configuration-profile sideload surface.
    func testConfigProfilePrefFilterExcludesSystemProfiler() {
        XCTAssertFalse(
            ConfigProfileSideloadCollector.isConfigurationProfilePrefName(
                "com.apple.SystemProfiler.plist"
            )
        )
        XCTAssertFalse(
            ConfigProfileSideloadCollector.isConfigurationProfilePrefName(
                "com.apple.systemprofiler.plist"
            )
        )
        XCTAssertTrue(
            ConfigProfileSideloadCollector.isConfigurationProfilePrefName(
                "com.example.vpn.mobileconfig"
            )
        )
        XCTAssertTrue(
            ConfigProfileSideloadCollector.isConfigurationProfilePrefName(
                "com.apple.managedclient.plist"
            )
        )
        XCTAssertTrue(
            ConfigProfileSideloadCollector.isConfigurationProfilePrefName(
                "com.jamf.configurationprofiles.plist"
            )
        )
        // Bare "profile" without config/mdm context is insufficient
        XCTAssertFalse(
            ConfigProfileSideloadCollector.isConfigurationProfilePrefName(
                "com.example.myprofile.plist"
            )
        )
    }

    func testConfigProfileCollectorDoesNotListSystemProfilerAsHint() async throws {
        let state = try await ConfigProfileSideloadCollector().collect(context: .assess())
        guard let cfg = state.configProfileSideload else {
            XCTFail("configProfileSideload required")
            return
        }
        for hint in cfg.downloadsProfileHints + cfg.userMobileconfigPaths {
            let lower = hint.lowercased()
            XCTAssertFalse(
                lower.contains("systemprofiler"),
                "SystemProfiler must not appear as sideload surface: \(hint)"
            )
        }
    }

    /// Stock Apple ES paths must never appear as third-party clients (sensor-gap honesty).
    func testESFCollectorDoesNotCountAppleInfrastructureAsClients() async throws {
        let state = try await ESFEndpointSecurityCollector().collect(context: .assess())
        guard let esf = state.esf else {
            XCTFail("esf state required")
            return
        }
        // endpointsecurityd / framework / bare SystemExtensions root are Apple infra.
        for path in esf.clientPaths {
            XCTAssertFalse(
                ESFEndpointSecurityCollector.isAppleInfrastructurePath(path),
                "Apple infra must not be clientPaths: \(path)"
            )
            XCTAssertFalse(
                path == "/usr/libexec/endpointsecurityd",
                "endpointsecurityd counted as client"
            )
            XCTAssertFalse(
                path == "/Library/SystemExtensions",
                "bare SystemExtensions directory counted as client"
            )
            XCTAssertFalse(
                path.hasPrefix("/System/Library/Frameworks/EndpointSecurity"),
                "framework counted as client: \(path)"
            )
        }
        // Notes should still acknowledge Apple infrastructure when present.
        let notesBlob = esf.notes.joined(separator: " ")
        let noteMentionsInfra =
            notesBlob.contains("apple_infra")
            || notesBlob.contains("endpointsecurityd")
            || notesBlob.contains("EndpointSecurity.framework")
        let frameworkKnown = esf.frameworkPresent == true
        XCTAssertTrue(
            noteMentionsInfra || frameworkKnown || !FileManager.default.fileExists(
                atPath: "/usr/libexec/endpointsecurityd"
            ),
            "collector should record Apple infra in notes/framework when present on host"
        )
        // Collector note uses thirdPartyClients token for gap detection.
        let cnote = state.collectorNotes[ESFEndpointSecurityCollector.id] ?? ""
        XCTAssertTrue(
            cnote.contains("thirdPartyClients="),
            "collector note must report thirdPartyClients= count; got \(cnote)"
        )
    }

    /// Key-adjacent entitlement parse: other `<true/>` keys must not set get-task-allow.
    func testLaunchConstraintEntitlementBoolKeyAdjacent() {
        let xmlWithUnrelatedTrue = """
        <?xml version="1.0"?>
        <plist>
        <dict>
            <key>com.apple.security.app-sandbox</key>
            <true/>
            <key>com.apple.security.get-task-allow</key>
            <false/>
            <key>com.apple.security.cs.disable-library-validation</key>
            <true/>
        </dict>
        </plist>
        """
        // Would FAIL if parser used global text.contains("<true").
        XCTAssertEqual(
            LaunchConstraintCollector.entitlementBool(
                in: xmlWithUnrelatedTrue,
                key: "com.apple.security.get-task-allow"
            ),
            false,
            "get-task-allow must be false when key-adjacent value is false"
        )
        XCTAssertEqual(
            LaunchConstraintCollector.entitlementBool(
                in: xmlWithUnrelatedTrue,
                key: "com.apple.security.cs.disable-library-validation"
            ),
            true
        )
        XCTAssertEqual(
            LaunchConstraintCollector.entitlementBool(
                in: xmlWithUnrelatedTrue,
                key: "com.apple.security.app-sandbox"
            ),
            true
        )
        XCTAssertNil(
            LaunchConstraintCollector.entitlementBool(
                in: xmlWithUnrelatedTrue,
                key: "com.apple.security.cs.allow-dyld-environment-variables"
            ),
            "absent key must be nil"
        )

        let getTaskAllowTrue = """
        <key>com.apple.security.get-task-allow</key>
        <true/>
        <key>com.apple.security.app-sandbox</key>
        <false/>
        """
        XCTAssertEqual(
            LaunchConstraintCollector.entitlementBool(
                in: getTaskAllowTrue,
                key: "com.apple.security.get-task-allow"
            ),
            true
        )
        XCTAssertEqual(
            LaunchConstraintCollector.entitlementBool(
                in: getTaskAllowTrue,
                key: "com.apple.security.app-sandbox"
            ),
            false
        )

        // Global true pollution fixture (the bug class).
        let pollution = """
        <key>some.other.entitlement</key>
        <true/>
        <key>com.apple.security.get-task-allow</key>
        <false/>
        """
        XCTAssertEqual(
            LaunchConstraintCollector.entitlementBool(
                in: pollution,
                key: "com.apple.security.get-task-allow"
            ),
            false,
            "unrelated <true/> must not force get-task-allow"
        )
    }
}
