import XCTest
@testable import RootstockCore
@testable import RootstockLab

final class LabActionTests: XCTestCase {
    private func labContext(dryRun: Bool) -> EvaluationContext {
        EvaluationContext(
            mode: .lab,
            profile: .standard,
            dryRun: dryRun,
            consent: ConsentTokens(
                iAmAuthorized: true,
                scope: "ENG",
                operatorName: "alice"
            )
        )
    }

    private func tempDir(prefix: String) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("rootstock-red-lab-\(prefix)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    // MARK: - LaunchAgent dry-run

    func testLaunchAgentDryRunInstallDoesNotWrite() async throws {
        let dir = try tempDir(prefix: "la-dry")
        defer { try? FileManager.default.removeItem(at: dir) }

        let action = LaunchAgentLabAction()
        let request = LabActionRequest(
            actionId: LaunchAgentLabAction.id,
            operation: .install,
            parameters: [
                "directory": dir.path,
                "label": "com.rootstock.red.lab.test",
            ]
        )
        let result = try await action.run(request: request, context: labContext(dryRun: true))

        XCTAssertTrue(result.success)
        XCTAssertTrue(result.dryRun)
        XCTAssertEqual(result.actionId, "lab.persist.launchagent")
        XCTAssertFalse(result.plannedSteps.isEmpty)
        XCTAssertTrue(result.message.contains("BTM") || result.cleanupNotes.contains { $0.contains("BTM") })
        XCTAssertFalse(result.artifacts.isEmpty)

        let plist = dir.appendingPathComponent("com.rootstock.red.lab.test.plist")
        XCTAssertFalse(
            FileManager.default.fileExists(atPath: plist.path),
            "dry-run must not write LaunchAgent plist"
        )
    }

    func testLaunchAgentInstallStatusRemoveWithTempDirectory() async throws {
        let dir = try tempDir(prefix: "la-rw")
        defer { try? FileManager.default.removeItem(at: dir) }

        let label = "com.rootstock.red.lab.lifecycle"
        let params = ["directory": dir.path, "label": label]
        let action = LaunchAgentLabAction()
        let ctx = labContext(dryRun: false)
        let pipeline = LabPipeline(registry: .production())

        let install = try await pipeline.run(
            request: LabActionRequest(
                actionId: LaunchAgentLabAction.id,
                operation: .install,
                parameters: params
            ),
            context: ctx
        )
        XCTAssertTrue(install.success)
        XCTAssertFalse(install.dryRun)
        XCTAssertFalse(install.cleanupNotes.isEmpty)

        let plist = dir.appendingPathComponent("\(label).plist")
        XCTAssertTrue(FileManager.default.fileExists(atPath: plist.path))

        // Harmless ProgramArguments
        let dict = NSDictionary(contentsOf: plist) as? [String: Any]
        XCTAssertEqual(dict?["Label"] as? String, label)
        let args = dict?["ProgramArguments"] as? [String]
        XCTAssertEqual(args?.first, "/usr/bin/true")

        let status = try await action.run(
            request: LabActionRequest(
                actionId: LaunchAgentLabAction.id,
                operation: .status,
                parameters: params
            ),
            context: ctx
        )
        XCTAssertTrue(status.success)
        XCTAssertTrue(status.message.contains("present"))
        XCTAssertEqual(status.artifacts, [plist.path])

        let remove = try await action.run(
            request: LabActionRequest(
                actionId: LaunchAgentLabAction.id,
                operation: .remove,
                parameters: params
            ),
            context: ctx
        )
        XCTAssertTrue(remove.success)
        XCTAssertFalse(FileManager.default.fileExists(atPath: plist.path))
        XCTAssertTrue(remove.cleanupNotes.contains { $0.contains("BTM") })
    }

    func testLaunchAgentRejectsPathTraversalLabel() async throws {
        let dir = try tempDir(prefix: "la-trav")
        defer { try? FileManager.default.removeItem(at: dir) }

        let action = LaunchAgentLabAction()
        let maliciousLabels = [
            "../../.ssh/orchard_pwn",
            "../escape",
            "com/rootstock-red/lab/bad",
            "com.rootstock.red.lab/../../tmp/pwn",
            "..",
            "foo/bar",
        ]

        for bad in maliciousLabels {
            do {
                _ = try await action.run(
                    request: LabActionRequest(
                        actionId: LaunchAgentLabAction.id,
                        operation: .install,
                        parameters: [
                            "directory": dir.path,
                            "label": bad,
                        ]
                    ),
                    context: labContext(dryRun: false)
                )
                XCTFail("expected invalidArgument for label \(bad)")
            } catch let error as RootstockError {
                guard case .invalidArgument = error else {
                    XCTFail("unexpected RootstockError for \(bad): \(error)")
                    continue
                }
            } catch {
                XCTFail("unexpected error type for \(bad): \(error)")
            }
        }

        // No plists written under or outside temp dir from traversal attempts
        let contents = (try? FileManager.default.contentsOfDirectory(atPath: dir.path)) ?? []
        XCTAssertTrue(contents.isEmpty, "traversal must not create files; saw \(contents)")

        // Explicit path containment: resolvePlistURL rejects escape even if sanitize missed
        XCTAssertThrowsError(
            try LaunchAgentLabAction.resolveLabel(params: ["label": "../../.ssh/orchard_pwn"])
        )
        let safe = try LaunchAgentLabAction.resolveLabel(params: ["label": "com.rootstock.red.lab.safe"])
        XCTAssertEqual(safe, "com.rootstock.red.lab.safe")
        let url = try LaunchAgentLabAction.resolvePlistURL(directory: dir, label: safe)
        XCTAssertTrue(url.path.hasPrefix(dir.standardizedFileURL.path + "/"))
        XCTAssertEqual(url.lastPathComponent, "com.rootstock.red.lab.safe.plist")
    }

    func testLaunchAgentPathTraversalDoesNotWriteOutsideDirectory() async throws {
        // Skeptic demo: --label '../../.ssh/orchard_pwn' must not write ~/.ssh/orchard_pwn.plist
        let homeSSH = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".ssh", isDirectory: true)
        let escapeTarget = homeSSH.appendingPathComponent("orchard_pwn.plist")
        let existedBefore = FileManager.default.fileExists(atPath: escapeTarget.path)

        let dir = try tempDir(prefix: "la-outside")
        defer { try? FileManager.default.removeItem(at: dir) }

        let action = LaunchAgentLabAction()
        do {
            _ = try await action.run(
                request: LabActionRequest(
                    actionId: LaunchAgentLabAction.id,
                    operation: .install,
                    parameters: [
                        "directory": dir.path,
                        "label": "../../.ssh/orchard_pwn",
                    ]
                ),
                context: labContext(dryRun: false)
            )
            XCTFail("path traversal label must fail")
        } catch is RootstockError {
            // expected
        }

        let existsAfter = FileManager.default.fileExists(atPath: escapeTarget.path)
        if !existedBefore {
            XCTAssertFalse(existsAfter, "must not create \(escapeTarget.path)")
        }
    }

    func testLaunchAgentRemoveDryRunDoesNotDelete() async throws {
        let dir = try tempDir(prefix: "la-rm-dry")
        defer { try? FileManager.default.removeItem(at: dir) }

        let label = "com.rootstock.red.lab.keep"
        let plist = dir.appendingPathComponent("\(label).plist")
        try Data("<plist></plist>".utf8).write(to: plist)

        let action = LaunchAgentLabAction()
        let result = try await action.run(
            request: LabActionRequest(
                actionId: LaunchAgentLabAction.id,
                operation: .remove,
                parameters: ["directory": dir.path, "label": label]
            ),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(result.dryRun)
        XCTAssertTrue(FileManager.default.fileExists(atPath: plist.path))
    }

    // MARK: - Dylib surface

    func testDylibPlanDryRunDoesNotWrite() async throws {
        let root = try tempDir(prefix: "dylib-dry")
        defer { try? FileManager.default.removeItem(at: root) }

        let action = DylibSurfaceLabAction()
        let result = try await action.run(
            request: LabActionRequest(
                actionId: DylibSurfaceLabAction.id,
                operation: .plan,
                parameters: ["labRoot": root.path, "app": "SampleApp"]
            ),
            context: labContext(dryRun: true)
        )

        XCTAssertTrue(result.success)
        XCTAssertTrue(result.dryRun)
        XCTAssertEqual(result.actionId, "lab.surface.dylib_plan")
        XCTAssertFalse(result.plannedSteps.isEmpty)
        XCTAssertTrue(result.message.contains("marker") || result.message.contains("plan"))

        let marker = DylibSurfaceLabAction.markerURL(labRoot: root, app: "SampleApp")
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
    }

    func testDylibApplyStatusRemoveLifecycle() async throws {
        let root = try tempDir(prefix: "dylib-rw")
        defer { try? FileManager.default.removeItem(at: root) }

        let params = ["labRoot": root.path, "app": "TestApp"]
        let action = DylibSurfaceLabAction()
        let ctx = labContext(dryRun: false)
        let marker = DylibSurfaceLabAction.markerURL(labRoot: root, app: "TestApp")

        let apply = try await action.run(
            request: LabActionRequest(
                actionId: DylibSurfaceLabAction.id,
                operation: .install,
                parameters: params
            ),
            context: ctx
        )
        XCTAssertTrue(apply.success)
        XCTAssertFalse(apply.dryRun)
        XCTAssertTrue(FileManager.default.fileExists(atPath: marker.path))
        // Empty marker, not a dylib
        let size = try FileManager.default.attributesOfItem(atPath: marker.path)[.size] as? NSNumber
        XCTAssertEqual(size?.intValue, 0)

        let status = try await action.run(
            request: LabActionRequest(
                actionId: DylibSurfaceLabAction.id,
                operation: .status,
                parameters: params
            ),
            context: ctx
        )
        XCTAssertTrue(status.message.contains("present"))

        let remove = try await action.run(
            request: LabActionRequest(
                actionId: DylibSurfaceLabAction.id,
                operation: .remove,
                parameters: params
            ),
            context: ctx
        )
        XCTAssertTrue(remove.success)
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
    }

    // MARK: - Pipeline / registry

    func testProductionRegistryContainsExpectedActions() {
        let ids = ActionRegistry.production().actionIds
        XCTAssertTrue(ids.contains("lab.noop"))
        XCTAssertTrue(ids.contains("lab.persist.launchagent"))
        XCTAssertTrue(ids.contains("lab.surface.dylib_plan"))
        // Expanded lab surface (wave 1)
        XCTAssertTrue(ids.contains("lab.persist.shellrc"))
        XCTAssertTrue(ids.contains("lab.persist.cron_marker"))
        XCTAssertTrue(ids.contains("lab.surface.dyld_env"))
        // 2026 coverage lab surface (wave 2) - production registry ≥ 9 IDs
        XCTAssertTrue(ids.contains("lab.persist.loginitem_marker"))
        XCTAssertTrue(ids.contains("lab.purple.atomic_ioc"))
        XCTAssertTrue(ids.contains("lab.surface.xpc_helper_plan"))
        XCTAssertTrue(ids.contains("lab.persist.periodic_marker"))
        XCTAssertTrue(ids.contains("lab.surface.sudoers_plan"))
        XCTAssertTrue(ids.contains("lab.purple.esf_expect"))
        XCTAssertTrue(ids.contains("lab.surface.quarantine_plan"))
        XCTAssertTrue(ids.contains("lab.surface.keychain_path_plan"))
        XCTAssertTrue(ids.contains("lab.purple.xattr_detect_pair"))
        // Wave-5 2026 coverage lab surface
        XCTAssertTrue(ids.contains("lab.surface.esf_sensor_plan"))
        XCTAssertTrue(ids.contains("lab.surface.tcc_graph_plan"))
        XCTAssertTrue(ids.contains("lab.surface.patch_debt_plan"))
        XCTAssertTrue(ids.contains("lab.surface.launch_constraint_plan"))
        XCTAssertTrue(ids.contains("lab.surface.lol_multistage_plan"))
        // Wave-6 2026 coverage lab surface
        XCTAssertTrue(ids.contains("lab.surface.network_extension_plan"))
        XCTAssertTrue(ids.contains("lab.surface.auth_rights_plan"))
        XCTAssertTrue(ids.contains("lab.surface.developer_toolchain_plan"))
        XCTAssertTrue(ids.contains("lab.surface.time_machine_plan"))
        XCTAssertTrue(ids.contains("lab.surface.mobileconfig_sideload_plan"))
        // Wave-7 2026 coverage lab surface
        XCTAssertTrue(ids.contains("lab.surface.app_sandbox_plan"))
        XCTAssertTrue(ids.contains("lab.surface.notarization_plan"))
        XCTAssertTrue(ids.contains("lab.surface.virtualization_plan"))
        XCTAssertTrue(ids.contains("lab.surface.continuity_airdrop_plan"))
        XCTAssertTrue(ids.contains("lab.surface.filevault_escrow_plan"))
        // Wave-8 2026 coverage lab surface
        XCTAssertTrue(ids.contains("lab.surface.clickfix_terminal_plan"))
        XCTAssertTrue(ids.contains("lab.surface.remote_apple_events_plan"))
        XCTAssertTrue(ids.contains("lab.surface.spotlight_ai_cache_plan"))
        XCTAssertTrue(ids.contains("lab.surface.security_mgmt_plane_plan"))
        XCTAssertTrue(ids.contains("lab.surface.third_party_tcc_inheritance_plan"))
        XCTAssertTrue(ids.contains("lab.surface.ssh_agent_key_path_plan"))
        // Wave-9 2026 coverage lab surface
        XCTAssertTrue(ids.contains("lab.surface.packagekit_installer_plan"))
        XCTAssertTrue(ids.contains("lab.surface.archive_quarantine_plan"))
        XCTAssertTrue(ids.contains("lab.surface.infostealer_path_plan"))
        XCTAssertTrue(ids.contains("lab.surface.tcc_esf_visibility_plan"))
        XCTAssertTrue(ids.contains("lab.surface.mdm_profile_parse_plan"))
        // Wave-11 2026 coverage multi-plane lab surface
        XCTAssertTrue(ids.contains("lab.surface.url_scheme_handler_plan"))
        XCTAssertTrue(ids.contains("lab.surface.launchd_override_depth_plan"))
        XCTAssertTrue(ids.contains("lab.surface.browser_extension_dualuse_plan"))
        XCTAssertTrue(ids.contains("lab.surface.shortcuts_app_intents_plan"))
        // Wave-12 2026 coverage multi-plane lab surface
        XCTAssertTrue(ids.contains("lab.surface.webloc_inetloc_plan"))
        XCTAssertTrue(ids.contains("lab.surface.mail_rules_automation_plan"))
        XCTAssertTrue(ids.contains("lab.surface.unified_log_observation_plan"))
        XCTAssertTrue(ids.contains("lab.surface.dock_persistence_plan"))
        XCTAssertTrue(ids.contains("lab.surface.osascript_scpt_plan"))
        XCTAssertTrue(ids.contains("lab.surface.network_share_mount_plan"))
        // Wave-13 2026 coverage multi-plane lab surface
        XCTAssertTrue(ids.contains("lab.surface.calendar_reminders_plan"))
        XCTAssertTrue(ids.contains("lab.surface.gk_assessment_history_plan"))
        XCTAssertTrue(ids.contains("lab.surface.homebrew_package_plan"))
        XCTAssertTrue(ids.contains("lab.surface.cups_print_plan"))
        XCTAssertTrue(ids.contains("lab.surface.screencapture_privacy_plan"))
        // Wave-14
        XCTAssertTrue(ids.contains("lab.surface.automator_workflow_plan"))
        XCTAssertTrue(ids.contains("lab.surface.icloud_drive_path_plan"))
        XCTAssertTrue(ids.contains("lab.surface.bluetooth_continuity_depth_plan"))
        XCTAssertTrue(ids.contains("lab.surface.font_validation_dualuse_plan"))
        XCTAssertTrue(ids.contains("lab.surface.quicklook_cache_depth_plan"))
        XCTAssertTrue(ids.contains("lab.surface.dns_resolver_dualuse_plan"))
        XCTAssertTrue(ids.contains("lab.surface.ls_quarantine_db_depth_plan"))
        XCTAssertTrue(ids.contains("lab.surface.pam_auth_module_plan"))
        XCTAssertTrue(ids.contains("lab.surface.cron_at_job_depth_plan"))
        XCTAssertTrue(ids.contains("lab.surface.notes_metadata_plane_plan"))
                // Wave-15
        XCTAssertTrue(ids.contains("lab.surface.photos_library_path_plan"))
        XCTAssertTrue(ids.contains("lab.surface.vpn_config_dualuse_plan"))
        XCTAssertTrue(ids.contains("lab.surface.sandbox_container_depth_plan"))
        XCTAssertTrue(ids.contains("lab.surface.xpc_mach_service_depth_plan"))
        XCTAssertTrue(ids.contains("lab.surface.tm_local_snapshot_depth_plan"))
        XCTAssertTrue(ids.contains("lab.surface.emond_legacy_depth_plan"))
        XCTAssertTrue(ids.contains("lab.surface.screen_sharing_ard_depth_plan"))
        XCTAssertTrue(ids.contains("lab.surface.keychain_acl_path_plan"))
        XCTAssertTrue(ids.contains("lab.surface.python_runtime_dualuse_plan"))
        XCTAssertTrue(ids.contains("lab.surface.shell_plugin_manager_plan"))
                // Wave-16
        XCTAssertTrue(ids.contains("lab.surface.airplay_receiver_surface_plan"))
        XCTAssertTrue(ids.contains("lab.surface.handoff_clipboard_depth_plan"))
        XCTAssertTrue(ids.contains("lab.surface.imessage_path_plane_plan"))
        XCTAssertTrue(ids.contains("lab.surface.facetime_camera_surface_plan"))
        XCTAssertTrue(ids.contains("lab.surface.finder_sync_extension_plan"))
        XCTAssertTrue(ids.contains("lab.surface.fileprovider_domain_plan"))
        XCTAssertTrue(ids.contains("lab.surface.notification_center_depth_plan"))
        XCTAssertTrue(ids.contains("lab.surface.siri_suggestions_plane_plan"))
        XCTAssertTrue(ids.contains("lab.surface.spotlight_importer_depth_plan"))
        XCTAssertTrue(ids.contains("lab.surface.contacts_path_plane_plan"))
        XCTAssertTrue(ids.contains("lab.surface.calendar_server_path_plan"))
        XCTAssertTrue(ids.contains("lab.surface.reminders_cloud_path_plan"))
        XCTAssertTrue(ids.contains("lab.surface.maps_location_path_plan"))
        XCTAssertTrue(ids.contains("lab.surface.weather_widget_path_plan"))
        XCTAssertTrue(ids.contains("lab.surface.music_library_path_plan"))
        XCTAssertTrue(ids.contains("lab.surface.books_path_plane_plan"))
        XCTAssertTrue(ids.contains("lab.surface.podcasts_path_plane_plan"))
        XCTAssertTrue(ids.contains("lab.surface.tv_app_path_plane_plan"))
        XCTAssertTrue(ids.contains("lab.surface.homekit_path_plane_plan"))
        XCTAssertTrue(ids.contains("lab.surface.health_path_plane_plan"))
        XCTAssertTrue(ids.contains("lab.surface.wallet_pass_path_plan"))
        XCTAssertTrue(ids.contains("lab.surface.findmy_path_plane_plan"))
        XCTAssertTrue(ids.contains("lab.surface.shortcuts_icloud_sync_plan"))
        XCTAssertTrue(ids.contains("lab.surface.devicemanagement_profile_plan"))
        XCTAssertTrue(ids.contains("lab.surface.softwareupdate_catalog_plan"))
        XCTAssertGreaterThanOrEqual(ids.count, 101)
    }

    // MARK: - Login-item marker

    func testLoginItemMarkerPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "loginitem-rw")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = [
            "labRoot": root.path,
            "label": "com.rootstock.red.lab.loginitem.test",
        ]
        let action = LoginItemMarkerLabAction()

        let plan = try await action.run(
            request: LabActionRequest(
                actionId: LoginItemMarkerLabAction.id,
                operation: .plan,
                parameters: params
            ),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(plan.success)
        XCTAssertTrue(plan.dryRun)
        XCTAssertEqual(plan.actionId, "lab.persist.loginitem_marker")
        XCTAssertFalse(plan.plannedSteps.isEmpty)
        XCTAssertFalse(plan.cleanupNotes.isEmpty)
        XCTAssertTrue(
            plan.cleanupNotes.contains { $0.localizedCaseInsensitiveContains("BTM") }
                || plan.message.localizedCaseInsensitiveContains("BTM")
        )

        let install = try await action.run(
            request: LabActionRequest(
                actionId: LoginItemMarkerLabAction.id,
                operation: .install,
                parameters: params
            ),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(install.success)
        XCTAssertFalse(install.artifacts.isEmpty)
        for path in install.artifacts {
            XCTAssertTrue(FileManager.default.fileExists(atPath: path))
        }

        let status = try await action.run(
            request: LabActionRequest(
                actionId: LoginItemMarkerLabAction.id,
                operation: .status,
                parameters: params
            ),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(status.message.contains("present"))

        let remove = try await action.run(
            request: LabActionRequest(
                actionId: LoginItemMarkerLabAction.id,
                operation: .remove,
                parameters: params
            ),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(remove.success)
        for path in install.artifacts {
            XCTAssertFalse(FileManager.default.fileExists(atPath: path))
        }
    }

    // MARK: - Purple atomic IOC

    func testAtomicIOCPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "atomic-ioc")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path, "technique": "T1543.001"]
        let action = AtomicIOCLabAction()
        let marker = root
            .appendingPathComponent("purple-ioc")
            .appendingPathComponent(AtomicIOCLabAction.markerName)

        let plan = try await action.run(
            request: LabActionRequest(
                actionId: AtomicIOCLabAction.id,
                operation: .plan,
                parameters: params
            ),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(plan.dryRun)
        XCTAssertEqual(plan.actionId, "lab.purple.atomic_ioc")
        XCTAssertFalse(plan.plannedSteps.isEmpty)
        XCTAssertFalse(plan.cleanupNotes.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))

        let install = try await action.run(
            request: LabActionRequest(
                actionId: AtomicIOCLabAction.id,
                operation: .install,
                parameters: params
            ),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(install.success)
        XCTAssertTrue(FileManager.default.fileExists(atPath: marker.path))
        let body = try String(contentsOf: marker, encoding: .utf8)
        XCTAssertTrue(body.contains("T1543.001") || body.contains("atomic"))

        let remove = try await action.run(
            request: LabActionRequest(
                actionId: AtomicIOCLabAction.id,
                operation: .remove,
                parameters: params
            ),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(remove.success)
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
    }

    // MARK: - XPC helper plan

    func testXPCHelperPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "xpc-plan")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path, "helper": "com.example.helper"]
        let action = XPCHelperPlanLabAction()
        let marker = XPCHelperPlanLabAction.markerURL(labRoot: root, helper: "com.example.helper")

        let plan = try await action.run(
            request: LabActionRequest(
                actionId: XPCHelperPlanLabAction.id,
                operation: .plan,
                parameters: params
            ),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(plan.success)
        XCTAssertTrue(plan.dryRun)
        XCTAssertEqual(plan.actionId, "lab.surface.xpc_helper_plan")
        XCTAssertFalse(plan.plannedSteps.isEmpty)
        XCTAssertFalse(plan.cleanupNotes.isEmpty)
        XCTAssertTrue(
            plan.message.contains("PrivilegedHelperTools")
                || plan.plannedSteps.contains { $0.contains("PrivilegedHelperTools") }
        )
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))

        let install = try await action.run(
            request: LabActionRequest(
                actionId: XPCHelperPlanLabAction.id,
                operation: .install,
                parameters: params
            ),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(install.success)
        XCTAssertTrue(FileManager.default.fileExists(atPath: marker.path))
        // Must not write system helper path
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: "/Library/PrivilegedHelperTools/com.example.helper"
            )
        )

        let remove = try await action.run(
            request: LabActionRequest(
                actionId: XPCHelperPlanLabAction.id,
                operation: .remove,
                parameters: params
            ),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(remove.success)
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
    }

    func testSOTA2026LabActionsConsentRequired() async {
        let bad = EvaluationContext(mode: .lab, dryRun: true, consent: ConsentTokens())
        let actions: [any LabAction] = [
            LoginItemMarkerLabAction(),
            AtomicIOCLabAction(),
            XPCHelperPlanLabAction(),
        ]
        for action in actions {
            do {
                _ = try await action.run(
                    request: LabActionRequest(
                        actionId: type(of: action).id,
                        operation: .plan,
                        parameters: ["labRoot": "/tmp"]
                    ),
                    context: bad
                )
                XCTFail("expected unauthorized for \(type(of: action).id)")
            } catch let error as RootstockError {
                guard case .unauthorized = error else {
                    XCTFail("expected unauthorized for \(type(of: action).id), got \(error)")
                    return
                }
            } catch {
                XCTFail("unexpected error for \(type(of: action).id): \(error)")
            }
        }
    }

    // MARK: - Shell RC

    func testShellRCDryRunPlanDoesNotWrite() async throws {
        let dir = try tempDir(prefix: "shellrc-dry")
        defer { try? FileManager.default.removeItem(at: dir) }
        let rc = dir.appendingPathComponent(".zshrc_lab")

        let action = ShellRCLabAction()
        let result = try await action.run(
            request: LabActionRequest(
                actionId: ShellRCLabAction.id,
                operation: .plan,
                parameters: ["rcFile": rc.path]
            ),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(result.success)
        XCTAssertTrue(result.dryRun)
        XCTAssertEqual(result.actionId, "lab.persist.shellrc")
        XCTAssertFalse(result.plannedSteps.isEmpty)
        XCTAssertFalse(result.cleanupNotes.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: rc.path))
    }

    func testShellRCInstallStatusRemoveLifecycle() async throws {
        let dir = try tempDir(prefix: "shellrc-rw")
        defer { try? FileManager.default.removeItem(at: dir) }
        let rc = dir.appendingPathComponent(".zshrc_lab")
        try "export PATH=/usr/bin\n".write(to: rc, atomically: true, encoding: .utf8)

        let params = ["rcFile": rc.path]
        let action = ShellRCLabAction()
        let ctx = labContext(dryRun: false)

        let install = try await action.run(
            request: LabActionRequest(actionId: ShellRCLabAction.id, operation: .install, parameters: params),
            context: ctx
        )
        XCTAssertTrue(install.success)
        XCTAssertFalse(install.dryRun)
        let body = try String(contentsOf: rc, encoding: .utf8)
        XCTAssertTrue(body.contains(ShellRCLabAction.markerPrefix))
        XCTAssertTrue(body.contains("export PATH=/usr/bin"))

        let status = try await action.run(
            request: LabActionRequest(actionId: ShellRCLabAction.id, operation: .status, parameters: params),
            context: ctx
        )
        XCTAssertTrue(status.message.contains("present"))

        let remove = try await action.run(
            request: LabActionRequest(actionId: ShellRCLabAction.id, operation: .remove, parameters: params),
            context: ctx
        )
        XCTAssertTrue(remove.success)
        let after = try String(contentsOf: rc, encoding: .utf8)
        XCTAssertFalse(after.contains(ShellRCLabAction.markerPrefix))
        XCTAssertTrue(after.contains("export PATH=/usr/bin"))
    }

    // MARK: - Cron marker

    func testCronMarkerPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "cron-rw")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let action = CronMarkerLabAction()
        let marker = CronMarkerLabAction.markerURL(labRoot: root)

        let plan = try await action.run(
            request: LabActionRequest(actionId: CronMarkerLabAction.id, operation: .plan, parameters: params),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(plan.dryRun)
        XCTAssertEqual(plan.actionId, "lab.persist.cron_marker")
        XCTAssertFalse(plan.plannedSteps.isEmpty)
        XCTAssertTrue(plan.message.localizedCaseInsensitiveContains("crontab") || plan.cleanupNotes.contains { $0.localizedCaseInsensitiveContains("crontab") })
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))

        let install = try await action.run(
            request: LabActionRequest(actionId: CronMarkerLabAction.id, operation: .install, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(install.success)
        XCTAssertTrue(FileManager.default.fileExists(atPath: marker.path))

        let status = try await action.run(
            request: LabActionRequest(actionId: CronMarkerLabAction.id, operation: .status, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(status.message.contains("present"))

        let remove = try await action.run(
            request: LabActionRequest(actionId: CronMarkerLabAction.id, operation: .remove, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(remove.success)
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
    }

    // MARK: - DYLD env surface

    func testDyldEnvPlanDryRunAndLifecycle() async throws {
        let root = try tempDir(prefix: "dyld-rw")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path, "app": "SampleApp"]
        let action = DyldEnvLabAction()
        let marker = DyldEnvLabAction.markerURL(labRoot: root, app: "SampleApp")

        let plan = try await action.run(
            request: LabActionRequest(actionId: DyldEnvLabAction.id, operation: .plan, parameters: params),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(plan.success)
        XCTAssertTrue(plan.dryRun)
        XCTAssertEqual(plan.actionId, "lab.surface.dyld_env")
        XCTAssertFalse(plan.plannedSteps.isEmpty)
        XCTAssertFalse(plan.cleanupNotes.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))

        let install = try await action.run(
            request: LabActionRequest(actionId: DyldEnvLabAction.id, operation: .install, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(install.success)
        XCTAssertTrue(FileManager.default.fileExists(atPath: marker.path))
        let body = try String(contentsOf: marker, encoding: .utf8)
        XCTAssertTrue(body.contains("DYLD_") || body.contains("ROOTSTOCK_RED_LAB_DYLD_MARKER"))

        let remove = try await action.run(
            request: LabActionRequest(actionId: DyldEnvLabAction.id, operation: .remove, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(remove.success)
        XCTAssertFalse(FileManager.default.fileExists(atPath: marker.path))
    }

    func testNewLabActionsConsentRequired() async {
        let bad = EvaluationContext(mode: .lab, dryRun: true, consent: ConsentTokens())
        let actions: [any LabAction] = [
            ShellRCLabAction(),
            CronMarkerLabAction(),
            DyldEnvLabAction(),
        ]
        for action in actions {
            do {
                _ = try await action.run(
                    request: LabActionRequest(
                        actionId: type(of: action).id,
                        operation: .plan,
                        parameters: ["labRoot": "/tmp", "rcFile": "/tmp/x"]
                    ),
                    context: bad
                )
                XCTFail("expected unauthorized for \(type(of: action).id)")
            } catch let error as RootstockError {
                guard case .unauthorized = error else {
                    XCTFail("expected unauthorized for \(type(of: action).id), got \(error)")
                    return
                }
            } catch {
                XCTFail("unexpected error for \(type(of: action).id): \(error)")
            }
        }
    }

    func testPlanAllDryRunsBothWithoutWrites() async throws {
        let laDir = try tempDir(prefix: "plan-la")
        let dylibRoot = try tempDir(prefix: "plan-dylib")
        defer {
            try? FileManager.default.removeItem(at: laDir)
            try? FileManager.default.removeItem(at: dylibRoot)
        }

        // planAll uses action defaults; ensure no accidental home writes by using
        // a custom registry of only the two lab actions exercised via direct plan.
        let pipeline = LabPipeline(registry: ActionRegistry(actions: [
            LaunchAgentLabAction(),
            DylibSurfaceLabAction(),
        ]))

        // Direct plan with temp paths
        let la = try await LaunchAgentLabAction().run(
            request: LabActionRequest(
                actionId: LaunchAgentLabAction.id,
                operation: .plan,
                parameters: ["directory": laDir.path, "label": "com.rootstock.red.lab.plan"]
            ),
            context: labContext(dryRun: true)
        )
        let dy = try await DylibSurfaceLabAction().run(
            request: LabActionRequest(
                actionId: DylibSurfaceLabAction.id,
                operation: .plan,
                parameters: ["labRoot": dylibRoot.path]
            ),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(la.dryRun)
        XCTAssertTrue(dy.dryRun)
        XCTAssertTrue(laDir.isEmptyDirectory)
        XCTAssertTrue(dylibRoot.isEmptyDirectory)

        // planAll with noop-free registry still requires consent; defaults only plan paths under home,
        // we assert structure/serialization only with production planAll (dry-run messages, no force apply).
        let all = try await pipeline.planAll(context: labContext(dryRun: true))
        XCTAssertEqual(all.count, 2)
        XCTAssertTrue(all.allSatisfy(\.dryRun))
        XCTAssertTrue(all.allSatisfy(\.success))

        let encoded = try JSONEncoder().encode(LabPlanAllResult(results: all))
        XCTAssertFalse(encoded.isEmpty)
        let decoded = try JSONDecoder().decode(LabPlanAllResult.self, from: encoded)
        XCTAssertEqual(decoded.results.count, 2)
    }

    func testConsentRequired() async {
        let action = LaunchAgentLabAction()
        let bad = EvaluationContext(mode: .lab, dryRun: true, consent: ConsentTokens())
        do {
            _ = try await action.run(
                request: LabActionRequest(
                    actionId: LaunchAgentLabAction.id,
                    operation: .status,
                    parameters: ["directory": "/tmp", "label": "com.rootstock.red.lab.x"]
                ),
                context: bad
            )
            XCTFail("expected unauthorized")
        } catch let error as RootstockError {
            guard case .unauthorized = error else {
                XCTFail("expected unauthorized, got \(error)")
                return
            }
        } catch {
            XCTFail("unexpected error \(error)")
        }
    }

    func testActionResultCodableIncludesNewFields() throws {
        let result = ActionResult(
            actionId: "lab.persist.launchagent",
            success: true,
            message: "ok",
            dryRun: true,
            plannedSteps: ["a"],
            cleanupNotes: ["b"],
            artifacts: ["/tmp/x"]
        )
        let data = try JSONEncoder().encode(result)
        let decoded = try JSONDecoder().decode(ActionResult.self, from: data)
        XCTAssertEqual(decoded, result)

        // Missing optional keys still decode
        let legacy = """
        {"actionId":"lab.noop","success":true,"message":"m","dryRun":true}
        """.data(using: .utf8)!
        let legacyDecoded = try JSONDecoder().decode(ActionResult.self, from: legacy)
        XCTAssertEqual(legacyDecoded.plannedSteps, [])
        XCTAssertEqual(legacyDecoded.cleanupNotes, [])
        XCTAssertEqual(legacyDecoded.artifacts, [])
    }

    func testPipelineRejectsUnknownAction() async {
        let pipeline = LabPipeline()
        do {
            _ = try await pipeline.run(
                request: LabActionRequest(actionId: "lab.evil", operation: .plan),
                context: labContext(dryRun: true)
            )
            XCTFail("expected invalidArgument")
        } catch let error as RootstockError {
            guard case .invalidArgument = error else {
                XCTFail("expected invalidArgument")
                return
            }
        } catch {
            XCTFail("unexpected \(error)")
        }
    }

    // MARK: - Wave-3 lab actions

    func testPeriodicMarkerPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "periodic-lab")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let action = PeriodicMarkerLabAction()
        let plan = try await action.run(
            request: LabActionRequest(actionId: PeriodicMarkerLabAction.id, operation: .plan, parameters: params),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(plan.dryRun)
        XCTAssertEqual(plan.actionId, "lab.persist.periodic_marker")
        XCTAssertFalse(plan.plannedSteps.isEmpty)
        XCTAssertFalse(plan.cleanupNotes.isEmpty)
        let install = try await action.run(
            request: LabActionRequest(actionId: PeriodicMarkerLabAction.id, operation: .install, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(install.success)
        XCTAssertFalse(install.artifacts.isEmpty)
        for a in install.artifacts { XCTAssertTrue(FileManager.default.fileExists(atPath: a)) }
        let remove = try await action.run(
            request: LabActionRequest(actionId: PeriodicMarkerLabAction.id, operation: .remove, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(remove.success)
        for a in install.artifacts { XCTAssertFalse(FileManager.default.fileExists(atPath: a)) }
    }

    func testSudoersPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "sudoers-lab")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let action = SudoersPlanLabAction()
        let plan = try await action.run(
            request: LabActionRequest(actionId: SudoersPlanLabAction.id, operation: .plan, parameters: params),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(plan.dryRun)
        XCTAssertEqual(plan.actionId, "lab.surface.sudoers_plan")
        XCTAssertFalse(plan.plannedSteps.isEmpty)
        XCTAssertTrue(plan.message.contains("sudoers") || plan.plannedSteps.contains { $0.contains("sudoers") })
        let install = try await action.run(
            request: LabActionRequest(actionId: SudoersPlanLabAction.id, operation: .install, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(install.success)
        XCTAssertFalse(FileManager.default.fileExists(atPath: "/etc/sudoers.d/rootstock-red-lab"))
        let remove = try await action.run(
            request: LabActionRequest(actionId: SudoersPlanLabAction.id, operation: .remove, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(remove.success)
    }

    func testESFExpectPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "esf-lab")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path, "technique": "T1543.001", "esfEvents": "OPEN,WRITE,CREATE"]
        let action = ESFExpectLabAction()
        let plan = try await action.run(
            request: LabActionRequest(actionId: ESFExpectLabAction.id, operation: .plan, parameters: params),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(plan.dryRun)
        XCTAssertEqual(plan.actionId, "lab.purple.esf_expect")
        XCTAssertFalse(plan.plannedSteps.isEmpty)
        let install = try await action.run(
            request: LabActionRequest(actionId: ESFExpectLabAction.id, operation: .install, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(install.success)
        XCTAssertFalse(install.artifacts.isEmpty)
        let body = try String(contentsOfFile: install.artifacts[0], encoding: .utf8)
        XCTAssertTrue(body.contains("T1543.001"))
        XCTAssertTrue(body.contains("OPEN") || body.contains("esfExpected"))
        let remove = try await action.run(
            request: LabActionRequest(actionId: ESFExpectLabAction.id, operation: .remove, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(remove.success)
        for a in install.artifacts { XCTAssertFalse(FileManager.default.fileExists(atPath: a)) }
    }




    // MARK: - Wave-4 lab actions

    func testQuarantinePlanLifecycle() async throws {
        let root = try tempDir(prefix: "q-plan")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let action = QuarantinePlanLabAction()
        let plan = try await action.run(
            request: LabActionRequest(actionId: QuarantinePlanLabAction.id, operation: .plan, parameters: params),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(plan.dryRun)
        XCTAssertEqual(plan.actionId, "lab.surface.quarantine_plan")
        XCTAssertFalse(plan.plannedSteps.isEmpty)
        XCTAssertFalse(plan.cleanupNotes.isEmpty)
        let install = try await action.run(
            request: LabActionRequest(actionId: QuarantinePlanLabAction.id, operation: .install, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(install.success)
        XCTAssertFalse(install.artifacts.isEmpty)
        for a in install.artifacts { XCTAssertTrue(FileManager.default.fileExists(atPath: a)) }
        let remove = try await action.run(
            request: LabActionRequest(actionId: QuarantinePlanLabAction.id, operation: .remove, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(remove.success)
        for a in install.artifacts { XCTAssertFalse(FileManager.default.fileExists(atPath: a)) }
    }

    func testKeychainPathPlanLifecycle() async throws {
        let root = try tempDir(prefix: "kc-plan")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let action = KeychainPathPlanLabAction()
        let plan = try await action.run(
            request: LabActionRequest(actionId: KeychainPathPlanLabAction.id, operation: .plan, parameters: params),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(plan.dryRun)
        XCTAssertEqual(plan.actionId, "lab.surface.keychain_path_plan")
        XCTAssertFalse(plan.plannedSteps.isEmpty)
        let blob = (plan.message + plan.plannedSteps.joined() + plan.cleanupNotes.joined()).lowercased()
        XCTAssertFalse(blob.contains("password="))
        let install = try await action.run(
            request: LabActionRequest(actionId: KeychainPathPlanLabAction.id, operation: .install, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(install.success)
        let remove = try await action.run(
            request: LabActionRequest(actionId: KeychainPathPlanLabAction.id, operation: .remove, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(remove.success)
    }

    func testXattrDetectPairLifecycle() async throws {
        let root = try tempDir(prefix: "xattr-pair")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path, "technique": "T1553.001"]
        let action = XattrDetectPairLabAction()
        let plan = try await action.run(
            request: LabActionRequest(actionId: XattrDetectPairLabAction.id, operation: .plan, parameters: params),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(plan.dryRun)
        XCTAssertEqual(plan.actionId, "lab.purple.xattr_detect_pair")
        XCTAssertFalse(plan.plannedSteps.isEmpty)
        let install = try await action.run(
            request: LabActionRequest(actionId: XattrDetectPairLabAction.id, operation: .install, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(install.success)
        XCTAssertFalse(install.artifacts.isEmpty)
        let body = try String(contentsOfFile: install.artifacts[0], encoding: .utf8)
        XCTAssertTrue(body.contains("T1553.001") || body.contains("xattr") || body.contains("quarantine") || body.contains("OPEN"))
        let remove = try await action.run(
            request: LabActionRequest(actionId: XattrDetectPairLabAction.id, operation: .remove, parameters: params),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(remove.success)
        for a in install.artifacts { XCTAssertFalse(FileManager.default.fileExists(atPath: a)) }
    }

    // MARK: - lab actions

    func testWave5LabActionsConsentRequired() async {
        let bad = EvaluationContext(mode: .lab, dryRun: true, consent: ConsentTokens())
        let actions: [any LabAction] = [
            ESFSensorPlanLabAction(),
            TCCGraphPlanLabAction(),
            PatchDebtPlanLabAction(),
            LaunchConstraintPlanLabAction(),
            LOLMultistagePlanLabAction(),
        ]
        for action in actions {
            do {
                _ = try await action.run(
                    request: LabActionRequest(
                        actionId: type(of: action).id,
                        operation: .plan,
                        parameters: ["labRoot": "/tmp"]
                    ),
                    context: bad
                )
                XCTFail("expected unauthorized for \(type(of: action).id)")
            } catch let error as RootstockError {
                guard case .unauthorized = error else {
                    XCTFail("expected unauthorized for \(type(of: action).id), got \(error)")
                    return
                }
            } catch {
                XCTFail("unexpected error for \(type(of: action).id): \(error)")
            }
        }
    }

    func testWave5LabActionsPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "wave5-lab")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let actions: [any LabAction] = [
            ESFSensorPlanLabAction(),
            TCCGraphPlanLabAction(),
            PatchDebtPlanLabAction(),
            LaunchConstraintPlanLabAction(),
            LOLMultistagePlanLabAction(),
        ]
        for action in actions {
            let id = type(of: action).id
            let plan = try await action.run(
                request: LabActionRequest(actionId: id, operation: .plan, parameters: params),
                context: labContext(dryRun: true)
            )
            XCTAssertTrue(plan.dryRun, "\(id) plan dryRun")
            XCTAssertTrue(plan.success, "\(id) plan success")
            XCTAssertFalse(plan.plannedSteps.isEmpty, "\(id) steps")

            let install = try await action.run(
                request: LabActionRequest(actionId: id, operation: .install, parameters: params),
                context: labContext(dryRun: false)
            )
            XCTAssertTrue(install.success, "\(id) install")
            XCTAssertFalse(install.artifacts.isEmpty, "\(id) artifacts")
            for a in install.artifacts {
                XCTAssertTrue(FileManager.default.fileExists(atPath: a), "\(id) wrote \(a)")
                XCTAssertFalse(a.contains("/Library/PrivilegedHelperTools"), "\(id) no system helper")
                XCTAssertTrue(a.hasPrefix(root.path), "\(id) under lab root")
            }

            let remove = try await action.run(
                request: LabActionRequest(actionId: id, operation: .remove, parameters: params),
                context: labContext(dryRun: false)
            )
            XCTAssertTrue(remove.success, "\(id) remove")
            for a in install.artifacts {
                XCTAssertFalse(FileManager.default.fileExists(atPath: a), "\(id) cleaned \(a)")
            }
        }
    }

    // MARK: - lab surface

    func testWave6LabActionsConsentRequired() async {
        let bad = EvaluationContext(mode: .lab, dryRun: true, consent: ConsentTokens())
        let actions: [any LabAction] = [
            NetworkExtensionPlanLabAction(),
            AuthRightsPlanLabAction(),
            DeveloperToolchainPlanLabAction(),
            TimeMachinePlanLabAction(),
            MobileconfigSideloadPlanLabAction(),
        ]
        for action in actions {
            do {
                _ = try await action.run(
                    request: LabActionRequest(
                        actionId: type(of: action).id,
                        operation: .plan,
                        parameters: ["labRoot": "/tmp"]
                    ),
                    context: bad
                )
                XCTFail("expected unauthorized for \(type(of: action).id)")
            } catch let error as RootstockError {
                guard case .unauthorized = error else {
                    XCTFail("expected unauthorized for \(type(of: action).id), got \(error)")
                    return
                }
            } catch {
                XCTFail("unexpected error for \(type(of: action).id): \(error)")
            }
        }
    }

    func testWave6LabActionsPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "wave6-lab")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let actions: [any LabAction] = [
            NetworkExtensionPlanLabAction(),
            AuthRightsPlanLabAction(),
            DeveloperToolchainPlanLabAction(),
            TimeMachinePlanLabAction(),
            MobileconfigSideloadPlanLabAction(),
        ]
        for action in actions {
            let id = type(of: action).id
            let plan = try await action.run(
                request: LabActionRequest(actionId: id, operation: .plan, parameters: params),
                context: labContext(dryRun: true)
            )
            XCTAssertTrue(plan.dryRun, "\(id) plan dryRun")
            XCTAssertTrue(plan.success, "\(id) plan success")
            XCTAssertFalse(plan.plannedSteps.isEmpty, "\(id) steps")
            // Safety: plan must not write system helpers / auth.db / NE config
            let planBlob = (plan.message + plan.plannedSteps.joined()).lowercased()
            XCTAssertFalse(planBlob.contains("password="), "\(id) no secrets")

            let install = try await action.run(
                request: LabActionRequest(actionId: id, operation: .install, parameters: params),
                context: labContext(dryRun: false)
            )
            XCTAssertTrue(install.success, "\(id) install")
            XCTAssertFalse(install.artifacts.isEmpty, "\(id) artifacts")
            for a in install.artifacts {
                XCTAssertTrue(FileManager.default.fileExists(atPath: a), "\(id) wrote \(a)")
                XCTAssertFalse(a.contains("/Library/PrivilegedHelperTools"), "\(id) no system helper")
                XCTAssertFalse(a.contains("/var/db/auth.db"), "\(id) no auth.db write")
                XCTAssertTrue(a.hasPrefix(root.path), "\(id) under lab root")
            }

            let remove = try await action.run(
                request: LabActionRequest(actionId: id, operation: .remove, parameters: params),
                context: labContext(dryRun: false)
            )
            XCTAssertTrue(remove.success, "\(id) remove")
            for a in install.artifacts {
                XCTAssertFalse(FileManager.default.fileExists(atPath: a), "\(id) cleaned \(a)")
            }
        }
    }

    // MARK: - lab surface

    func testWave7LabActionsConsentRequired() async {
        let bad = EvaluationContext(mode: .lab, dryRun: true, consent: ConsentTokens())
        let actions: [any LabAction] = [
            AppSandboxPlanLabAction(),
            NotarizationPlanLabAction(),
            VirtualizationPlanLabAction(),
            ContinuityAirDropPlanLabAction(),
            FileVaultEscrowPlanLabAction(),
        ]
        for action in actions {
            do {
                _ = try await action.run(
                    request: LabActionRequest(
                        actionId: type(of: action).id,
                        operation: .plan,
                        parameters: ["labRoot": "/tmp"]
                    ),
                    context: bad
                )
                XCTFail("expected unauthorized for \(type(of: action).id)")
            } catch let error as RootstockError {
                guard case .unauthorized = error else {
                    XCTFail("expected unauthorized for \(type(of: action).id), got \(error)")
                    return
                }
            } catch {
                XCTFail("unexpected error for \(type(of: action).id): \(error)")
            }
        }
    }

    func testWave7LabActionsPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "wave7-lab")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let actions: [any LabAction] = [
            AppSandboxPlanLabAction(),
            NotarizationPlanLabAction(),
            VirtualizationPlanLabAction(),
            ContinuityAirDropPlanLabAction(),
            FileVaultEscrowPlanLabAction(),
        ]
        for action in actions {
            let id = type(of: action).id
            let plan = try await action.run(
                request: LabActionRequest(actionId: id, operation: .plan, parameters: params),
                context: labContext(dryRun: true)
            )
            XCTAssertTrue(plan.dryRun, "\(id) plan dryRun")
            XCTAssertTrue(plan.success, "\(id) plan success")
            XCTAssertFalse(plan.plannedSteps.isEmpty, "\(id) steps")
            let planBlob = (plan.message + plan.plannedSteps.joined()).lowercased()
            XCTAssertFalse(planBlob.contains("password="), "\(id) no secrets")
            XCTAssertFalse(planBlob.contains("recovery key="), "\(id) no recovery keys")

            let install = try await action.run(
                request: LabActionRequest(actionId: id, operation: .install, parameters: params),
                context: labContext(dryRun: false)
            )
            XCTAssertTrue(install.success, "\(id) install")
            XCTAssertFalse(install.artifacts.isEmpty, "\(id) artifacts")
            for a in install.artifacts {
                XCTAssertTrue(FileManager.default.fileExists(atPath: a), "\(id) wrote \(a)")
                XCTAssertFalse(a.contains("/Library/PrivilegedHelperTools"), "\(id) no system helper")
                XCTAssertFalse(a.contains("/var/db/auth.db"), "\(id) no auth.db write")
                XCTAssertFalse(a.contains("FileVaultMaster"), "\(id) no FV master keychain write")
                XCTAssertTrue(a.hasPrefix(root.path), "\(id) under lab root")
            }

            let remove = try await action.run(
                request: LabActionRequest(actionId: id, operation: .remove, parameters: params),
                context: labContext(dryRun: false)
            )
            XCTAssertTrue(remove.success, "\(id) remove")
            for a in install.artifacts {
                XCTAssertFalse(FileManager.default.fileExists(atPath: a), "\(id) cleaned \(a)")
            }
        }
    }

    // MARK: - lab surface

    func testWave8LabActionsConsentRequired() async {
        let bad = EvaluationContext(mode: .lab, dryRun: true, consent: ConsentTokens())
        let actions: [any LabAction] = [
            ClickFixTerminalPlanLabAction(),
            RemoteAppleEventsPlanLabAction(),
            SpotlightAICachePlanLabAction(),
            SecurityMgmtPlanePlanLabAction(),
            ThirdPartyTCCInheritancePlanLabAction(),
            SSHAgentKeyPathPlanLabAction(),
        ]
        for action in actions {
            do {
                _ = try await action.run(
                    request: LabActionRequest(
                        actionId: type(of: action).id,
                        operation: .plan,
                        parameters: ["labRoot": "/tmp"]
                    ),
                    context: bad
                )
                XCTFail("expected unauthorized for \(type(of: action).id)")
            } catch let error as RootstockError {
                guard case .unauthorized = error else {
                    XCTFail("expected unauthorized for \(type(of: action).id), got \(error)")
                    return
                }
            } catch {
                XCTFail("unexpected error for \(type(of: action).id): \(error)")
            }
        }
    }

    func testWave8LabActionsPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "wave8-lab")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let actions: [any LabAction] = [
            ClickFixTerminalPlanLabAction(),
            RemoteAppleEventsPlanLabAction(),
            SpotlightAICachePlanLabAction(),
            SecurityMgmtPlanePlanLabAction(),
            ThirdPartyTCCInheritancePlanLabAction(),
            SSHAgentKeyPathPlanLabAction(),
        ]
        for action in actions {
            let id = type(of: action).id
            let plan = try await action.run(
                request: LabActionRequest(actionId: id, operation: .plan, parameters: params),
                context: labContext(dryRun: true)
            )
            XCTAssertTrue(plan.dryRun, "\(id) plan dryRun")
            XCTAssertTrue(plan.success, "\(id) plan success")
            XCTAssertFalse(plan.plannedSteps.isEmpty, "\(id) steps")
            let planBlob = (plan.message + plan.plannedSteps.joined()).lowercased()
            XCTAssertFalse(planBlob.contains("password="), "\(id) no secrets")
            XCTAssertFalse(planBlob.contains("begin rsa private key"), "\(id) no private keys")
            XCTAssertFalse(planBlob.contains("paste this payload"), "\(id) no ClickFix recipes")

            let install = try await action.run(
                request: LabActionRequest(actionId: id, operation: .install, parameters: params),
                context: labContext(dryRun: false)
            )
            XCTAssertTrue(install.success, "\(id) install")
            XCTAssertFalse(install.artifacts.isEmpty, "\(id) artifacts")
            for a in install.artifacts {
                XCTAssertTrue(FileManager.default.fileExists(atPath: a), "\(id) wrote \(a)")
                XCTAssertFalse(a.contains("/Library/PrivilegedHelperTools"), "\(id) no system helper")
                XCTAssertFalse(a.contains("/.ssh/"), "\(id) no ssh key write")
                XCTAssertTrue(a.hasPrefix(root.path), "\(id) under lab root")
            }

            let remove = try await action.run(
                request: LabActionRequest(actionId: id, operation: .remove, parameters: params),
                context: labContext(dryRun: false)
            )
            XCTAssertTrue(remove.success, "\(id) remove")
            for a in install.artifacts {
                XCTAssertFalse(FileManager.default.fileExists(atPath: a), "\(id) cleaned \(a)")
            }
        }
    }

    // MARK: - lab surface

    func testWave9LabActionsConsentRequired() async {
        let bad = EvaluationContext(mode: .lab, dryRun: true, consent: ConsentTokens())
        let actions: [any LabAction] = [
            PackageKitInstallerPlanLabAction(),
            ArchiveQuarantinePlanLabAction(),
            InfoStealerPathPlanLabAction(),
            TCCESFVisibilityPlanLabAction(),
            MDMProfileParsePlanLabAction(),
        ]
        for action in actions {
            do {
                _ = try await action.run(
                    request: LabActionRequest(
                        actionId: type(of: action).id,
                        operation: .plan,
                        parameters: ["labRoot": "/tmp"]
                    ),
                    context: bad
                )
                XCTFail("expected unauthorized for \(type(of: action).id)")
            } catch let error as RootstockError {
                guard case .unauthorized = error else {
                    XCTFail("expected unauthorized for \(type(of: action).id), got \(error)")
                    return
                }
            } catch {
                XCTFail("unexpected error for \(type(of: action).id): \(error)")
            }
        }
    }

    func testWave9LabActionsPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "wave9-lab")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let actions: [any LabAction] = [
            PackageKitInstallerPlanLabAction(),
            ArchiveQuarantinePlanLabAction(),
            InfoStealerPathPlanLabAction(),
            TCCESFVisibilityPlanLabAction(),
            MDMProfileParsePlanLabAction(),
        ]
        for action in actions {
            let id = type(of: action).id
            let plan = try await action.run(
                request: LabActionRequest(actionId: id, operation: .plan, parameters: params),
                context: labContext(dryRun: true)
            )
            XCTAssertTrue(plan.dryRun, "\(id) plan dryRun")
            XCTAssertTrue(plan.success, "\(id) plan success")
            XCTAssertFalse(plan.plannedSteps.isEmpty, "\(id) steps")
            let planBlob = (plan.message + plan.plannedSteps.joined()).lowercased()
            XCTAssertFalse(planBlob.contains("password="), "\(id) no secrets")
            XCTAssertFalse(planBlob.contains("begin rsa private key"), "\(id) no private keys")
            XCTAssertFalse(planBlob.contains("strip quarantine now"), "\(id) no quarantine strip")
            XCTAssertFalse(planBlob.contains("select * from access"), "\(id) no TCC dump")

            let install = try await action.run(
                request: LabActionRequest(actionId: id, operation: .install, parameters: params),
                context: labContext(dryRun: false)
            )
            XCTAssertTrue(install.success, "\(id) install")
            XCTAssertFalse(install.artifacts.isEmpty, "\(id) artifacts")
            for a in install.artifacts {
                XCTAssertTrue(FileManager.default.fileExists(atPath: a), "\(id) wrote \(a)")
                XCTAssertFalse(a.contains("/Library/PrivilegedHelperTools"), "\(id) no system helper")
                XCTAssertFalse(a.contains("/Library/Receipts"), "\(id) no system receipts")
                XCTAssertTrue(a.hasPrefix(root.path), "\(id) under lab root")
            }

            let remove = try await action.run(
                request: LabActionRequest(actionId: id, operation: .remove, parameters: params),
                context: labContext(dryRun: false)
            )
            XCTAssertTrue(remove.success, "\(id) remove")
            for a in install.artifacts {
                XCTAssertFalse(FileManager.default.fileExists(atPath: a), "\(id) cleaned \(a)")
            }
        }
    }







    // MARK: - lab surface

    func testWave16LabActionsConsentRequired() async {
        let bad = EvaluationContext(mode: .lab, dryRun: true, consent: ConsentTokens())
        let actions: [any LabAction] = [
            AirplayReceiverSurfacePlanLabAction(),
            HandoffClipboardDepthPlanLabAction(),
            ImessagePathPlanePlanLabAction(),
            FacetimeCameraSurfacePlanLabAction(),
            FinderSyncExtensionPlanLabAction(),
            FileproviderDomainPlanLabAction(),
            NotificationCenterDepthPlanLabAction(),
            SiriSuggestionsPlanePlanLabAction(),
            SpotlightImporterDepthPlanLabAction(),
            ContactsPathPlanePlanLabAction(),
            CalendarServerPathPlanLabAction(),
            RemindersCloudPathPlanLabAction(),
            MapsLocationPathPlanLabAction(),
            WeatherWidgetPathPlanLabAction(),
            MusicLibraryPathPlanLabAction(),
            BooksPathPlanePlanLabAction(),
            PodcastsPathPlanePlanLabAction(),
            TvAppPathPlanePlanLabAction(),
            HomekitPathPlanePlanLabAction(),
            HealthPathPlanePlanLabAction(),
            WalletPassPathPlanLabAction(),
            FindmyPathPlanePlanLabAction(),
            ShortcutsIcloudSyncPlanLabAction(),
            DevicemanagementProfilePlanLabAction(),
            SoftwareupdateCatalogPlanLabAction()
        ]
        for action in actions {
            do {
                _ = try await action.run(
                    request: LabActionRequest(actionId: type(of: action).id, operation: .plan, parameters: ["labRoot": "/tmp"]),
                    context: bad)
                XCTFail("expected unauthorized for \(type(of: action).id)")
            } catch let error as RootstockError {
                guard case .unauthorized = error else { XCTFail("expected unauthorized"); return }
            } catch { XCTFail("unexpected \(error)") }
        }
    }

    func testWave16LabActionsPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "wave16-lab")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let actions: [any LabAction] = [
            AirplayReceiverSurfacePlanLabAction(),
            HandoffClipboardDepthPlanLabAction(),
            ImessagePathPlanePlanLabAction(),
            FacetimeCameraSurfacePlanLabAction(),
            FinderSyncExtensionPlanLabAction(),
            FileproviderDomainPlanLabAction(),
            NotificationCenterDepthPlanLabAction(),
            SiriSuggestionsPlanePlanLabAction(),
            SpotlightImporterDepthPlanLabAction(),
            ContactsPathPlanePlanLabAction(),
            CalendarServerPathPlanLabAction(),
            RemindersCloudPathPlanLabAction(),
            MapsLocationPathPlanLabAction(),
            WeatherWidgetPathPlanLabAction(),
            MusicLibraryPathPlanLabAction(),
            BooksPathPlanePlanLabAction(),
            PodcastsPathPlanePlanLabAction(),
            TvAppPathPlanePlanLabAction(),
            HomekitPathPlanePlanLabAction(),
            HealthPathPlanePlanLabAction(),
            WalletPassPathPlanLabAction(),
            FindmyPathPlanePlanLabAction(),
            ShortcutsIcloudSyncPlanLabAction(),
            DevicemanagementProfilePlanLabAction(),
            SoftwareupdateCatalogPlanLabAction()
        ]
        for action in actions {
            let id = type(of: action).id
            let plan = try await action.run(
                request: LabActionRequest(actionId: id, operation: .plan, parameters: params),
                context: labContext(dryRun: true))
            XCTAssertTrue(plan.dryRun && plan.success, "\(id)")
            let install = try await action.run(
                request: LabActionRequest(actionId: id, operation: .install, parameters: params),
                context: labContext(dryRun: false))
            XCTAssertTrue(install.success && !install.artifacts.isEmpty, "\(id)")
            for a in install.artifacts {
                XCTAssertTrue(FileManager.default.fileExists(atPath: a) && a.hasPrefix(root.path))
            }
            let remove = try await action.run(
                request: LabActionRequest(actionId: id, operation: .remove, parameters: params),
                context: labContext(dryRun: false))
            XCTAssertTrue(remove.success)
            for a in install.artifacts { XCTAssertFalse(FileManager.default.fileExists(atPath: a)) }
        }
    }


    // MARK: - lab surface

    func testWave15LabActionsConsentRequired() async {
        let bad = EvaluationContext(mode: .lab, dryRun: true, consent: ConsentTokens())
        let actions: [any LabAction] = [
            PhotosLibraryPathPlanLabAction(),
            VpnConfigDualusePlanLabAction(),
            SandboxContainerDepthPlanLabAction(),
            XpcMachServiceDepthPlanLabAction(),
            TmLocalSnapshotDepthPlanLabAction(),
            EmondLegacyDepthPlanLabAction(),
            ScreenSharingArdDepthPlanLabAction(),
            KeychainAclPathPlanLabAction(),
            PythonRuntimeDualusePlanLabAction(),
            ShellPluginManagerPlanLabAction()
        ]
        for action in actions {
            do {
                _ = try await action.run(
                    request: LabActionRequest(actionId: type(of: action).id, operation: .plan, parameters: ["labRoot": "/tmp"]),
                    context: bad)
                XCTFail("expected unauthorized for \(type(of: action).id)")
            } catch let error as RootstockError {
                guard case .unauthorized = error else { XCTFail("expected unauthorized"); return }
            } catch { XCTFail("unexpected \(error)") }
        }
    }

    func testWave15LabActionsPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "wave15-lab")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let actions: [any LabAction] = [
            PhotosLibraryPathPlanLabAction(),
            VpnConfigDualusePlanLabAction(),
            SandboxContainerDepthPlanLabAction(),
            XpcMachServiceDepthPlanLabAction(),
            TmLocalSnapshotDepthPlanLabAction(),
            EmondLegacyDepthPlanLabAction(),
            ScreenSharingArdDepthPlanLabAction(),
            KeychainAclPathPlanLabAction(),
            PythonRuntimeDualusePlanLabAction(),
            ShellPluginManagerPlanLabAction()
        ]
        for action in actions {
            let id = type(of: action).id
            let plan = try await action.run(
                request: LabActionRequest(actionId: id, operation: .plan, parameters: params),
                context: labContext(dryRun: true))
            XCTAssertTrue(plan.dryRun && plan.success, "\(id)")
            let install = try await action.run(
                request: LabActionRequest(actionId: id, operation: .install, parameters: params),
                context: labContext(dryRun: false))
            XCTAssertTrue(install.success && !install.artifacts.isEmpty, "\(id) install")
            for a in install.artifacts {
                XCTAssertTrue(FileManager.default.fileExists(atPath: a) && a.hasPrefix(root.path))
            }
            let remove = try await action.run(
                request: LabActionRequest(actionId: id, operation: .remove, parameters: params),
                context: labContext(dryRun: false))
            XCTAssertTrue(remove.success)
            for a in install.artifacts { XCTAssertFalse(FileManager.default.fileExists(atPath: a)) }
        }
    }


    // MARK: - lab surface

    func testWave14LabActionsConsentRequired() async {
        let bad = EvaluationContext(mode: .lab, dryRun: true, consent: ConsentTokens())
        let actions: [any LabAction] = [
            AutomatorWorkflowPlanLabAction(),
            IcloudDrivePathPlanLabAction(),
            BluetoothContinuityDepthPlanLabAction(),
            FontValidationDualusePlanLabAction(),
            QuicklookCacheDepthPlanLabAction(),
            DnsResolverDualusePlanLabAction(),
            LsQuarantineDbDepthPlanLabAction(),
            PamAuthModulePlanLabAction(),
            CronAtJobDepthPlanLabAction(),
            NotesMetadataPlanePlanLabAction()
        ]
        for action in actions {
            do {
                _ = try await action.run(
                    request: LabActionRequest(actionId: type(of: action).id, operation: .plan, parameters: ["labRoot": "/tmp"]),
                    context: bad)
                XCTFail("expected unauthorized for \(type(of: action).id)")
            } catch let error as RootstockError {
                guard case .unauthorized = error else {
                    XCTFail("expected unauthorized, got \(error)"); return
                }
            } catch { XCTFail("unexpected \(error)") }
        }
    }

    func testWave14LabActionsPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "wave14-lab")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let actions: [any LabAction] = [
            AutomatorWorkflowPlanLabAction(),
            IcloudDrivePathPlanLabAction(),
            BluetoothContinuityDepthPlanLabAction(),
            FontValidationDualusePlanLabAction(),
            QuicklookCacheDepthPlanLabAction(),
            DnsResolverDualusePlanLabAction(),
            LsQuarantineDbDepthPlanLabAction(),
            PamAuthModulePlanLabAction(),
            CronAtJobDepthPlanLabAction(),
            NotesMetadataPlanePlanLabAction()
        ]
        for action in actions {
            let id = type(of: action).id
            let plan = try await action.run(
                request: LabActionRequest(actionId: id, operation: .plan, parameters: params),
                context: labContext(dryRun: true))
            XCTAssertTrue(plan.dryRun && plan.success, "\(id)")
            let install = try await action.run(
                request: LabActionRequest(actionId: id, operation: .install, parameters: params),
                context: labContext(dryRun: false))
            XCTAssertTrue(install.success && !install.artifacts.isEmpty, "\(id) install")
            for a in install.artifacts {
                XCTAssertTrue(FileManager.default.fileExists(atPath: a) && a.hasPrefix(root.path))
            }
            let remove = try await action.run(
                request: LabActionRequest(actionId: id, operation: .remove, parameters: params),
                context: labContext(dryRun: false))
            XCTAssertTrue(remove.success)
            for a in install.artifacts { XCTAssertFalse(FileManager.default.fileExists(atPath: a)) }
        }
    }


    // MARK: - lab surface

    func testWave13LabActionsConsentRequired() async {
        let bad = EvaluationContext(mode: .lab, dryRun: true, consent: ConsentTokens())
        let actions: [any LabAction] = [
            CalendarRemindersPlanLabAction(),
            GatekeeperAssessmentHistoryPlanLabAction(),
            HomebrewPackagePlanLabAction(),
            CupsPrintPlanLabAction(),
            ScreenCapturePrivacyPlanLabAction()
        ]
        for action in actions {
            do {
                _ = try await action.run(
                    request: LabActionRequest(actionId: type(of: action).id, operation: .plan, parameters: ["labRoot": "/tmp"]),
                    context: bad
                )
                XCTFail("expected unauthorized for \(type(of: action).id)")
            } catch let error as RootstockError {
                guard case .unauthorized = error else {
                    XCTFail("expected unauthorized for \(type(of: action).id), got \(error)")
                    return
                }
            } catch {
                XCTFail("unexpected error for \(type(of: action).id): \(error)")
            }
        }
    }

    func testWave13LabActionsPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "wave13-lab")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let actions: [any LabAction] = [
            CalendarRemindersPlanLabAction(),
            GatekeeperAssessmentHistoryPlanLabAction(),
            HomebrewPackagePlanLabAction(),
            CupsPrintPlanLabAction(),
            ScreenCapturePrivacyPlanLabAction()
        ]
        for action in actions {
            let id = type(of: action).id
            let plan = try await action.run(
                request: LabActionRequest(actionId: id, operation: .plan, parameters: params),
                context: labContext(dryRun: true)
            )
            XCTAssertTrue(plan.dryRun && plan.success, "\(id) plan")
            let install = try await action.run(
                request: LabActionRequest(actionId: id, operation: .install, parameters: params),
                context: labContext(dryRun: false)
            )
            XCTAssertTrue(install.success && !install.artifacts.isEmpty, "\(id) install")
            for a in install.artifacts {
                XCTAssertTrue(FileManager.default.fileExists(atPath: a))
                XCTAssertTrue(a.hasPrefix(root.path))
            }
            let remove = try await action.run(
                request: LabActionRequest(actionId: id, operation: .remove, parameters: params),
                context: labContext(dryRun: false)
            )
            XCTAssertTrue(remove.success)
            for a in install.artifacts {
                XCTAssertFalse(FileManager.default.fileExists(atPath: a))
            }
        }
    }


    // MARK: - lab surface

    func testWave12LabActionsConsentRequired() async {
        let bad = EvaluationContext(mode: .lab, dryRun: true, consent: ConsentTokens())
        let actions: [any LabAction] = [
            WeblocInetlocPlanLabAction(),
            MailRulesAutomationPlanLabAction(),
            UnifiedLogObservationPlanLabAction(),
            DockPersistencePlanLabAction(),
            OsascriptScptPlanLabAction(),
            NetworkShareMountPlanLabAction()
        ]
        for action in actions {
            do {
                _ = try await action.run(
                    request: LabActionRequest(
                        actionId: type(of: action).id,
                        operation: .plan,
                        parameters: ["labRoot": "/tmp"]
                    ),
                    context: bad
                )
                XCTFail("expected unauthorized for \(type(of: action).id)")
            } catch let error as RootstockError {
                guard case .unauthorized = error else {
                    XCTFail("expected unauthorized for \(type(of: action).id), got \(error)")
                    return
                }
            } catch {
                XCTFail("unexpected error for \(type(of: action).id): \(error)")
            }
        }
    }

    func testWave12LabActionsPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "wave12-lab")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let actions: [any LabAction] = [
            WeblocInetlocPlanLabAction(),
            MailRulesAutomationPlanLabAction(),
            UnifiedLogObservationPlanLabAction(),
            DockPersistencePlanLabAction(),
            OsascriptScptPlanLabAction(),
            NetworkShareMountPlanLabAction()
        ]
        for action in actions {
            let id = type(of: action).id
            let plan = try await action.run(
                request: LabActionRequest(actionId: id, operation: .plan, parameters: params),
                context: labContext(dryRun: true)
            )
            XCTAssertTrue(plan.dryRun, "\(id) plan dryRun")
            XCTAssertTrue(plan.success, "\(id) plan success")
            XCTAssertFalse(plan.plannedSteps.isEmpty, "\(id) steps")

            let install = try await action.run(
                request: LabActionRequest(actionId: id, operation: .install, parameters: params),
                context: labContext(dryRun: false)
            )
            XCTAssertTrue(install.success, "\(id) install")
            XCTAssertFalse(install.artifacts.isEmpty, "\(id) artifacts")
            for a in install.artifacts {
                XCTAssertTrue(FileManager.default.fileExists(atPath: a), "\(id) wrote \(a)")
                XCTAssertTrue(a.hasPrefix(root.path), "\(id) under lab root")
            }

            let remove = try await action.run(
                request: LabActionRequest(actionId: id, operation: .remove, parameters: params),
                context: labContext(dryRun: false)
            )
            XCTAssertTrue(remove.success, "\(id) remove")
            for a in install.artifacts {
                XCTAssertFalse(FileManager.default.fileExists(atPath: a), "\(id) cleaned \(a)")
            }
        }
    }


    // MARK: - lab surface

    func testWave11LabActionsConsentRequired() async {
        let bad = EvaluationContext(mode: .lab, dryRun: true, consent: ConsentTokens())
        let actions: [any LabAction] = [
            URLSchemeHandlerPlanLabAction(),
            LaunchdOverrideDepthPlanLabAction(),
            BrowserExtensionDualUsePlanLabAction(),
            ShortcutsAppIntentsPlanLabAction(),
        ]
        for action in actions {
            do {
                _ = try await action.run(
                    request: LabActionRequest(
                        actionId: type(of: action).id,
                        operation: .plan,
                        parameters: ["labRoot": "/tmp"]
                    ),
                    context: bad
                )
                XCTFail("expected unauthorized for \(type(of: action).id)")
            } catch let error as RootstockError {
                guard case .unauthorized = error else {
                    XCTFail("expected unauthorized for \(type(of: action).id), got \(error)")
                    return
                }
            } catch {
                XCTFail("unexpected error for \(type(of: action).id): \(error)")
            }
        }
    }

    func testWave11LabActionsPlanAndLifecycle() async throws {
        let root = try tempDir(prefix: "wave11-lab")
        defer { try? FileManager.default.removeItem(at: root) }
        let params = ["labRoot": root.path]
        let actions: [any LabAction] = [
            URLSchemeHandlerPlanLabAction(),
            LaunchdOverrideDepthPlanLabAction(),
            BrowserExtensionDualUsePlanLabAction(),
            ShortcutsAppIntentsPlanLabAction(),
        ]
        for action in actions {
            let id = type(of: action).id
            let plan = try await action.run(
                request: LabActionRequest(actionId: id, operation: .plan, parameters: params),
                context: labContext(dryRun: true)
            )
            XCTAssertTrue(plan.dryRun, "\(id) plan dryRun")
            XCTAssertTrue(plan.success, "\(id) plan success")
            XCTAssertFalse(plan.plannedSteps.isEmpty, "\(id) steps")
            let planBlob = (plan.message + plan.plannedSteps.joined()).lowercased()
            XCTAssertFalse(planBlob.contains("password="), "\(id) no secrets")
            XCTAssertFalse(planBlob.contains("disable santa now"), "\(id) no disable")
            XCTAssertFalse(planBlob.contains("run shortcuts payload"), "\(id) no run shortcuts")

            let install = try await action.run(
                request: LabActionRequest(actionId: id, operation: .install, parameters: params),
                context: labContext(dryRun: false)
            )
            XCTAssertTrue(install.success, "\(id) install")
            XCTAssertFalse(install.artifacts.isEmpty, "\(id) artifacts")
            for a in install.artifacts {
                XCTAssertTrue(FileManager.default.fileExists(atPath: a), "\(id) wrote \(a)")
                XCTAssertTrue(a.hasPrefix(root.path), "\(id) under lab root")
            }

            let remove = try await action.run(
                request: LabActionRequest(actionId: id, operation: .remove, parameters: params),
                context: labContext(dryRun: false)
            )
            XCTAssertTrue(remove.success, "\(id) remove")
            for a in install.artifacts {
                XCTAssertFalse(FileManager.default.fileExists(atPath: a), "\(id) cleaned \(a)")
            }
        }
    }


    // MARK: - Shared LabPaths / LabMarkerLifecycle

    func testLabPathsResolveLabRootDefaultAndOverride() {
        let def = LabPaths.resolveLabRoot(params: [:])
        XCTAssertTrue(def.path.hasSuffix("/Library/RootstockLab") || def.path.contains("Library/RootstockLab"))
        let cron = LabPaths.resolveLabRoot(params: [:], subdirectory: "cron")
        XCTAssertTrue(cron.path.hasSuffix("/Library/RootstockLab/cron") || cron.path.contains("RootstockLab/cron"))
        let custom = LabPaths.resolveLabRoot(params: ["labRoot": "/tmp/rootstock-lab-test-root"])
        XCTAssertEqual(custom.standardizedFileURL.path, "/tmp/rootstock-lab-test-root")
        // Explicit labRoot ignores default subdirectory
        let customWithSub = LabPaths.resolveLabRoot(
            params: ["labRoot": "/tmp/rootstock-lab-test-root"],
            subdirectory: "cron"
        )
        XCTAssertEqual(customWithSub.standardizedFileURL.path, "/tmp/rootstock-lab-test-root")
    }

    func testLabPathsSanitizeAndJsonStringList() {
        XCTAssertEqual(LabPaths.sanitizePathComponent("Hello World!"), "Hello_World_")
        XCTAssertEqual(LabPaths.sanitizePathComponent(""), "generic")
        XCTAssertEqual(LabPaths.jsonStringList(fromCSV: "OPEN, EXEC ,WRITE"), "\"OPEN\",\"EXEC\",\"WRITE\"")
    }

    func testLabMarkerLifecycleWriteStatusRemoveDrivesShippedHelpers() throws {
        let dir = try tempDir(prefix: "lifecycle")
        defer { try? FileManager.default.removeItem(at: dir) }
        let marker = dir.appendingPathComponent("shared.marker")
        XCTAssertFalse(LabMarkerLifecycle.markerExists(at: marker))

        let copy = FileMarkerCopy(
            planMessage: "plan \(marker.path)",
            planSteps: ["step-a"],
            planCleanup: ["cleanup-a"],
            applyDryRunMessage: "dry \(marker.path)",
            applySuccessMessage: "wrote \(marker.path)",
            applySteps: ["write"],
            applyCleanup: ["delete"],
            presentMessage: "present",
            absentMessage: "absent",
            removeDryRunMessage: { exists in "dry-remove exists=\(exists)" },
            removeSuccessMessage: { exists in "removed exists=\(exists)" },
            removeCleanup: ["done"]
        )

        let plan = try LabMarkerLifecycle.runFileMarker(
            actionId: "lab.test.shared",
            operation: .plan,
            markerURL: marker,
            body: "hello",
            contextDryRun: true,
            copy: copy
        )
        XCTAssertTrue(plan.success)
        XCTAssertTrue(plan.dryRun)
        XCTAssertFalse(LabMarkerLifecycle.markerExists(at: marker))

        let dryInstall = try LabMarkerLifecycle.runFileMarker(
            actionId: "lab.test.shared",
            operation: .install,
            markerURL: marker,
            body: "hello",
            contextDryRun: true,
            copy: copy
        )
        XCTAssertTrue(dryInstall.dryRun)
        XCTAssertFalse(LabMarkerLifecycle.markerExists(at: marker))

        let install = try LabMarkerLifecycle.runFileMarker(
            actionId: "lab.test.shared",
            operation: .install,
            markerURL: marker,
            body: "hello-body",
            contextDryRun: false,
            copy: copy
        )
        XCTAssertTrue(install.success)
        XCTAssertFalse(install.dryRun)
        XCTAssertTrue(LabMarkerLifecycle.markerExists(at: marker))
        XCTAssertEqual(try String(contentsOf: marker, encoding: .utf8), "hello-body")

        let status = try LabMarkerLifecycle.runFileMarker(
            actionId: "lab.test.shared",
            operation: .status,
            markerURL: marker,
            body: "hello-body",
            contextDryRun: false,
            copy: copy
        )
        XCTAssertEqual(status.message, "present")

        let remove = try LabMarkerLifecycle.runFileMarker(
            actionId: "lab.test.shared",
            operation: .remove,
            markerURL: marker,
            body: "hello-body",
            contextDryRun: false,
            copy: copy
        )
        XCTAssertTrue(remove.success)
        XCTAssertFalse(LabMarkerLifecycle.markerExists(at: marker))
    }

    func testClickFixPlanActionUsesSharedLifecycle() async throws {
        let dir = try tempDir(prefix: "clickfix-shared")
        defer { try? FileManager.default.removeItem(at: dir) }
        let action = ClickFixTerminalPlanLabAction()
        let params = ["labRoot": dir.path]
        let plan = try await action.run(
            request: LabActionRequest(
                actionId: ClickFixTerminalPlanLabAction.id,
                operation: .plan,
                parameters: params
            ),
            context: labContext(dryRun: true)
        )
        XCTAssertTrue(plan.success)
        XCTAssertTrue(plan.dryRun)
        XCTAssertFalse(plan.plannedSteps.isEmpty)

        let install = try await action.run(
            request: LabActionRequest(
                actionId: ClickFixTerminalPlanLabAction.id,
                operation: .install,
                parameters: params
            ),
            context: labContext(dryRun: false)
        )
        XCTAssertTrue(install.success)
        XCTAssertFalse(install.artifacts.isEmpty)
        for a in install.artifacts {
            XCTAssertTrue(FileManager.default.fileExists(atPath: a), a)
        }
        // Public resolveLabRoot is the shared LabPaths implementation
        let resolved = ClickFixTerminalPlanLabAction.resolveLabRoot(params: params)
        XCTAssertEqual(resolved.standardizedFileURL.path, dir.standardizedFileURL.path)
    }

}


private extension URL {
    var isEmptyDirectory: Bool {
        let contents = try? FileManager.default.contentsOfDirectory(atPath: path)
        return (contents ?? []).isEmpty
    }
}
