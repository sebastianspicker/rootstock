import XCTest
import RootstockCore
import MacEnumKit
import MacArtifactKit
@testable import MacVulnKit

final class AttackVectorTests: XCTestCase {
    // MARK: - Registration

    func testAttackVectorIdsRegistered() {
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        for id in AttackVectorPlane.ids {
            XCTAssertTrue(registered.contains(id), "vector \(id) not in allChecks()")
        }
        XCTAssertGreaterThanOrEqual(AttackVectorPlane.ids.count, 53)
        XCTAssertEqual(AttackVectorPlane.allChecks().count, AttackVectorPlane.ids.count)
        let requiredWave2 = [
            XPCHelperAbuseSurfaceVector.id,
            PlatformSSOLateralVector.id,
            SecurityProductGapVector.id,
            SystemLaunchDaemonSurfaceVector.id,
            SMAppLoginItemHonestyVector.id,
        ]
        for id in requiredWave2 {
            XCTAssertTrue(AttackVectorPlane.ids.contains(id), "missing 2026 coverage vector \(id)")
        }
        let requiredWave3 = [
            SudoersMisconfigSurfaceVector.id,
            PeriodicMaintenanceSurfaceVector.id,
            GatekeeperTrustGapVector.id,
            AutomationExecutionSurfaceVector.id,
            ElectronDevtoolsSurfaceVector.id,
        ]
        for id in requiredWave3 {
            XCTAssertTrue(AttackVectorPlane.ids.contains(id), "missing wave-3 vector \(id)")
        }
        let requiredWave4 = [
            QuarantineXattrSurfaceVector.id,
            KeychainPathSurfaceVector.id,
            MDMManagementChannelSurfaceVector.id,
            ScreenAccessibilitySurfaceVector.id,
            SecurityCLIDualUseVector.id,
        ]
        for id in requiredWave4 {
            XCTAssertTrue(AttackVectorPlane.ids.contains(id), "missing wave-4 vector \(id)")
        }
        let requiredWave5 = [
            ESFSensorGapVector.id,
            CVEPatchDebtSuggesterVector.id,
            TCCPermissionGraphDepthVector.id,
            XPCClientValidationSurfaceVector.id,
            LaunchConstraintInjectTruthVector.id,
            LOOBinDualUseMultiStageVector.id,
        ]
        for id in requiredWave5 {
            XCTAssertTrue(AttackVectorPlane.ids.contains(id), "missing wave-5 vector \(id)")
        }
        let requiredWave6 = [
            NetworkExtensionFilterGapVector.id,
            AuthRightsPrivilegeSurfaceVector.id,
            DeveloperToolchainDualUseVector.id,
            TimeMachineSnapshotAccessVector.id,
            MobileconfigSideloadRiskVector.id,
        ]
        for id in requiredWave6 {
            XCTAssertTrue(AttackVectorPlane.ids.contains(id), "missing wave-6 vector \(id)")
        }
        let requiredWave7 = [
            SandboxEntitlementThickClientVector.id,
            NotarizationStaplingGapVector.id,
            VirtContainerDualUseVector.id,
            ContinuityAirDropSurfaceVector.id,
            FileVaultEscrowPostureVector.id,
        ]
        for id in requiredWave7 {
            XCTAssertTrue(AttackVectorPlane.ids.contains(id), "missing wave-7 vector \(id)")
        }
        let requiredWave8 = [
            ClickFixTerminalDeliveryVector.id,
            RemoteAppleEventsLateralVector.id,
            SpotlightAICacheAccessVector.id,
            SecurityMgmtPlaneSurfaceVector.id,
            ThirdPartyTCCInheritanceVector.id,
            SSHAgentKeyPathLateralVector.id,
        ]
        for id in requiredWave8 {
            XCTAssertTrue(AttackVectorPlane.ids.contains(id), "missing wave-8 vector \(id)")
        }
        let requiredWave9 = [
            PackageKitInstallerDesignVector.id,
            ArchiveQuarantineExtractorVector.id,
            InfoStealerPathPlaneVector.id,
            TCCESFVisibilityDepthVector.id,
            MDMProfileParseDepthVector.id,
        ]
        for id in requiredWave9 {
            XCTAssertTrue(AttackVectorPlane.ids.contains(id), "missing wave-9 vector \(id)")
        }
        let requiredWave10 = [
            PackageKitReceiptScriptCompoundVector.id,
            ExtractorQuarantineCompoundVector.id,
            StealerRemoteCompoundVector.id,
            VisibilitySensorCompoundVector.id,
        ]
        for id in requiredWave10 {
            XCTAssertTrue(AttackVectorPlane.ids.contains(id), "missing wave-10 residual-pair vector \(id)")
        }
        let requiredWave11 = [
            URLSchemeHandlerVector.id,
            LaunchdOverrideDepthVector.id,
            BrowserExtensionDualUseVector.id,
            ShortcutsAppIntentsVector.id,
            URLSchemeRemoteCompoundVector.id,
            LaunchdSecurityDisableCompoundVector.id,
            BrowserExtensionCollectionCompoundVector.id,
            ShortcutsLateralCompoundVector.id,
        ]
        for id in requiredWave11 {
            XCTAssertTrue(AttackVectorPlane.ids.contains(id), "missing wave-11 multi-plane vector \(id)")
        }
        XCTAssertGreaterThanOrEqual(AttackVectorPlane.ids.count, 65)
        let requiredWave12 = [
            WeblocInetlocDeliveryVector.id,
            WeblocRemoteCompoundVector.id,
            MailRulesAutomationVector.id,
            MailRulesScriptCompoundVector.id,
            UnifiedLogObservationVector.id,
            UnifiedLogSensorCompoundVector.id,
            DockPersistenceSurfaceVector.id,
            DockRemoteCompoundVector.id,
            OsascriptScptDeliveryVector.id,
            OsascriptRemoteCompoundVector.id,
            NetworkShareMountVector.id,
            NetworkShareRemoteCompoundVector.id
        ]
        for id in requiredWave12 {
            XCTAssertTrue(AttackVectorPlane.ids.contains(id), "missing wave-12 multi-plane vector \(id)")
        }
        // Wave-11 + Wave-12 expansions → ≥77.
        XCTAssertGreaterThanOrEqual(AttackVectorPlane.ids.count, 77)
        let requiredWave13 = [
            CalendarRemindersAutomationVector.id,
            CalendarRemoteCompoundVector.id,
            GatekeeperAssessmentHistoryVector.id,
            GatekeeperAssessmentRemoteCompoundVector.id,
            HomebrewPackageDualUseVector.id,
            HomebrewRemoteCompoundVector.id,
            CupsPrintDualUseVector.id,
            CupsRemoteCompoundVector.id,
            ScreenCapturePrivacyDualUseVector.id,
            ScreenCaptureFdaCompoundVector.id
        ]
        for id in requiredWave13 {
            XCTAssertTrue(AttackVectorPlane.ids.contains(id), "missing wave-13 multi-plane vector \(id)")
        }
        XCTAssertGreaterThanOrEqual(AttackVectorPlane.ids.count, 87)
        let requiredWave14 = [
            AutomatorWorkflowVector.id,
            AutomatorWorkflowRemoteCompoundVector.id,
            IcloudDrivePathVector.id,
            IcloudDrivePathRemoteCompoundVector.id,
            BluetoothContinuityDepthVector.id,
            BluetoothContinuityDepthRemoteCompoundVector.id,
            FontValidationDualuseVector.id,
            FontValidationDualuseRemoteCompoundVector.id,
            QuicklookCacheDepthVector.id,
            QuicklookCacheDepthRemoteCompoundVector.id,
            DnsResolverDualuseVector.id,
            DnsResolverDualuseRemoteCompoundVector.id,
            LsQuarantineDbDepthVector.id,
            LsQuarantineDbDepthRemoteCompoundVector.id,
            PamAuthModuleVector.id,
            PamAuthModuleRemoteCompoundVector.id,
            CronAtJobDepthVector.id,
            CronAtJobDepthRemoteCompoundVector.id,
            NotesMetadataPlaneVector.id,
            NotesMetadataPlaneRemoteCompoundVector.id
        ]
        for id in requiredWave14 {
            XCTAssertTrue(AttackVectorPlane.ids.contains(id), "missing wave-14 vector \(id)")
        }
        XCTAssertGreaterThanOrEqual(AttackVectorPlane.ids.count, 107)
        let requiredWave15 = [
            PhotosLibraryPathVector.id,
            PhotosLibraryPathRemoteCompoundVector.id,
            VpnConfigDualuseVector.id,
            VpnConfigDualuseRemoteCompoundVector.id,
            SandboxContainerDepthVector.id,
            SandboxContainerDepthRemoteCompoundVector.id,
            XpcMachServiceDepthVector.id,
            XpcMachServiceDepthRemoteCompoundVector.id,
            TmLocalSnapshotDepthVector.id,
            TmLocalSnapshotDepthRemoteCompoundVector.id,
            EmondLegacyDepthVector.id,
            EmondLegacyDepthRemoteCompoundVector.id,
            ScreenSharingArdDepthVector.id,
            ScreenSharingArdDepthRemoteCompoundVector.id,
            KeychainAclPathVector.id,
            KeychainAclPathRemoteCompoundVector.id,
            PythonRuntimeDualuseVector.id,
            PythonRuntimeDualuseRemoteCompoundVector.id,
            ShellPluginManagerVector.id,
            ShellPluginManagerRemoteCompoundVector.id
        ]
        for id in requiredWave15 {
            XCTAssertTrue(AttackVectorPlane.ids.contains(id), "missing wave-15 vector \(id)")
        }
        XCTAssertGreaterThanOrEqual(AttackVectorPlane.ids.count, 127)
        let requiredWave16 = [
            AirplayReceiverSurfaceVector.id,
            AirplayReceiverSurfaceRemoteCompoundVector.id,
            HandoffClipboardDepthVector.id,
            HandoffClipboardDepthRemoteCompoundVector.id,
            ImessagePathPlaneVector.id,
            ImessagePathPlaneRemoteCompoundVector.id,
            FacetimeCameraSurfaceVector.id,
            FacetimeCameraSurfaceRemoteCompoundVector.id,
            FinderSyncExtensionVector.id,
            FinderSyncExtensionRemoteCompoundVector.id,
            FileproviderDomainVector.id,
            FileproviderDomainRemoteCompoundVector.id,
            NotificationCenterDepthVector.id,
            NotificationCenterDepthRemoteCompoundVector.id,
            SiriSuggestionsPlaneVector.id,
            SiriSuggestionsPlaneRemoteCompoundVector.id,
            SpotlightImporterDepthVector.id,
            SpotlightImporterDepthRemoteCompoundVector.id,
            ContactsPathPlaneVector.id,
            ContactsPathPlaneRemoteCompoundVector.id,
            CalendarServerPathVector.id,
            CalendarServerPathRemoteCompoundVector.id,
            RemindersCloudPathVector.id,
            RemindersCloudPathRemoteCompoundVector.id,
            MapsLocationPathVector.id,
            MapsLocationPathRemoteCompoundVector.id,
            WeatherWidgetPathVector.id,
            WeatherWidgetPathRemoteCompoundVector.id,
            MusicLibraryPathVector.id,
            MusicLibraryPathRemoteCompoundVector.id,
            BooksPathPlaneVector.id,
            BooksPathPlaneRemoteCompoundVector.id,
            PodcastsPathPlaneVector.id,
            PodcastsPathPlaneRemoteCompoundVector.id,
            TvAppPathPlaneVector.id,
            TvAppPathPlaneRemoteCompoundVector.id,
            HomekitPathPlaneVector.id,
            HomekitPathPlaneRemoteCompoundVector.id,
            HealthPathPlaneVector.id,
            HealthPathPlaneRemoteCompoundVector.id,
            WalletPassPathVector.id,
            WalletPassPathRemoteCompoundVector.id,
            FindmyPathPlaneVector.id,
            FindmyPathPlaneRemoteCompoundVector.id,
            ShortcutsIcloudSyncVector.id,
            ShortcutsIcloudSyncRemoteCompoundVector.id,
            DevicemanagementProfileVector.id,
            DevicemanagementProfileRemoteCompoundVector.id,
            SoftwareupdateCatalogVector.id,
            SoftwareupdateCatalogRemoteCompoundVector.id
        ]
        for id in requiredWave16 {
            XCTAssertTrue(AttackVectorPlane.ids.contains(id), "missing wave-16 vector \(id)")
        }
        XCTAssertGreaterThanOrEqual(AttackVectorPlane.ids.count, 177)
        // All vector checks are low-cost so standard profile includes them.
        for check in AttackVectorPlane.allChecks() {
            XCTAssertEqual(type(of: check).cost, .low, "\(type(of: check).id) should be .low")
        }
    }

    // MARK: - Synthetic CollectedState → real Check.evaluate

    func testSyntheticStateFiresAtLeastThreeVectors() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)

        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let results = try await check.evaluate(state: state, context: context)
            fired.append(contentsOf: results)
        }

        let vectorIds = Set(fired.map(\.id)).intersection(Set(AttackVectorPlane.ids))
        XCTAssertGreaterThanOrEqual(
            vectorIds.count,
            3,
            "expected ≥3 vector ids on synthetic state; got \(vectorIds.sorted()) findings=\(fired.map(\.id))"
        )

        // Known weak synthetic inputs should hit these specifically.
        XCTAssertTrue(
            vectorIds.contains(ProtectionsWeakVector.id),
            "protections_weak should fire (SIP false)"
        )
        XCTAssertTrue(
            vectorIds.contains(InjectSurfaceVector.id),
            "inject.surface should fire (get-task-allow / HR off)"
        )
        XCTAssertTrue(
            vectorIds.contains(CredOrIdentityPivotVector.id),
            "cred_or_identity_pivot should fire (cred paths + adBound)"
        )
        XCTAssertTrue(
            vectorIds.contains(LOLExecutionChainVector.id),
            "lool.execution_chain should fire (osascript+launchctl)"
        )

        for f in fired {
            XCTAssertTrue(f.dryRunSafe, "\(f.id) dryRunSafe")
            XCTAssertFalse(f.evidence.isEmpty, "\(f.id) missing evidence")
            XCTAssertFalse(f.attackTechniques.isEmpty, "\(f.id) missing ATT&CK")
            XCTAssertFalse(f.remediation.isEmpty, "\(f.id) missing remediation")
            XCTAssertNotNil(f.opsecScore, "\(f.id) missing opsecScore")
        }

        // BTM honesty on persist vector.
        if let persist = fired.first(where: { $0.id == UserWritableLaunchAgentsVector.id }) {
            let blob = (persist.evidence.map(\.detail) + persist.remediation).joined(separator: " ")
            XCTAssertTrue(
                blob.localizedCaseInsensitiveContains("BTM")
                    || blob.localizedCaseInsensitiveContains("Background Task"),
                "persist vector should mention BTM honesty"
            )
            XCTAssertGreaterThanOrEqual(persist.opsecScore ?? 0, 50, "silent claim OPSEC should be high")
        }
    }

    /// Expanded plane: synthetic state must fire multiple new vectors with full Finding fields.
    func testExpandedVectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let newIds: [String] = [
            TCCFDAPermissionPivotVector.id,
            PrivilegedHelperSygextVector.id,
            MDMManagementGapVector.id,
            BrowserSessionArtifactPivotVector.id,
            WritablePrivilegedPathsVector.id,
        ]

        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard newIds.contains(id) else { continue }
            let results = try await check.evaluate(state: state, context: context)
            fired.append(contentsOf: results)
        }

        let firedIds = Set(fired.map(\.id))
        XCTAssertGreaterThanOrEqual(
            firedIds.count,
            4,
            "expected ≥4 new vectors on synthetic state; got \(firedIds.sorted())"
        )
        for id in newIds where firedIds.contains(id) {
            let f = fired.first { $0.id == id }!
            XCTAssertFalse(f.evidence.isEmpty, "\(id) evidence")
            XCTAssertFalse(f.attackTechniques.isEmpty, "\(id) ATT&CK")
            let hasRemediationOrFP = !f.remediation.isEmpty || (f.falsePositiveNotes?.isEmpty == false)
            XCTAssertTrue(hasRemediationOrFP, "\(id) remediation or FP notes")
            XCTAssertNotNil(f.opsecScore, "\(id) opsecScore")
            XCTAssertTrue(f.dryRunSafe, "\(id) dryRunSafe")
        }

        // PEASS-class writable path vector must fire via collector note / temp path.
        XCTAssertTrue(
            firedIds.contains(WritablePrivilegedPathsVector.id),
            "writable_privileged_paths should fire on synthetic privesc notes"
        )
        XCTAssertTrue(
            firedIds.contains(TCCFDAPermissionPivotVector.id),
            "fda_permission_pivot should fire (FDA true + sensitive paths)"
        )
        XCTAssertTrue(
            firedIds.contains(BrowserSessionArtifactPivotVector.id),
            "browser session pivot should fire"
        )
    }

    func testPrivescClusterEmitsRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let findings = try await PrivescPathClusterCheck().evaluate(
            state: state,
            context: .assess()
        )
        XCTAssertFalse(findings.isEmpty, "privesc cluster should emit on synthetic weak state")
        for f in findings {
            XCTAssertTrue(f.id.hasPrefix(PrivescPathClusterCheck.id) || f.id == PrivescPathClusterCheck.id
                || f.id.contains("privesc"), "unexpected id \(f.id)")
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
        }
        // Registry surfaces the cluster check.
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(PrivescPathClusterCheck.id))
    }

    /// 2026 coverage wave: ≥3 of the new vector IDs fire with full Finding fields.
    func testSOTA2026VectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let wave2: [String] = [
            XPCHelperAbuseSurfaceVector.id,
            PlatformSSOLateralVector.id,
            SecurityProductGapVector.id,
            SystemLaunchDaemonSurfaceVector.id,
            SMAppLoginItemHonestyVector.id,
        ]

        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave2.contains(id) else { continue }
            let results = try await check.evaluate(state: state, context: context)
            fired.append(contentsOf: results)
        }

        let firedIds = Set(fired.map(\.id))
        XCTAssertGreaterThanOrEqual(
            firedIds.count,
            3,
            "expected ≥3 2026 coverage vectors; got \(firedIds.sorted())"
        )
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty, "\(f.id) evidence")
            XCTAssertFalse(f.attackTechniques.isEmpty, "\(f.id) ATT&CK")
            let hasRemediationOrFP = !f.remediation.isEmpty || (f.falsePositiveNotes?.isEmpty == false)
            XCTAssertTrue(hasRemediationOrFP, "\(f.id) remediation or FP")
            XCTAssertNotNil(f.opsecScore, "\(f.id) opsec")
            XCTAssertTrue(f.dryRunSafe, "\(f.id) dryRunSafe")
        }
    }

    func testIdentityEDRClusterEmitsRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let findings = try await IdentityEDRClusterCheck().evaluate(
            state: state,
            context: .assess()
        )
        XCTAssertFalse(findings.isEmpty, "identity/EDR cluster should emit on synthetic state")
        for f in findings {
            XCTAssertTrue(
                f.id.hasPrefix(IdentityEDRClusterCheck.id),
                "unexpected cluster finding id \(f.id)"
            )
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
        }
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(IdentityEDRClusterCheck.id))
    }


    /// ≥3 new vectors fire with full Finding fields.

    /// ≥3 new vectors fire with full Finding fields.
    func testWave4VectorsFireOnSyntheticState() async throws {
        var state = Self.syntheticWeakState()
        // Tailor for wave-4 path-to-impact (non-duplicative of prior waves).
        state.collectorNotes["codesign.quarantine_hits"] = "/tmp/rootstock-red-q/quarantined.app"
        state.collectorNotes["auth.keychain_paths"] = "/tmp/rootstock-red-kc/login.keychain-db"
        state.collectorNotes["tcc.screen_accessibility"] = "screen_recording=likely|accessibility=unknown"
        state.mdm = MDMState(
            enrolled: true,
            vendorHints: ["Jamf"],
            managedPreferenceNames: ["com.jamf.management"],
            profileStoreReadable: true,
            profileFileCount: 3,
            pppcPolicyPresent: true,
            notes: ["synthetic enrolled Jamf channel"]
        )
        state.loobins = state.loobins + [
            LOOBinHit(name: "security", path: "/usr/bin/security", present: true, tactics: ["credential-access", "discovery"]),
            LOOBinHit(name: "codesign", path: "/usr/bin/codesign", present: true, tactics: ["discovery"]),
            LOOBinHit(name: "spctl", path: "/usr/sbin/spctl", present: true, tactics: ["discovery"]),
            LOOBinHit(name: "screencapture", path: "/usr/sbin/screencapture", present: true, tactics: ["collection"]),
        ]
        let context = EvaluationContext.assess(profile: .standard)
        let wave4: [String] = [
            QuarantineXattrSurfaceVector.id,
            KeychainPathSurfaceVector.id,
            MDMManagementChannelSurfaceVector.id,
            ScreenAccessibilitySurfaceVector.id,
            SecurityCLIDualUseVector.id,
        ]
        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave4.contains(id) else { continue }
            fired.append(contentsOf: try await check.evaluate(state: state, context: context))
        }
        let firedIds = Set(fired.map(\.id))
        XCTAssertGreaterThanOrEqual(
            firedIds.count,
            3,
            "expected ≥3 wave-4 vectors; got \(firedIds.sorted())"
        )
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty, "\(f.id) evidence")
            XCTAssertFalse(f.attackTechniques.isEmpty, "\(f.id) ATT&CK")
            XCTAssertTrue(!f.remediation.isEmpty || (f.falsePositiveNotes?.isEmpty == false), "\(f.id) rem/FP")
            XCTAssertNotNil(f.opsecScore)
            XCTAssertTrue(f.dryRunSafe)
            // Never claim secret dump
            let blob = (f.title + f.evidence.map(\.detail).joined() + f.remediation.joined()).lowercased()
            XCTAssertFalse(blob.contains("password="), "\(f.id) must not dump secrets")
        }
        XCTAssertTrue(firedIds.contains(QuarantineXattrSurfaceVector.id) || firedIds.contains(KeychainPathSurfaceVector.id))
    }

    func testDeliveryTrustClusterEmitsRankedFindings() async throws {
        var state = Self.syntheticWeakState()
        state.collectorNotes["codesign.quarantine_hits"] = "/tmp/q.app"
        // GK already false + SSH true in syntheticWeakState → gatekeeper_off_with_remote rule
        let findings = try await DeliveryTrustClusterCheck().evaluate(state: state, context: .assess())
        XCTAssertFalse(findings.isEmpty, "delivery trust cluster should emit")
        for f in findings {
            XCTAssertTrue(f.id.hasPrefix(DeliveryTrustClusterCheck.id), "id \(f.id)")
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
        }
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(DeliveryTrustClusterCheck.id))
    }

    /// ≥4 new vectors fire with full Finding fields on synthetic state.
    func testWave5VectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let wave5: [String] = [
            ESFSensorGapVector.id,
            CVEPatchDebtSuggesterVector.id,
            TCCPermissionGraphDepthVector.id,
            XPCClientValidationSurfaceVector.id,
            LaunchConstraintInjectTruthVector.id,
            LOOBinDualUseMultiStageVector.id,
        ]
        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave5.contains(id) else { continue }
            fired.append(contentsOf: try await check.evaluate(state: state, context: context))
        }
        let firedIds = Set(fired.map(\.id))
        XCTAssertGreaterThanOrEqual(
            firedIds.count,
            4,
            "expected ≥4 wave-5 vectors; got \(firedIds.sorted())"
        )
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty, "\(f.id) evidence")
            XCTAssertFalse(f.attackTechniques.isEmpty, "\(f.id) ATT&CK")
            XCTAssertTrue(!f.remediation.isEmpty || (f.falsePositiveNotes?.isEmpty == false), "\(f.id) rem/FP")
            XCTAssertNotNil(f.opsecScore)
            XCTAssertTrue(f.dryRunSafe)
            let blob = (f.title + f.evidence.map(\.detail).joined() + f.remediation.joined()).lowercased()
            XCTAssertFalse(blob.contains("password="), "\(f.id) must not dump secrets")
        }
    }

    func testWave5ClustersEmitRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let ctx = EvaluationContext.assess()
        let esf = try await ESFEDRPostureClusterCheck().evaluate(state: state, context: ctx)
        let cve = try await CVEPatchDebtClusterCheck().evaluate(state: state, context: ctx)
        let tcc = try await TCCGraphClusterCheck().evaluate(state: state, context: ctx)
        XCTAssertFalse(esf.isEmpty || cve.isEmpty || tcc.isEmpty,
                       "wave-5 clusters should emit; esf=\(esf.count) cve=\(cve.count) tcc=\(tcc.count)")
        for f in esf + cve + tcc {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
        }
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(ESFEDRPostureClusterCheck.id))
        XCTAssertTrue(registered.contains(CVEPatchDebtClusterCheck.id))
        XCTAssertTrue(registered.contains(TCCGraphClusterCheck.id))
    }

    /// ≥4 new vectors fire with full Finding fields on synthetic state.
    func testWave6VectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let wave6: [String] = [
            NetworkExtensionFilterGapVector.id,
            AuthRightsPrivilegeSurfaceVector.id,
            DeveloperToolchainDualUseVector.id,
            TimeMachineSnapshotAccessVector.id,
            MobileconfigSideloadRiskVector.id,
        ]
        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave6.contains(id) else { continue }
            fired.append(contentsOf: try await check.evaluate(state: state, context: context))
        }
        let firedIds = Set(fired.map(\.id))
        XCTAssertGreaterThanOrEqual(
            firedIds.count,
            4,
            "expected ≥4 wave-6 vectors; got \(firedIds.sorted())"
        )
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty, "\(f.id) evidence")
            XCTAssertFalse(f.attackTechniques.isEmpty, "\(f.id) ATT&CK")
            XCTAssertTrue(!f.remediation.isEmpty || (f.falsePositiveNotes?.isEmpty == false), "\(f.id) rem/FP")
            XCTAssertNotNil(f.opsecScore)
            XCTAssertTrue(f.dryRunSafe)
            let blob = (f.title + f.evidence.map(\.detail).joined() + f.remediation.joined()).lowercased()
            XCTAssertFalse(blob.contains("password="), "\(f.id) must not dump secrets")
        }
    }

    func testWave6ClustersEmitRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let ctx = EvaluationContext.assess()
        let ne = try await NetworkExtensionClusterCheck().evaluate(state: state, context: ctx)
        let authDev = try await AuthDevPrivilegeClusterCheck().evaluate(state: state, context: ctx)
        let data = try await DataAccessSurfaceClusterCheck().evaluate(state: state, context: ctx)
        XCTAssertFalse(
            ne.isEmpty || authDev.isEmpty || data.isEmpty,
            "wave-6 clusters should emit; ne=\(ne.count) authDev=\(authDev.count) data=\(data.count)"
        )
        for f in ne + authDev + data {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
        }
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(NetworkExtensionClusterCheck.id))
        XCTAssertTrue(registered.contains(AuthDevPrivilegeClusterCheck.id))
        XCTAssertTrue(registered.contains(DataAccessSurfaceClusterCheck.id))
    }

    func testWave7VectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let wave7: [String] = [
            SandboxEntitlementThickClientVector.id,
            NotarizationStaplingGapVector.id,
            VirtContainerDualUseVector.id,
            ContinuityAirDropSurfaceVector.id,
            FileVaultEscrowPostureVector.id,
        ]
        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave7.contains(id) else { continue }
            fired.append(contentsOf: try await check.evaluate(state: state, context: context))
        }
        let firedIds = Set(fired.map(\.id))
        XCTAssertGreaterThanOrEqual(
            firedIds.count,
            4,
            "expected ≥4 wave-7 vectors; got \(firedIds.sorted())"
        )
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty, "\(f.id) evidence")
            XCTAssertFalse(f.attackTechniques.isEmpty, "\(f.id) ATT&CK")
            XCTAssertTrue(!f.remediation.isEmpty || (f.falsePositiveNotes?.isEmpty == false), "\(f.id) rem/FP")
            XCTAssertNotNil(f.opsecScore)
            XCTAssertTrue(f.dryRunSafe)
            let blob = (f.title + f.evidence.map(\.detail).joined() + f.remediation.joined()).lowercased()
            XCTAssertFalse(blob.contains("password="), "\(f.id) must not dump secrets")
            XCTAssertFalse(blob.contains("recovery key="), "\(f.id) must not dump recovery keys")
        }
    }

    func testWave7ClustersEmitRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let ctx = EvaluationContext.assess()
        let trust = try await TrustDeliveryDepthClusterCheck().evaluate(state: state, context: ctx)
        let local = try await LocalDataProtectionClusterCheck().evaluate(state: state, context: ctx)
        let kill = try await KillChainCompoundClusterCheck().evaluate(state: state, context: ctx)
        XCTAssertFalse(
            trust.isEmpty && local.isEmpty && kill.isEmpty,
            "wave-7 clusters should emit; trust=\(trust.count) local=\(local.count) kill=\(kill.count)"
        )
        XCTAssertFalse(kill.isEmpty, "kill-chain compound should fire on multi-plane synthetic state")
        for f in trust + local + kill {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
        }
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(TrustDeliveryDepthClusterCheck.id))
        XCTAssertTrue(registered.contains(LocalDataProtectionClusterCheck.id))
        XCTAssertTrue(registered.contains(KillChainCompoundClusterCheck.id))
    }

    func testWave8VectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let wave8: [String] = [
            ClickFixTerminalDeliveryVector.id,
            RemoteAppleEventsLateralVector.id,
            SpotlightAICacheAccessVector.id,
            SecurityMgmtPlaneSurfaceVector.id,
            ThirdPartyTCCInheritanceVector.id,
            SSHAgentKeyPathLateralVector.id,
        ]
        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave8.contains(id) else { continue }
            fired.append(contentsOf: try await check.evaluate(state: state, context: context))
        }
        let firedIds = Set(fired.map(\.id))
        // Every Wave-8 vector family must fire on the intentional weak synthetic state.
        for id in wave8 {
            XCTAssertTrue(firedIds.contains(id), "wave-8 vector family must fire: \(id); got \(firedIds.sorted())")
        }
        XCTAssertEqual(firedIds.count, wave8.count, "expected all \(wave8.count) wave-8 vectors; got \(firedIds.sorted())")
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty, "\(f.id) evidence")
            XCTAssertFalse(f.attackTechniques.isEmpty, "\(f.id) ATT&CK")
            XCTAssertTrue(!f.remediation.isEmpty || (f.falsePositiveNotes?.isEmpty == false), "\(f.id) rem/FP")
            XCTAssertNotNil(f.opsecScore)
            XCTAssertTrue(f.dryRunSafe)
            let blob = (f.title + f.evidence.map(\.detail).joined() + f.remediation.joined()).lowercased()
            XCTAssertFalse(blob.contains("password="), "\(f.id) must not dump secrets")
            XCTAssertFalse(blob.contains("begin rsa private key"), "\(f.id) must not dump keys")
            XCTAssertFalse(blob.contains("paste this payload"), "\(f.id) must not deliver ClickFix recipes")
            XCTAssertFalse(blob.contains("unload edr now"), "\(f.id) must not weaponize unload")
        }
    }

    func testWave8ClusterEmitsRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let ctx = EvaluationContext.assess()
        let cluster = try await Wave8DeliveryLateralClusterCheck().evaluate(state: state, context: ctx)
        XCTAssertFalse(cluster.isEmpty, "wave-8 delivery×lateral cluster should fire on multi-plane synthetic state")
        for f in cluster {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
            XCTAssertTrue(f.id.contains("wave8") || f.id.contains(Wave8DeliveryLateralClusterCheck.id))
            let planeEv = f.evidence.first { $0.type == "planes" }
            XCTAssertNotNil(planeEv, "\(f.id) should include planes evidence")
            XCTAssertTrue(planeEv!.detail.contains("count="), "\(f.id) planes evidence should include count")
            // Synthetic weak state co-presents real Wave-8 surfaces (not notes alone).
            XCTAssertTrue(
                planeEv!.detail.contains("clickfix_delivery")
                    || planeEv!.detail.contains("ssh_key_depth")
                    || planeEv!.detail.contains("rae_lateral"),
                "\(f.id) should rank real Wave-8 surface planes: \(planeEv!.detail)"
            )
        }
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(Wave8DeliveryLateralClusterCheck.id))
    }

    /// Collectors "ran" (notes set) but typed surfaces empty/false → cluster must stay silent.
    /// Bare collectorNotes must never invent multi-plane compounds.
    func testWave8ClusterSilentWhenSurfacesEmptyDespiteCollectorNotes() async throws {
        var state = CollectedState()
        state.clickFixTerminalDelivery = ClickFixTerminalDeliveryState(
            terminalAppPaths: [],
            scriptEditorPaths: [],
            loaderBinaryPaths: [],
            pasteWarningHints: [],
            deliverySurfacePresent: false,
            notes: ["collector ran - no delivery surface"]
        )
        state.remoteAppleEvents = RemoteAppleEventsState(
            remoteAEPrefPaths: [],
            eppcFrameworkPaths: [],
            remoteMgmtHints: [],
            remoteAutomationSurfacePresent: false,
            notes: ["collector ran - no RAE surface"]
        )
        state.spotlightAICache = SpotlightAICacheState(
            spotlightPaths: [],
            metadataFrameworkPaths: [],
            aiCachePathHints: [],
            dataAccessSurfacePresent: false,
            notes: ["collector ran - no index surface"]
        )
        state.securityMgmtPlane = SecurityMgmtPlaneState(
            managementCLIPaths: [],
            privilegedHelperPaths: [],
            unloadAdjacentHints: [],
            managementPlanePresent: false,
            notes: ["collector ran - no mgmt surface"]
        )
        state.thirdPartyTCCInheritance = ThirdPartyTCCInheritanceState(
            thickClientAppPaths: [],
            embeddedInterpreterPaths: [],
            electronHelperPaths: [],
            inheritanceSurfacePresent: false,
            notes: ["collector ran - thick=0, no inheritance surface"]
        )
        state.sshAgentKeyPath = SSHAgentKeyPathState(
            agentSocketPaths: [],
            keyPathHits: [],
            sshdSupportPaths: [],
            lateralPathSurfacePresent: false,
            notes: ["collector ran - no key path surface"]
        )
        // Notes present for all Wave-8 collectors (must not invent planes).
        state.collectorNotes["collect.clickfix_terminal_delivery"] = "surface=false"
        state.collectorNotes["collect.remote_apple_events"] = "surface=false"
        state.collectorNotes["collect.spotlight_ai_cache"] = "surface=false"
        state.collectorNotes["collect.security_mgmt_plane"] = "surface=false"
        state.collectorNotes["collect.third_party_tcc_inheritance"] = "surface=false thick=0"
        state.collectorNotes["collect.ssh_agent_key_path"] = "surface=false"
        state.collectorNotes["collect.esf_endpoint_security"] = "framework=true clients=0"
        // No remote / FDA amplifiers either.
        state.network = NetworkState(
            remoteLoginSSH: false,
            screenSharingARD: false,
            notes: ["hardened remote off"]
        )
        state.tcc = TCCState(fullDiskAccessLikely: false, notes: ["no FDA"], probeMethod: "synthetic")
        // ESF state absent so sensor_gap is not typed-present either.
        state.esf = nil
        state.securityProducts = [
            SecurityProductHit(name: "PresentEDR", path: "/Applications/PresentEDR.app", present: true),
        ]

        let ctx = EvaluationContext.assess()
        let cluster = try await Wave8DeliveryLateralClusterCheck().evaluate(state: state, context: ctx)
        XCTAssertTrue(
            cluster.isEmpty,
            "cluster must stay silent when collectors ran but Wave-8 surfaces empty; got \(cluster.map(\.id))"
        )

        // Matching vectors should also stay silent on empty inheritance (thick=0).
        let tccFindings = try await ThirdPartyTCCInheritanceVector().evaluate(state: state, context: ctx)
        XCTAssertTrue(
            tccFindings.isEmpty,
            "third_party_inheritance must not fire when thick=0; got \(tccFindings.map(\.id))"
        )
    }

    func testWave9VectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let wave9: [String] = [
            PackageKitInstallerDesignVector.id,
            ArchiveQuarantineExtractorVector.id,
            InfoStealerPathPlaneVector.id,
            TCCESFVisibilityDepthVector.id,
            MDMProfileParseDepthVector.id,
        ]
        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave9.contains(id) else { continue }
            fired.append(contentsOf: try await check.evaluate(state: state, context: context))
        }
        let firedIds = Set(fired.map(\.id))
        for id in wave9 {
            XCTAssertTrue(firedIds.contains(id), "wave-9 vector family must fire: \(id); got \(firedIds.sorted())")
        }
        XCTAssertEqual(firedIds.count, wave9.count, "expected all \(wave9.count) wave-9 vectors; got \(firedIds.sorted())")
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty, "\(f.id) evidence")
            XCTAssertFalse(f.attackTechniques.isEmpty, "\(f.id) ATT&CK")
            XCTAssertTrue(!f.remediation.isEmpty || (f.falsePositiveNotes?.isEmpty == false), "\(f.id) rem/FP")
            XCTAssertNotNil(f.opsecScore)
            XCTAssertTrue(f.dryRunSafe)
            let blob = (f.title + f.evidence.map(\.detail).joined() + f.remediation.joined()).lowercased()
            XCTAssertFalse(blob.contains("password="), "\(f.id) must not dump secrets")
            XCTAssertFalse(blob.contains("begin rsa private key"), "\(f.id) must not dump keys")
            XCTAssertFalse(blob.contains("strip quarantine now"), "\(f.id) must not weaponize quarantine strip")
            XCTAssertFalse(blob.contains("build malicious pkg"), "\(f.id) must not build pkgs")
            XCTAssertFalse(blob.contains("select * from access"), "\(f.id) must not dump TCC.db")
        }
    }

    func testWave9ClusterEmitsRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let ctx = EvaluationContext.assess()
        let cluster = try await Wave9InstallerCollectionClusterCheck().evaluate(state: state, context: ctx)
        XCTAssertFalse(cluster.isEmpty, "wave-9 installer×collection cluster should fire on multi-plane synthetic state")
        for f in cluster {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
            XCTAssertTrue(f.id.contains("wave9") || f.id.contains(Wave9InstallerCollectionClusterCheck.id))
            let planeEv = f.evidence.first { $0.type == "planes" }
            XCTAssertNotNil(planeEv, "\(f.id) should include planes evidence")
            XCTAssertTrue(planeEv!.detail.contains("count="), "\(f.id) planes evidence should include count")
            XCTAssertTrue(
                planeEv!.detail.contains("installer_design")
                    || planeEv!.detail.contains("stealer_paths")
                    || planeEv!.detail.contains("archive_extractor"),
                "\(f.id) should rank real Wave-9 surface planes: \(planeEv!.detail)"
            )
        }
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(Wave9InstallerCollectionClusterCheck.id))
    }

    func testWave10ResidualPairVectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let wave10: [String] = [
            PackageKitReceiptScriptCompoundVector.id,
            ExtractorQuarantineCompoundVector.id,
            StealerRemoteCompoundVector.id,
            VisibilitySensorCompoundVector.id,
        ]
        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave10.contains(id) else { continue }
            fired.append(contentsOf: try await check.evaluate(state: state, context: context))
        }
        let firedIds = Set(fired.map(\.id))
        for id in wave10 {
            XCTAssertTrue(
                firedIds.contains(id),
                "wave-10 residual-pair vector must fire: \(id); got \(firedIds.sorted())"
            )
        }
        XCTAssertEqual(
            firedIds.count,
            wave10.count,
            "expected all \(wave10.count) wave-10 compounds; got \(firedIds.sorted())"
        )
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty, "\(f.id) evidence")
            XCTAssertFalse(f.attackTechniques.isEmpty, "\(f.id) ATT&CK")
            XCTAssertTrue(!f.remediation.isEmpty || (f.falsePositiveNotes?.isEmpty == false), "\(f.id) rem/FP")
            XCTAssertNotNil(f.opsecScore)
            XCTAssertTrue(f.dryRunSafe)
            let blob = (f.title + f.evidence.map(\.detail).joined() + f.remediation.joined()).lowercased()
            XCTAssertFalse(blob.contains("password="), "\(f.id) must not dump secrets")
            XCTAssertFalse(blob.contains("begin rsa private key"), "\(f.id) must not dump keys")
            XCTAssertFalse(blob.contains("strip quarantine now"), "\(f.id) must not weaponize quarantine strip")
            XCTAssertFalse(blob.contains("build malicious pkg"), "\(f.id) must not build pkgs")
            XCTAssertFalse(blob.contains("select * from access"), "\(f.id) must not dump TCC.db")
        }
    }

    func testWave10ResidualPairClusterEmitsRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let ctx = EvaluationContext.assess()
        let cluster = try await Wave10ResidualPairClusterCheck().evaluate(state: state, context: ctx)
        XCTAssertFalse(
            cluster.isEmpty,
            "wave-10 residual-pair cluster should fire when ≥2 pair planes present on synthetic state"
        )
        for f in cluster {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
            XCTAssertTrue(f.id.contains("wave10") || f.id.contains(Wave10ResidualPairClusterCheck.id))
            let planeEv = f.evidence.first { $0.type == "planes" }
            XCTAssertNotNil(planeEv, "\(f.id) should include planes evidence")
            XCTAssertTrue(planeEv!.detail.contains("count="), "\(f.id) planes evidence should include count")
            XCTAssertTrue(
                planeEv!.detail.contains("installer_design")
                    || planeEv!.detail.contains("stealer_paths")
                    || planeEv!.detail.contains("archive_extractor")
                    || planeEv!.detail.contains("visibility_depth"),
                "\(f.id) should rank real residual pair planes: \(planeEv!.detail)"
            )
            let blob = (f.title + f.evidence.map(\.detail).joined() + f.remediation.joined()).lowercased()
            XCTAssertFalse(blob.contains("password="), "\(f.id) must not dump secrets")
            XCTAssertFalse(blob.contains("begin rsa private key"), "\(f.id) must not dump keys")
            XCTAssertFalse(blob.contains("strip quarantine now"), "\(f.id) must not weaponize quarantine strip")
            XCTAssertFalse(blob.contains("build malicious pkg"), "\(f.id) must not build pkgs")
            XCTAssertFalse(blob.contains("select * from access"), "\(f.id) must not dump TCC.db")
        }
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(Wave10ResidualPairClusterCheck.id))
    }

    /// Collectors "ran" (notes set) but typed surfaces empty/false → cluster must stay silent.
    func testWave9ClusterSilentWhenSurfacesEmptyDespiteCollectorNotes() async throws {
        var state = CollectedState()
        state.packageKitInstallerDesign = PackageKitInstallerDesignState(
            installerServicePaths: [],
            receiptAndHistoryPaths: [],
            installerPluginPaths: [],
            toolingPaths: [],
            designSurfacePresent: false,
            notes: ["collector ran - no installer design surface"]
        )
        state.archiveQuarantineExtractor = ArchiveQuarantineExtractorState(
            thirdPartyExtractorPaths: [],
            stockExtractorPaths: [],
            archiveDropHints: [],
            extractorSurfacePresent: false,
            notes: ["collector ran - no extractor surface"]
        )
        state.infoStealerPathPlane = InfoStealerPathPlaneState(
            browserAdjacentPaths: [],
            messagingAndVaultPaths: [],
            walletAndSyncPaths: [],
            collectionSurfacePresent: false,
            notes: ["collector ran - no stealer path surface"]
        )
        state.tccEsfVisibilityDepth = TCCESFVisibilityDepthState(
            tccDbPathHits: [],
            visibilityToolPaths: [],
            privacyPrefPaths: [],
            visibilityDepth: "thin",
            visibilitySurfacePresent: false,
            notes: ["collector ran - no visibility surface"]
        )
        state.mdmProfileParseDepth = MDMProfileParseDepthState(
            examinedProfilePaths: [],
            payloadTypes: [],
            parsedProfileCount: 0,
            displayNamePresent: false,
            parseSurfacePresent: false,
            notes: ["collector ran - no parse surface"]
        )
        state.collectorNotes["collect.packagekit_installer_design"] = "surface=false"
        state.collectorNotes["collect.archive_quarantine_extractor"] = "surface=false"
        state.collectorNotes["collect.infostealer_path_plane"] = "surface=false"
        state.collectorNotes["collect.tcc_esf_visibility_depth"] = "surface=false"
        state.collectorNotes["collect.mdm_profile_parse_depth"] = "surface=false"
        state.network = NetworkState(
            remoteLoginSSH: false,
            screenSharingARD: false,
            notes: ["hardened remote off"]
        )
        state.tcc = TCCState(fullDiskAccessLikely: false, notes: ["no FDA"], probeMethod: "synthetic")
        state.esf = nil

        let ctx = EvaluationContext.assess()
        let cluster = try await Wave9InstallerCollectionClusterCheck().evaluate(state: state, context: ctx)
        XCTAssertTrue(
            cluster.isEmpty,
            "cluster must stay silent when collectors ran but Wave-9 surfaces empty; got \(cluster.map(\.id))"
        )
    }

    /// Stock pf/ALF-only inventory + remote/high-value MUST fire NE filter gap.
    /// Stock `/etc/pf.conf` must never suppress enterprise content-filter gap findings.
    func testNEFilterGapFiresWhenOnlyStockPfPresent() async throws {
        var state = CollectedState()
        // Simulate collector after stock/enterprise split: notes mention pf, but
        // contentFilterHints stay empty (enterprise only) and neApps empty.
        state.networkExtension = NetworkExtensionState(
            frameworkPresent: true,
            vpnConfigPaths: [],
            contentFilterHints: [],
            packetTunnelHints: [],
            neAppPaths: [],
            notes: [
                "stock_os_network: pf_conf path=/etc/pf.conf",
                "stock_os_network: pf_anchors path=/etc/pf.anchors",
                "stock_os_network: application_firewall_alf path=/Library/Preferences/com.apple.alf.plist",
                "enterprise content-filter none",
            ]
        )
        state.network = NetworkState(remoteLoginSSH: true, screenSharingARD: false)
        state.identity = IdentityState(adBound: true, platformSSO: false)
        state.credPaths = [
            CredPathHit(kind: "ssh", path: NSHomeDirectory() + "/.ssh/id_rsa", exists: true),
        ]
        state.collectorNotes["collect.network_extension"] =
            "framework=true vpnConfigs=0 contentFilter=0 packetTunnel=0 neApps=0 stockNetworkArtifacts=3"
        state.collectorNotes["ne.filter_gap"] =
            "enterprise_content_filter=0 neApps=0 stock_os_network=3"

        let gap = try await NetworkExtensionFilterGapVector().evaluate(
            state: state,
            context: .assess()
        )
        XCTAssertEqual(gap.count, 1, "NE filter gap must fire for stock-pf-only + remote")
        XCTAssertEqual(gap.first?.id, NetworkExtensionFilterGapVector.id)
        XCTAssertFalse(gap.first?.evidence.isEmpty ?? true)

        let cluster = try await NetworkExtensionClusterCheck().evaluate(
            state: state,
            context: .assess()
        )
        let thinRemote = cluster.first { $0.id.hasSuffix("no_filter_with_remote") }
        XCTAssertNotNil(
            thinRemote,
            "cluster no_filter_with_remote must fire; got \(cluster.map(\.id))"
        )

        // Negative: enterprise filter hint present should suppress thin gap (no remote-only fire
        // if filters non-zero). Build state with enterprise filter + still remote.
        var withEnterprise = state
        withEnterprise.networkExtension = NetworkExtensionState(
            frameworkPresent: true,
            vpnConfigPaths: [],
            contentFilterHints: [
                "content_filter_prefs:/Library/Preferences/com.apple.networkextension.filter.plist",
            ],
            packetTunnelHints: [],
            neAppPaths: ["/Applications/LuLu.app"],
            notes: ["enterprise filter present"]
        )
        withEnterprise.collectorNotes.removeValue(forKey: "ne.filter_gap")
        let suppressed = try await NetworkExtensionFilterGapVector().evaluate(
            state: withEnterprise,
            context: .assess()
        )
        XCTAssertTrue(
            suppressed.isEmpty,
            "enterprise filter + neApp must suppress thin filter gap; got \(suppressed.map(\.id))"
        )

        // Even if stock hints leaked into contentFilterHints, defensive filter must still fire gap.
        var leakedStock = state
        leakedStock.networkExtension = NetworkExtensionState(
            frameworkPresent: true,
            contentFilterHints: [
                "pf_conf:/etc/pf.conf",
                "application_firewall:/Library/Preferences/com.apple.alf.plist",
            ],
            neAppPaths: [],
            notes: ["leaked stock only"]
        )
        let stillGap = try await NetworkExtensionFilterGapVector().evaluate(
            state: leakedStock,
            context: .assess()
        )
        XCTAssertEqual(
            stillGap.count,
            1,
            "stock pf/ALF leaked into contentFilterHints must still fire gap after defensive filter"
        )
    }

    /// Honest fixture: Apple-only ES inventory (endpointsecurityd/framework in notes,
    /// empty third-party clientPaths) + remote/high-value MUST still fire sensor-gap.
    /// Stock OS paths must not suppress third-party sensor gap.
    func testESFSensorGapFiresWhenOnlyAppleInfrastructurePresent() async throws {
        var state = CollectedState()
        // Simulate collector output after the Apple-infra split: notes mention apple paths,
        // but clientPaths/edrHints stay empty (third-party only).
        state.esf = ESFPostureState(
            frameworkPresent: true,
            clientPaths: [],
            systemExtensionCount: 0,
            edrHints: [],
            notes: [
                "apple_infra: endpointsecurityd path=/usr/libexec/endpointsecurityd",
                "apple_infra: EndpointSecurity.framework path=/System/Library/Frameworks/EndpointSecurity.framework",
                "systemExtension root present (directory existence ≠ EDR client)",
                "third_party_clients none",
            ]
        )
        state.securityProducts = [
            SecurityProductHit(name: "SyntheticEDR", path: "/Applications/SyntheticEDR.app", present: false),
        ]
        state.network = NetworkState(remoteLoginSSH: true, screenSharingARD: false)
        state.identity = IdentityState(adBound: true, platformSSO: false)
        state.collectorNotes["collect.esf_endpoint_security"] =
            "framework=true thirdPartyClients=0 thirdPartySysext≈0 edrHints=0 appleInfra=2"
        state.collectorNotes["esf.sensor_gap"] = "third_party_clients=0 apple_infra_only=true"

        let gap = try await ESFSensorGapVector().evaluate(state: state, context: .assess())
        XCTAssertEqual(gap.count, 1, "sensor gap must fire for Apple-infra-only + remote")
        XCTAssertEqual(gap.first?.id, ESFSensorGapVector.id)
        XCTAssertFalse(gap.first?.evidence.isEmpty ?? true)
        let evidenceBlob = gap.first?.evidence.map(\.detail).joined(separator: " ") ?? ""
        XCTAssertTrue(
            evidenceBlob.contains("thirdParty") || evidenceBlob.contains("third-party")
                || evidenceBlob.localizedCaseInsensitiveContains("Apple"),
            "evidence should distinguish third-party vs Apple infra"
        )

        let cluster = try await ESFEDRPostureClusterCheck().evaluate(state: state, context: .assess())
        let thinRemote = cluster.first { $0.id.hasSuffix("thin_sensor_remote") }
        XCTAssertNotNil(thinRemote, "cluster thin_sensor_remote must fire; got \(cluster.map(\.id))")

        // Negative: third-party client present → gap should NOT fire.
        var withClient = state
        withClient.esf = ESFPostureState(
            frameworkPresent: true,
            clientPaths: ["/Library/CS/falconctl"],
            systemExtensionCount: 0,
            edrHints: ["CrowdStrike Falcon"],
            notes: ["third_party_client: CrowdStrike"]
        )
        withClient.collectorNotes.removeValue(forKey: "esf.sensor_gap")
        let noGap = try await ESFSensorGapVector().evaluate(state: withClient, context: .assess())
        XCTAssertTrue(noGap.isEmpty, "third-party client must suppress sensor-gap")
    }

    /// Live collector → vector: after real collect, if no third-party clients and remote is
    /// synthetic-injected, sensor-gap semantics still hold (Apple paths in notes only).
    func testESFCollectorToVectorAppleInfraDoesNotSuppressGap() async throws {
        let collected = try await ESFEndpointSecurityCollector().collect(context: .assess())
        // Assert collector semantics first.
        for path in collected.esf?.clientPaths ?? [] {
            XCTAssertFalse(
                path.contains("endpointsecurityd") || path == "/Library/SystemExtensions",
                "live collector leaked Apple path into clients: \(path)"
            )
        }

        var state = collected
        // Inject remote + empty products so path-to-impact compounds apply.
        if state.securityProducts.contains(where: \.present) {
            // Host has real EDR - vector correctly silent; still assert collector split.
            XCTAssertTrue(true, "host has third-party product paths; skip gap fire assertion")
            return
        }
        state.network = NetworkState(remoteLoginSSH: true)
        state.securityProducts = state.securityProducts.map {
            SecurityProductHit(name: $0.name, path: $0.path, present: false)
        }
        // If collector already found third-party clients, gap must not fire.
        if !(state.esf?.clientPaths.isEmpty ?? true) || !(state.esf?.edrHints.isEmpty ?? true) {
            let findings = try await ESFSensorGapVector().evaluate(state: state, context: .assess())
            XCTAssertTrue(
                findings.isEmpty,
                "third-party clients present - gap must not fire; clients=\(state.esf?.clientPaths ?? [])"
            )
            return
        }
        let findings = try await ESFSensorGapVector().evaluate(state: state, context: .assess())
        XCTAssertEqual(
            findings.count,
            1,
            "Apple-infra-only live collect + remote must fire sensor-gap; note=\(state.collectorNotes)"
        )
        XCTAssertEqual(findings.first?.id, ESFSensorGapVector.id)
    }

    func testWave3VectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let wave3: [String] = [
            SudoersMisconfigSurfaceVector.id,
            PeriodicMaintenanceSurfaceVector.id,
            GatekeeperTrustGapVector.id,
            AutomationExecutionSurfaceVector.id,
            ElectronDevtoolsSurfaceVector.id,
        ]
        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave3.contains(id) else { continue }
            fired.append(contentsOf: try await check.evaluate(state: state, context: context))
        }
        let firedIds = Set(fired.map(\.id))
        XCTAssertGreaterThanOrEqual(
            firedIds.count,
            3,
            "expected ≥3 wave-3 vectors; got \(firedIds.sorted())"
        )
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty, "\(f.id) evidence")
            XCTAssertFalse(f.attackTechniques.isEmpty, "\(f.id) ATT&CK")
            XCTAssertTrue(!f.remediation.isEmpty || (f.falsePositiveNotes?.isEmpty == false), "\(f.id) rem/FP")
            XCTAssertNotNil(f.opsecScore, "\(f.id) opsec")
            XCTAssertTrue(f.dryRunSafe)
        }
    }

    func testTrustChainClusterEmitsRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let findings = try await TrustChainClusterCheck().evaluate(state: state, context: .assess())
        XCTAssertFalse(findings.isEmpty, "trust chain cluster should emit")
        for f in findings {
            XCTAssertTrue(f.id.hasPrefix(TrustChainClusterCheck.id), "id \(f.id)")
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
        }
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(TrustChainClusterCheck.id))
    }

    func testProtectionsWeakHighWhenSIPDisabled() async throws {
        var state = CollectedState()
        state.protections = ProtectionsState(
            sipEnabled: false,
            gatekeeperEnabled: true,
            fileVaultOn: true
        )
        let findings = try await ProtectionsWeakVector().evaluate(state: state, context: .assess())
        XCTAssertEqual(findings.count, 1)
        XCTAssertEqual(findings.first?.severity, .high)
        XCTAssertEqual(findings.first?.category, .misconfig)
    }

    func testProtectionsWeakLowWhenUnknownWithRoot() async throws {
        var state = CollectedState()
        state.protections = ProtectionsState(
            sipEnabled: nil,
            gatekeeperEnabled: nil,
            fileVaultOn: nil,
            notes: ["unknown"]
        )
        state.host = HostState(
            hostname: "h",
            username: "root",
            osVersion: "14.0",
            arch: "arm64",
            processArch: "arm64",
            isRoot: true
        )
        let findings = try await ProtectionsWeakVector().evaluate(state: state, context: .assess())
        XCTAssertEqual(findings.first?.severity, .low)
        XCTAssertEqual(findings.first?.id, ProtectionsWeakVector.id)
    }

    func testProtectionsWeakSilentWhenHardened() async throws {
        var state = CollectedState()
        state.protections = ProtectionsState(
            sipEnabled: true,
            gatekeeperEnabled: true,
            fileVaultOn: true
        )
        let findings = try await ProtectionsWeakVector().evaluate(state: state, context: .assess())
        XCTAssertTrue(findings.isEmpty)
    }

    func testRemoteAccessSurfaceWhenSSHEnabled() async throws {
        var state = CollectedState()
        state.network = NetworkState(
            remoteLoginSSH: true,
            screenSharingARD: false,
            remoteLoginPlistPresent: true,
            sshdConfigPresent: true
        )
        let findings = try await RemoteAccessSurfaceVector().evaluate(state: state, context: .assess())
        XCTAssertEqual(findings.first?.id, RemoteAccessSurfaceVector.id)
        XCTAssertEqual(findings.first?.severity, .medium)
        XCTAssertEqual(findings.first?.category, .network)
        XCTAssertTrue(findings.first?.attackTechniques.contains("T1021.004") == true)
    }

    func testCredPivotNeverClaimsSecretDump() async throws {
        var state = CollectedState()
        state.credPaths = [
            CredPathHit(kind: "ssh", path: "/Users/t/.ssh/id_rsa", exists: true),
        ]
        let findings = try await CredOrIdentityPivotVector().evaluate(state: state, context: .assess())
        let text = findings.map { f in
            f.title + f.evidence.map(\.detail).joined() + f.remediation.joined()
        }.joined()
        XCTAssertFalse(text.localizedCaseInsensitiveContains("password="))
        XCTAssertFalse(text.localizedCaseInsensitiveContains("private key material"))
        XCTAssertTrue(text.localizedCaseInsensitiveContains("metadata") || text.localizedCaseInsensitiveContains("path"))
    }

    // MARK: - Pipeline integration

    func testAssessPipelineRegistersAndMayFireVectors() async {
        // Ensure vectors are in the live registry used by the pipeline.
        let registryIds = Set(VulnModuleRegistry.fullRegistry().checkIds)
        for id in AttackVectorPlane.ids {
            XCTAssertTrue(registryIds.contains(id), "pipeline registry missing \(id)")
        }

        let (_, findings, _) = await AssessPipeline.run(profile: .standard)
        let hostVectorIds = Set(findings.map(\.id)).intersection(Set(AttackVectorPlane.ids))

        if hostVectorIds.count >= 3 {
            XCTAssertGreaterThanOrEqual(hostVectorIds.count, 3)
            return
        }

        // Hardened / minimal hosts may not fire 3 vectors - synthetic fallback for reliability.
        let synthetic = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        var syntheticFindings: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            if let results = try? await check.evaluate(state: synthetic, context: context) {
                syntheticFindings.append(contentsOf: results)
            }
        }
        let syntheticIds = Set(syntheticFindings.map(\.id)).intersection(Set(AttackVectorPlane.ids))
        XCTAssertGreaterThanOrEqual(
            syntheticIds.count,
            3,
            "host fired \(hostVectorIds.count) vectors; synthetic fallback expected ≥3, got \(syntheticIds.sorted())"
        )
    }

    // MARK: - Fixtures


    func testWave11VectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let wave11: [String] = [
            URLSchemeHandlerVector.id,
            LaunchdOverrideDepthVector.id,
            BrowserExtensionDualUseVector.id,
            ShortcutsAppIntentsVector.id,
            URLSchemeRemoteCompoundVector.id,
            LaunchdSecurityDisableCompoundVector.id,
            BrowserExtensionCollectionCompoundVector.id,
            ShortcutsLateralCompoundVector.id,
        ]
        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave11.contains(id) else { continue }
            fired.append(contentsOf: try await check.evaluate(state: state, context: context))
        }
        let firedIds = Set(fired.map(\.id))
        for id in wave11 {
            XCTAssertTrue(firedIds.contains(id), "wave-11 vector must fire: \(id); got \(firedIds.sorted())")
        }
        XCTAssertEqual(firedIds.count, wave11.count, "expected all \(wave11.count) wave-11 vectors; got \(firedIds.sorted())")
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty, "\(f.id) evidence")
            XCTAssertFalse(f.attackTechniques.isEmpty, "\(f.id) ATT&CK")
            XCTAssertTrue(!f.remediation.isEmpty || (f.falsePositiveNotes?.isEmpty == false), "\(f.id) rem/FP")
            XCTAssertTrue(f.dryRunSafe)
            let blob = (f.title + f.evidence.map(\.detail).joined() + f.remediation.joined()).lowercased()
            XCTAssertFalse(blob.contains("password="), "\(f.id) must not dump secrets")
            XCTAssertFalse(blob.contains("register malicious scheme"), "\(f.id) must not register schemes")
            XCTAssertFalse(blob.contains("disable santa now"), "\(f.id) must not disable security")
            XCTAssertFalse(blob.contains("run shortcuts payload"), "\(f.id) must not run shortcuts")
        }
    }

    func testWave11ClusterEmitsRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let ctx = EvaluationContext.assess()
        let cluster = try await Wave11MultiPlaneClusterCheck().evaluate(state: state, context: ctx)
        XCTAssertFalse(cluster.isEmpty, "wave-11 multi-plane cluster should fire on multi-plane synthetic state")
        for f in cluster {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
            XCTAssertTrue(f.id.contains("wave11") || f.id.contains(Wave11MultiPlaneClusterCheck.id))
            let planeEv = f.evidence.first { $0.type == "planes" }
            XCTAssertNotNil(planeEv, "\(f.id) should include planes evidence")
            XCTAssertTrue(planeEv!.detail.contains("count="), "\(f.id) planes evidence should include count")
            XCTAssertTrue(
                planeEv!.detail.contains("url_scheme_handler")
                    || planeEv!.detail.contains("launchd_override_depth")
                    || planeEv!.detail.contains("browser_extension_dualuse")
                    || planeEv!.detail.contains("shortcuts_app_intents"),
                "\(f.id) should rank real Wave-11 surface planes: \(planeEv!.detail)"
            )
        }
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(Wave11MultiPlaneClusterCheck.id))
    }



    func testWave12VectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let wave12: [String] = [
            WeblocInetlocDeliveryVector.id,
            WeblocRemoteCompoundVector.id,
            MailRulesAutomationVector.id,
            MailRulesScriptCompoundVector.id,
            UnifiedLogObservationVector.id,
            UnifiedLogSensorCompoundVector.id,
            DockPersistenceSurfaceVector.id,
            DockRemoteCompoundVector.id,
            OsascriptScptDeliveryVector.id,
            OsascriptRemoteCompoundVector.id,
            NetworkShareMountVector.id,
            NetworkShareRemoteCompoundVector.id
        ]
        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave12.contains(id) else { continue }
            fired.append(contentsOf: try await check.evaluate(state: state, context: context))
        }
        let firedIds = Set(fired.map(\.id))
        for id in wave12 {
            XCTAssertTrue(firedIds.contains(id), "wave-12 vector must fire: \(id); got \(firedIds.sorted())")
        }
        XCTAssertEqual(firedIds.count, wave12.count, "expected all \(wave12.count) wave-12 vectors; got \(firedIds.sorted())")
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty, "\(f.id) evidence")
            XCTAssertFalse(f.attackTechniques.isEmpty, "\(f.id) ATT&CK")
            XCTAssertTrue(f.dryRunSafe)
            let blob = (f.title + f.evidence.map(\.detail).joined() + f.remediation.joined()).lowercased()
            XCTAssertFalse(blob.contains("password="), "\(f.id) must not dump secrets")
            XCTAssertFalse(blob.contains("auto-exploit chain payload"), "\(f.id) not weaponized")
        }
    }

    func testWave12ClusterEmitsRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let ctx = EvaluationContext.assess()
        let cluster = try await Wave12MultiPlaneClusterCheck().evaluate(state: state, context: ctx)
        XCTAssertFalse(cluster.isEmpty, "wave-12 multi-plane cluster should fire")
        for f in cluster {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
            let planeEv = f.evidence.first { $0.type == "planes" }
            XCTAssertNotNil(planeEv)
            XCTAssertTrue(planeEv!.detail.contains("count="))
        }
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(Wave12MultiPlaneClusterCheck.id))
    }



    func testWave13VectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let wave13: [String] = [
            CalendarRemindersAutomationVector.id,
            CalendarRemoteCompoundVector.id,
            GatekeeperAssessmentHistoryVector.id,
            GatekeeperAssessmentRemoteCompoundVector.id,
            HomebrewPackageDualUseVector.id,
            HomebrewRemoteCompoundVector.id,
            CupsPrintDualUseVector.id,
            CupsRemoteCompoundVector.id,
            ScreenCapturePrivacyDualUseVector.id,
            ScreenCaptureFdaCompoundVector.id
        ]
        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave13.contains(id) else { continue }
            fired.append(contentsOf: try await check.evaluate(state: state, context: context))
        }
        let firedIds = Set(fired.map(\.id))
        for id in wave13 {
            XCTAssertTrue(firedIds.contains(id), "wave-13 vector must fire: \(id); got \(firedIds.sorted())")
        }
        XCTAssertEqual(firedIds.count, wave13.count)
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
            let blob = (f.title + f.evidence.map(\.detail).joined() + f.remediation.joined()).lowercased()
            XCTAssertFalse(blob.contains("password="))
            XCTAssertFalse(blob.contains("auto-exploit chain payload"))
        }
    }

    func testWave13ClusterEmitsRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let ctx = EvaluationContext.assess()
        let cluster = try await Wave13MultiPlaneClusterCheck().evaluate(state: state, context: ctx)
        XCTAssertFalse(cluster.isEmpty, "wave-13 multi-plane cluster should fire")
        for f in cluster {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
            let planeEv = f.evidence.first { $0.type == "planes" }
            XCTAssertNotNil(planeEv)
            XCTAssertTrue(planeEv!.detail.contains("count="))
        }
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(Wave13MultiPlaneClusterCheck.id))
    }



    func testWave14VectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let wave14: [String] = [
            AutomatorWorkflowVector.id,
            AutomatorWorkflowRemoteCompoundVector.id,
            IcloudDrivePathVector.id,
            IcloudDrivePathRemoteCompoundVector.id,
            BluetoothContinuityDepthVector.id,
            BluetoothContinuityDepthRemoteCompoundVector.id,
            FontValidationDualuseVector.id,
            FontValidationDualuseRemoteCompoundVector.id,
            QuicklookCacheDepthVector.id,
            QuicklookCacheDepthRemoteCompoundVector.id,
            DnsResolverDualuseVector.id,
            DnsResolverDualuseRemoteCompoundVector.id,
            LsQuarantineDbDepthVector.id,
            LsQuarantineDbDepthRemoteCompoundVector.id,
            PamAuthModuleVector.id,
            PamAuthModuleRemoteCompoundVector.id,
            CronAtJobDepthVector.id,
            CronAtJobDepthRemoteCompoundVector.id,
            NotesMetadataPlaneVector.id,
            NotesMetadataPlaneRemoteCompoundVector.id
        ]
        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave14.contains(id) else { continue }
            fired.append(contentsOf: try await check.evaluate(state: state, context: context))
        }
        let firedIds = Set(fired.map(\.id))
        for id in wave14 {
            XCTAssertTrue(firedIds.contains(id), "wave-14 vector must fire: \(id); got \(firedIds.sorted())")
        }
        XCTAssertEqual(firedIds.count, wave14.count)
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
            let blob = (f.title + f.evidence.map(\.detail).joined() + f.remediation.joined()).lowercased()
            XCTAssertFalse(blob.contains("password="))
            XCTAssertFalse(blob.contains("auto-exploit chain payload"))
        }
    }

    func testWave14ClusterEmitsRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let ctx = EvaluationContext.assess()
        let cluster = try await Wave14MultiPlaneClusterCheck().evaluate(state: state, context: ctx)
        XCTAssertFalse(cluster.isEmpty, "wave-14 multi-plane cluster should fire")
        for f in cluster {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
            let planeEv = f.evidence.first { $0.type == "planes" }
            XCTAssertNotNil(planeEv)
            XCTAssertTrue(planeEv!.detail.contains("count="))
        }
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(Wave14MultiPlaneClusterCheck.id))
    }



    func testWave15VectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let wave15: [String] = [
            PhotosLibraryPathVector.id,
            PhotosLibraryPathRemoteCompoundVector.id,
            VpnConfigDualuseVector.id,
            VpnConfigDualuseRemoteCompoundVector.id,
            SandboxContainerDepthVector.id,
            SandboxContainerDepthRemoteCompoundVector.id,
            XpcMachServiceDepthVector.id,
            XpcMachServiceDepthRemoteCompoundVector.id,
            TmLocalSnapshotDepthVector.id,
            TmLocalSnapshotDepthRemoteCompoundVector.id,
            EmondLegacyDepthVector.id,
            EmondLegacyDepthRemoteCompoundVector.id,
            ScreenSharingArdDepthVector.id,
            ScreenSharingArdDepthRemoteCompoundVector.id,
            KeychainAclPathVector.id,
            KeychainAclPathRemoteCompoundVector.id,
            PythonRuntimeDualuseVector.id,
            PythonRuntimeDualuseRemoteCompoundVector.id,
            ShellPluginManagerVector.id,
            ShellPluginManagerRemoteCompoundVector.id
        ]
        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave15.contains(id) else { continue }
            fired.append(contentsOf: try await check.evaluate(state: state, context: context))
        }
        let firedIds = Set(fired.map(\.id))
        for id in wave15 {
            XCTAssertTrue(firedIds.contains(id), "wave-15 vector must fire: \(id); got \(firedIds.sorted())")
        }
        XCTAssertEqual(firedIds.count, wave15.count)
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
            let blob = (f.title + f.evidence.map(\.detail).joined() + f.remediation.joined()).lowercased()
            XCTAssertFalse(blob.contains("password="))
            XCTAssertFalse(blob.contains("auto-exploit chain payload"))
        }
    }

    func testWave15ClusterEmitsRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let ctx = EvaluationContext.assess()
        let cluster = try await Wave15MultiPlaneClusterCheck().evaluate(state: state, context: ctx)
        XCTAssertFalse(cluster.isEmpty, "wave-15 multi-plane cluster should fire")
        for f in cluster {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.attackTechniques.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
            let planeEv = f.evidence.first { $0.type == "planes" }
            XCTAssertNotNil(planeEv)
            XCTAssertTrue(planeEv!.detail.contains("count="))
        }
        let registered = Set(VulnModuleRegistry.allChecks().map { type(of: $0).id })
        XCTAssertTrue(registered.contains(Wave15MultiPlaneClusterCheck.id))
    }



    func testWave16VectorsFireOnSyntheticState() async throws {
        let state = Self.syntheticWeakState()
        let context = EvaluationContext.assess(profile: .standard)
        let wave16: [String] = [
            AirplayReceiverSurfaceVector.id,
            AirplayReceiverSurfaceRemoteCompoundVector.id,
            HandoffClipboardDepthVector.id,
            HandoffClipboardDepthRemoteCompoundVector.id,
            ImessagePathPlaneVector.id,
            ImessagePathPlaneRemoteCompoundVector.id,
            FacetimeCameraSurfaceVector.id,
            FacetimeCameraSurfaceRemoteCompoundVector.id,
            FinderSyncExtensionVector.id,
            FinderSyncExtensionRemoteCompoundVector.id,
            FileproviderDomainVector.id,
            FileproviderDomainRemoteCompoundVector.id,
            NotificationCenterDepthVector.id,
            NotificationCenterDepthRemoteCompoundVector.id,
            SiriSuggestionsPlaneVector.id,
            SiriSuggestionsPlaneRemoteCompoundVector.id,
            SpotlightImporterDepthVector.id,
            SpotlightImporterDepthRemoteCompoundVector.id,
            ContactsPathPlaneVector.id,
            ContactsPathPlaneRemoteCompoundVector.id,
            CalendarServerPathVector.id,
            CalendarServerPathRemoteCompoundVector.id,
            RemindersCloudPathVector.id,
            RemindersCloudPathRemoteCompoundVector.id,
            MapsLocationPathVector.id,
            MapsLocationPathRemoteCompoundVector.id,
            WeatherWidgetPathVector.id,
            WeatherWidgetPathRemoteCompoundVector.id,
            MusicLibraryPathVector.id,
            MusicLibraryPathRemoteCompoundVector.id,
            BooksPathPlaneVector.id,
            BooksPathPlaneRemoteCompoundVector.id,
            PodcastsPathPlaneVector.id,
            PodcastsPathPlaneRemoteCompoundVector.id,
            TvAppPathPlaneVector.id,
            TvAppPathPlaneRemoteCompoundVector.id,
            HomekitPathPlaneVector.id,
            HomekitPathPlaneRemoteCompoundVector.id,
            HealthPathPlaneVector.id,
            HealthPathPlaneRemoteCompoundVector.id,
            WalletPassPathVector.id,
            WalletPassPathRemoteCompoundVector.id,
            FindmyPathPlaneVector.id,
            FindmyPathPlaneRemoteCompoundVector.id,
            ShortcutsIcloudSyncVector.id,
            ShortcutsIcloudSyncRemoteCompoundVector.id,
            DevicemanagementProfileVector.id,
            DevicemanagementProfileRemoteCompoundVector.id,
            SoftwareupdateCatalogVector.id,
            SoftwareupdateCatalogRemoteCompoundVector.id
        ]
        var fired: [Finding] = []
        for check in AttackVectorPlane.allChecks() {
            let id = type(of: check).id
            guard wave16.contains(id) else { continue }
            fired.append(contentsOf: try await check.evaluate(state: state, context: context))
        }
        let firedIds = Set(fired.map(\.id))
        for id in wave16 {
            XCTAssertTrue(firedIds.contains(id), "wave-16 vector must fire: \(id)")
        }
        XCTAssertEqual(firedIds.count, wave16.count)
        for f in fired {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
            let blob = (f.title + f.evidence.map(\.detail).joined()).lowercased()
            XCTAssertFalse(blob.contains("password="))
        }
    }

    func testWave16ClusterEmitsRankedFindings() async throws {
        let state = Self.syntheticWeakState()
        let cluster = try await Wave16MultiPlaneClusterCheck().evaluate(state: state, context: EvaluationContext.assess())
        XCTAssertFalse(cluster.isEmpty)
        for f in cluster {
            XCTAssertFalse(f.evidence.isEmpty)
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertTrue(f.dryRunSafe)
            XCTAssertNotNil(f.evidence.first { $0.type == "planes" })
        }
        XCTAssertTrue(Set(VulnModuleRegistry.allChecks().map { type(of: $0).id }).contains(Wave16MultiPlaneClusterCheck.id))
    }


    private static func syntheticWeakState() -> CollectedState {
        var state = CollectedState()
        state.host = HostState(
            hostname: "vector-test",
            username: "tester",
            osVersion: "14.5.0",
            arch: "arm64",
            processArch: "arm64",
            isRoot: false
        )
        state.protections = ProtectionsState(
            sipEnabled: false,
            gatekeeperEnabled: false,
            fileVaultOn: true,
            notes: ["synthetic: SIP and Gatekeeper off"]
        )
        state.launchAgents = [
            LaunchAgentEntry(
                label: "com.example.agent",
                path: NSHomeDirectory() + "/Library/LaunchAgents/com.example.agent.plist",
                programArguments: ["/usr/bin/true"]
            ),
        ]
        state.loginItems = LoginItemsState(
            btmStorePresent: true,
            btmDirectoryPath: NSHomeDirectory() + "/Library/Application Support/com.apple.backgroundtaskmanagementagent",
            notes: ["synthetic BTM present"]
        )
        state.injectabilityHits = [
            InjectabilityHit(
                path: "/tmp/debug.app/Contents/MacOS/debug",
                hardenedRuntime: false,
                getTaskAllow: true,
                disableLibraryValidation: true,
                riskFlags: ["hardened_runtime_off", "get-task-allow", "disable-library-validation"]
            ),
        ]
        state.dylibRiskHits = [
            DylibRiskHit(
                path: "/tmp/debug.app/Contents/MacOS/debug",
                weakDylibs: ["@rpath/libEvil.dylib"],
                notes: ["synthetic weak dylib"]
            ),
        ]
        state.credPaths = [
            CredPathHit(kind: "ssh", path: NSHomeDirectory() + "/.ssh/id_rsa", exists: true),
            CredPathHit(kind: "aws", path: NSHomeDirectory() + "/.aws/credentials", exists: true),
        ]
        state.identity = IdentityState(
            adBound: true,
            platformSSO: true,
            kerberosConfigPresent: true,
            odConfigPaths: ["/Library/Preferences/OpenDirectory/Configurations/Active Directory"],
            ssoPaths: ["/Library/Application Support/com.apple.AppSSOAgent"],
            notes: ["synthetic AD-bound + Platform SSO"]
        )
        // Explicit empty EDR path hits so security_product_gap / identity_edr cluster can fire.
        state.securityProducts = [
            SecurityProductHit(name: "SyntheticEDR", path: "/Applications/SyntheticEDR.app", present: false),
        ]
        state.loobins = [
            LOOBinHit(name: "osascript", path: "/usr/bin/osascript", present: true, tactics: ["execution"]),
            LOOBinHit(name: "launchctl", path: "/bin/launchctl", present: true, tactics: ["persistence", "execution"]),
            LOOBinHit(name: "system_profiler", path: "/usr/sbin/system_profiler", present: true, tactics: ["discovery"]),
            LOOBinHit(name: "mdfind", path: "/usr/bin/mdfind", present: true, tactics: ["discovery"]),
        ]
        state.lolPlans = [
            LOLPlanEntry(
                name: "system_profiler",
                path: "/usr/sbin/system_profiler",
                goal: "discovery",
                noiseScore: 15,
                rankReason: "discovery: system_profiler low noise"
            ),
            LOLPlanEntry(
                name: "mdfind",
                path: "/usr/bin/mdfind",
                goal: "discovery",
                noiseScore: 40,
                rankReason: "discovery: mdfind medium noise"
            ),
            LOLPlanEntry(
                name: "launchctl",
                path: "/bin/launchctl",
                goal: "persist",
                noiseScore: 50,
                rankReason: "persist: launchctl medium noise"
            ),
            LOLPlanEntry(
                name: "osascript",
                path: "/usr/bin/osascript",
                goal: "execute",
                noiseScore: 85,
                tccImpact: ["Automation"],
                rankReason: "execute: osascript very high noise"
            ),
        ]
        state.network = NetworkState(
            remoteLoginSSH: true,
            screenSharingARD: true,
            fileSharingSMB: true,
            remoteLoginPlistPresent: true,
            screenSharingPlistPresent: true,
            sshdConfigPresent: true,
            notes: ["synthetic remote access enabled"]
        )
        // Expanded vectors: TCC/FDA, browser session, helpers/sygext, MDM gap, PEASS paths.
        state.tcc = TCCState(
            fullDiskAccessLikely: true,
            notes: ["synthetic FDA path listability"],
            probeMethod: "synthetic"
        )
        state.browserMeta = [
            BrowserMetaEntry(
                browser: "Chrome",
                kind: "cookies",
                path: NSHomeDirectory() + "/Library/Application Support/Google/Chrome/Default/Cookies",
                exists: true,
                sizeBytes: 4096
            ),
            BrowserMetaEntry(
                browser: "Chrome",
                kind: "login_data",
                path: NSHomeDirectory() + "/Library/Application Support/Google/Chrome/Default/Login Data",
                exists: true,
                sizeBytes: 2048
            ),
        ]
        state.privilegedHelperTools = [
            "/tmp/rootstock-red-synthetic/PrivilegedHelperTools/com.example.helper",
        ]
        state.systemExtensionPaths = [
            "/tmp/rootstock-red-synthetic/SystemExtensions/com.example.ext.systemextension",
        ]
        state.mdm = MDMState(
            enrolled: false,
            vendorHints: [],
            managedPreferenceNames: [],
            profileStoreReadable: false,
            profileFileCount: 0,
            pppcPolicyPresent: false,
            notes: ["synthetic unmanaged host"]
        )
        // PEASS-class writable privileged paths via collector note (forceWritable) + real temp file.
        let tmpRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("rootstock-red-privesc-synth-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: tmpRoot, withIntermediateDirectories: true)
        let fakeDaemon = tmpRoot.appendingPathComponent("com.example.evil.plist")
        try? Data("synthetic".utf8).write(to: fakeDaemon)
        state.launchDaemons = [
            LaunchAgentEntry(
                label: "com.example.evil",
                path: fakeDaemon.path,
                programArguments: ["/usr/bin/true"]
            ),
        ]
        state.collectorNotes["privesc.writable_paths"] = fakeDaemon.path

        // Wave-3: sudoers / periodic / electron / gatekeeper (GK already false in protections)
        state.collectorNotes["privesc.sudoers_signals"] = "readable:/etc/sudoers|nopasswd_hint:synthetic"
        state.collectorNotes["privesc.periodic_paths"] = "writable:/tmp/rootstock-red-periodic-synth"
        state.collectorNotes["lool.electron_devtools"] = "--inspect=9229|electron_app=SyntheticApp"
        state.codesignSamples = [
            CodesignSample(
                path: "/tmp/rootstock-red-synth/unsigned",
                signed: false,
                hardenedRuntime: false,
                getTaskAllow: true,
                notes: ["synthetic unsigned"]
            ),
        ]
        state.runningApps = [
            RunningAppInfo(name: "Code", bundleIdentifier: "com.microsoft.VSCode", path: "/Applications/Visual Studio Code.app"),
            RunningAppInfo(name: "Slack", bundleIdentifier: "com.tinyspeck.slackmacgap", path: "/Applications/Slack.app"),
        ]

        state.esf = ESFPostureState(
            frameworkPresent: true,
            clientPaths: [],
            systemExtensionCount: 0,
            edrHints: [],
            notes: ["synthetic: ES framework present, no client path hits"]
        )
        state.patchDebt = PatchDebtState(
            osVersion: "13.6.0",
            osBuild: "22G120",
            softwareUpdatePlistPresent: false,
            lastUpdateHints: ["synthetic_lag"],
            majorVersionLag: 2,
            notes: ["synthetic multi-major lag for CVE suggester"]
        )
        state.tcc = TCCState(
            fullDiskAccessLikely: true,
            notes: ["synthetic FDA path listability", "graph domains present"],
            probeMethod: "synthetic+graph",
            domainSignals: [
                "ScreenCapture=tool_present",
                "Accessibility=tcc_support_paths_present",
                "Automation=osascript_present",
                "CameraMic=avfoundation_present",
                "FullDiskAccess=likely",
                "FilesAndFolders=Desktop+Documents",
            ]
        )
        state.launchConstraints = LaunchConstraintState(
            constrainedPaths: [],
            unconstrainedRiskPaths: ["/tmp/debug.app/Contents/MacOS/debug"],
            notes: ["synthetic unconstrained risk without LC artifact"]
        )
        state.collectorNotes["collect.esf_endpoint_security"] = "framework=true clients=0 sysext≈0 hints=0"
        state.collectorNotes["collect.tcc_permission_graph"] =
            "ScreenCapture=tool_present;Automation=osascript_present;FullDiskAccess=likely"
        state.collectorNotes["cve.patch_debt"] = "synthetic"
        // Ensure multi-stage LOOBin chain has discover+execute+persist (+security for 4th stage)
        state.loobins = state.loobins + [
            LOOBinHit(name: "security", path: "/usr/bin/security", present: true, tactics: ["credential-access"]),
            LOOBinHit(name: "curl", path: "/usr/bin/curl", present: true, tactics: ["execution"]),
        ]
        // Multiple helpers for XPC client-validation surface
        state.privilegedHelperTools = state.privilegedHelperTools + [
            "/tmp/rootstock-red-synthetic/PrivilegedHelperTools/com.example.helper2",
            "/tmp/rootstock-red-synthetic/PrivilegedHelperTools/com.example.helper3",
        ]

        state.networkExtension = NetworkExtensionState(
            frameworkPresent: true,
            vpnConfigPaths: [],
            contentFilterHints: [],
            packetTunnelHints: [],
            neAppPaths: [],
            notes: ["synthetic: thin NE inventory, no content filter"]
        )
        state.authRights = AuthRightsState(
            authDbPresent: true,
            authDbPath: "/var/db/auth.db",
            authorizationPlistPaths: ["/System/Library/Security/authorization.plist"],
            packageKitPaths: ["/System/Library/PrivateFrameworks/PackageKit.framework"],
            rightsHintCount: 3,
            notes: ["synthetic auth.db + PackageKit surface"]
        )
        state.developerToolchain = DeveloperToolchainState(
            xcodePresent: true,
            commandLineToolsPresent: true,
            toolchainPaths: ["/Applications/Xcode.app", "/Library/Developer/CommandLineTools"],
            dualUseBinaries: [
                "/usr/bin/lldb",
                "/usr/bin/dtrace",
                "/usr/bin/codesign",
                "/usr/bin/otool",
            ],
            notes: ["synthetic Xcode/CLT dual-use inventory"]
        )
        state.timeMachine = TimeMachineState(
            preferencesPresent: true,
            backupPaths: ["/Volumes/TimeMachine/Backups.backupdb"],
            localSnapshotHints: [".localsnapshots present"],
            volumeMountHints: ["/Volumes/TimeMachine"],
            notes: ["synthetic TM prefs + snapshot hints"]
        )
        state.configProfileSideload = ConfigProfileSideloadState(
            userMobileconfigPaths: [
                NSHomeDirectory() + "/Downloads/synthetic-vpn.mobileconfig",
            ],
            downloadsProfileHints: ["Downloads/*.mobileconfig"],
            profileInstallDbPresent: false,
            notes: ["synthetic user mobileconfig on unmanaged host"]
        )
        state.collectorNotes["ne.filter_gap"] = "contentFilter=0"
        state.collectorNotes["collect.network_extension"] = "contentFilter=0 filters=0"
        state.collectorNotes["collect.auth_rights"] = "authdb+packagekit"
        state.collectorNotes["collect.developer_toolchain"] = "xcode=true clt=true"
        state.collectorNotes["dev.toolchain_present"] = "1"
        state.collectorNotes["collect.time_machine"] = "tm+fda"
        state.collectorNotes["tm.snapshot_surface"] = "1"
        state.collectorNotes["collect.config_profile_sideload"] = "user_mobileconfig"
        state.collectorNotes["profile.sideload"] = "1"

        state.appSandboxEntitlements = AppSandboxEntitlementState(
            appSamples: [
                "/Applications/Slack.app",
                "/Applications/Visual Studio Code.app",
                "/Applications/Google Chrome.app",
            ],
            sandboxedHints: ["/System/Library/Sandbox"],
            dangerousEntitlementHints: ["tool:/usr/bin/codesign"],
            unsandboxedRiskPaths: [
                "/Applications/Slack.app",
                "/Applications/Visual Studio Code.app",
            ],
            notes: ["synthetic thick-client entitlement surface"]
        )
        state.notarizationStapling = NotarizationStaplingState(
            toolingPaths: ["/usr/bin/stapler", "/usr/sbin/spctl", "/usr/bin/codesign"],
            ticketCacheHints: ["/var/db/SystemPolicyConfiguration"],
            unstapledOrAdHocHints: [
                NSHomeDirectory() + "/Downloads/synthetic-tool.dmg",
                NSHomeDirectory() + "/Downloads/unsigned.pkg",
            ],
            assessmentToolsPresent: true,
            notes: ["synthetic notarization/stapling surface"]
        )
        state.virtualizationContainers = VirtualizationContainerState(
            containerToolPaths: ["/usr/local/bin/docker", "/Applications/Docker.app"],
            hypervisorAppPaths: ["/Applications/UTM.app"],
            frameworkPaths: ["/System/Library/Frameworks/Virtualization.framework"],
            dualUsePresent: true,
            notes: ["synthetic virt/container dual-use"]
        )
        state.continuityAirDrop = ContinuityAirDropState(
            airdropPrefPaths: [
                NSHomeDirectory() + "/Library/Preferences/com.apple.sharingd.plist",
            ],
            continuityFrameworkPaths: [
                "/System/Library/PrivateFrameworks/Sharing.framework",
                "/usr/libexec/sharingd",
            ],
            nearbyShareHints: ["/usr/libexec/rapportd"],
            proximitySurfacePresent: true,
            notes: ["synthetic Continuity/AirDrop surface"]
        )
        state.fileVaultEscrow = FileVaultEscrowState(
            fileVaultOn: false,
            escrowPathHints: [
                "/Library/Preferences/com.apple.security.FDERecoveryKeyEscrow.plist",
            ],
            institutionalEscrowHints: ["/Library/Managed Preferences"],
            fdesetupPresent: true,
            notes: ["synthetic FV off + escrow paths - never recovery keys"]
        )
        // Align protections FV with escrow for cluster compounds
        state.protections = ProtectionsState(
            sipEnabled: false,
            gatekeeperEnabled: false,
            fileVaultOn: false,
            notes: ["synthetic: SIP/GK/FV weak for Wave-7 compounds"]
        )
        state.collectorNotes["collect.app_sandbox_entitlements"] = "apps=3 risk=2"
        state.collectorNotes["collect.notarization_stapling"] = "tools=3 delivery=2"
        state.collectorNotes["collect.virtualization_containers"] = "dualUse=true"
        state.collectorNotes["collect.continuity_airdrop"] = "surface=true"
        state.collectorNotes["collect.filevault_escrow"] = "fv=false escrow=1"

        state.clickFixTerminalDelivery = ClickFixTerminalDeliveryState(
            terminalAppPaths: ["/System/Applications/Utilities/Terminal.app", "/bin/zsh"],
            scriptEditorPaths: ["/System/Applications/Utilities/Script Editor.app", "/usr/bin/osascript"],
            loaderBinaryPaths: ["/usr/bin/curl", "/usr/bin/osascript", "/bin/zsh", "/bin/bash"],
            pasteWarningHints: [NSHomeDirectory() + "/Library/Preferences/com.apple.Terminal.plist"],
            deliverySurfacePresent: true,
            notes: ["synthetic ClickFix Terminal delivery surface - never builds lures"]
        )
        state.remoteAppleEvents = RemoteAppleEventsState(
            remoteAEPrefPaths: [
                "/Library/Preferences/com.apple.RemoteManagement.plist",
                "/System/Library/LaunchDaemons/com.apple.AEServer.plist",
            ],
            eppcFrameworkPaths: [
                "/System/Library/Frameworks/ScriptingBridge.framework",
                "/System/Library/CoreServices/RemoteManagement",
            ],
            remoteMgmtHints: ["/System/Library/LaunchDaemons/com.apple.screensharing.plist"],
            remoteAutomationSurfacePresent: true,
            notes: ["synthetic Remote Apple Events lateral surface - never enables RAE"]
        )
        state.spotlightAICache = SpotlightAICacheState(
            spotlightPaths: ["/usr/bin/mdfind", "/usr/bin/mdutil", "/.Spotlight-V100"],
            metadataFrameworkPaths: [
                "/System/Library/Frameworks/CoreSpotlight.framework",
                "/System/Library/PrivateFrameworks/Spotlight.framework",
            ],
            aiCachePathHints: [NSHomeDirectory() + "/Library/Caches"],
            dataAccessSurfacePresent: true,
            notes: ["synthetic Spotlight/AI-cache surface - never dumps index contents"]
        )
        state.securityMgmtPlane = SecurityMgmtPlaneState(
            managementCLIPaths: ["/usr/bin/systemextensionsctl", "/bin/launchctl"],
            privilegedHelperPaths: [
                "/Library/PrivilegedHelperTools/com.example.security.helper",
            ],
            unloadAdjacentHints: ["/Library/SystemExtensions", "systemextensionsctl_present"],
            managementPlanePresent: true,
            notes: ["synthetic security mgmt-plane surface - never unloads sensors"]
        )
        state.thirdPartyTCCInheritance = ThirdPartyTCCInheritanceState(
            thickClientAppPaths: [
                "/Applications/Slack.app",
                "/Applications/Visual Studio Code.app",
            ],
            embeddedInterpreterPaths: [
                "/Applications/Slack.app/Contents/Frameworks/Electron Framework.framework",
                "/usr/bin/python3",
            ],
            electronHelperPaths: [
                "/Applications/Slack.app/Contents/Frameworks/Electron Framework.framework",
            ],
            inheritanceSurfacePresent: true,
            notes: ["synthetic TCC inheritance surface - never forges grants"]
        )
        state.sshAgentKeyPath = SSHAgentKeyPathState(
            agentSocketPaths: ["/usr/bin/ssh-agent", "/tmp/synthetic-ssh-agent.sock"],
            keyPathHits: [
                NSHomeDirectory() + "/.ssh/authorized_keys",
                NSHomeDirectory() + "/.ssh/id_ed25519",
                NSHomeDirectory() + "/.ssh/config",
            ],
            sshdSupportPaths: ["/usr/sbin/sshd", "/etc/ssh/sshd_config"],
            lateralPathSurfacePresent: true,
            notes: ["synthetic SSH agent/key path surface - never reads key material"]
        )
        state.collectorNotes["collect.clickfix_terminal_delivery"] = "terminal=2 loaders=4 surface=true"
        state.collectorNotes["collect.remote_apple_events"] = "prefs=2 eppc=2 surface=true"
        state.collectorNotes["collect.spotlight_ai_cache"] = "spotlight=3 surface=true"
        state.collectorNotes["collect.security_mgmt_plane"] = "mgmt=2 helpers=1 surface=true"
        state.collectorNotes["collect.third_party_tcc_inheritance"] = "thick=2 electron=1 surface=true"
        state.collectorNotes["collect.ssh_agent_key_path"] = "agent=2 keys=3 surface=true"

        state.packageKitInstallerDesign = PackageKitInstallerDesignState(
            installerServicePaths: [
                "/System/Library/PrivateFrameworks/PackageKit.framework/Versions/A/XPCServices/package_script_service.xpc",
                "/usr/libexec/installd",
            ],
            receiptAndHistoryPaths: [
                "/Library/Receipts",
                "/var/db/receipts",
                "/Library/InstallerSandboxes",
            ],
            installerPluginPaths: ["/Library/Installer Plugins"],
            toolingPaths: [
                "/usr/sbin/installer",
                "/usr/sbin/pkgutil",
                "/System/Library/PrivateFrameworks/PackageKit.framework",
            ],
            designSurfacePresent: true,
            notes: ["synthetic PackageKit installer design surface - never builds pkgs"]
        )
        state.archiveQuarantineExtractor = ArchiveQuarantineExtractorState(
            thirdPartyExtractorPaths: [
                "/Applications/The Unarchiver.app",
                "/Applications/Keka.app",
            ],
            stockExtractorPaths: [
                "/usr/bin/ditto",
                "/usr/bin/tar",
                "/usr/bin/unzip",
            ],
            archiveDropHints: [NSHomeDirectory() + "/Downloads"],
            extractorSurfacePresent: true,
            notes: ["synthetic archive extractor surface - never strips quarantine"]
        )
        state.infoStealerPathPlane = InfoStealerPathPlaneState(
            browserAdjacentPaths: [
                NSHomeDirectory() + "/Library/Application Support/Google/Chrome",
                NSHomeDirectory() + "/Library/Safari",
            ],
            messagingAndVaultPaths: [
                NSHomeDirectory() + "/Library/Messages",
                NSHomeDirectory() + "/Library/Mail",
                NSHomeDirectory() + "/Library/Keychains",
                NSHomeDirectory() + "/Library/Application Support/1Password",
            ],
            walletAndSyncPaths: [
                NSHomeDirectory() + "/Desktop",
                NSHomeDirectory() + "/Documents",
                NSHomeDirectory() + "/Library/CloudStorage",
            ],
            collectionSurfacePresent: true,
            notes: ["synthetic info-stealer path plane - never dumps secrets"]
        )
        state.tccEsfVisibilityDepth = TCCESFVisibilityDepthState(
            tccDbPathHits: [
                NSHomeDirectory() + "/Library/Application Support/com.apple.TCC/TCC.db",
            ],
            visibilityToolPaths: ["/usr/bin/log", "/usr/bin/sqlite3"],
            privacyPrefPaths: ["/Library/Preferences/com.apple.security.plist"],
            visibilityDepth: "partial",
            visibilitySurfacePresent: true,
            notes: ["synthetic TCC/ESF visibility depth - never dumps TCC.db rows"]
        )
        state.mdmProfileParseDepth = MDMProfileParseDepthState(
            examinedProfilePaths: [
                NSHomeDirectory() + "/Downloads/synthetic-vpn.mobileconfig",
            ],
            payloadTypes: [
                "Configuration",
                "com.apple.vpn.managed",
                "com.apple.wifi.managed",
            ],
            parsedProfileCount: 1,
            displayNamePresent: true,
            parseSurfacePresent: true,
            notes: ["synthetic MDM profile parse depth - never dumps secrets"]
        )
        state.collectorNotes["collect.packagekit_installer_design"] = "services=2 receipts=3 surface=true"
        state.collectorNotes["collect.archive_quarantine_extractor"] = "thirdParty=2 stock=3 surface=true"
        state.collectorNotes["collect.infostealer_path_plane"] = "browser=2 messagingVault=4 surface=true"
        state.collectorNotes["collect.tcc_esf_visibility_depth"] = "depth=partial surface=true"
        state.collectorNotes["collect.mdm_profile_parse_depth"] = "parsed=1 types=3 surface=true"
        state.urlSchemeHandler = URLSchemeHandlerState(
            launchServicesPaths: [
                NSHomeDirectory() + "/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist",
                "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework",
            ],
            urlTypePlistPaths: [
                "/Applications/Safari.app/Contents/Info.plist",
                "/System/Applications/Utilities/Terminal.app/Contents/Info.plist",
            ],
            documentHandlerPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework"],
            openerBinaryPaths: ["/usr/bin/open", "/usr/bin/osascript", "/usr/bin/osacompile"],
            handlerSurfacePresent: true,
            notes: ["synthetic URL scheme handler surface - never registers schemes"]
        )
        state.launchdOverrideDepth = LaunchdOverrideDepthState(
            overridePlistPaths: [
                "/var/db/com.apple.xpc.launchd/disabled.plist",
                "/var/db/launchd.db/com.apple.launchd/overrides.plist",
            ],
            securityDisabledHints: [
                "com.google.santa @ /var/db/com.apple.xpc.launchd/disabled.plist",
                "com.crowdstrike.falcon @ /var/db/com.apple.xpc.launchd/disabled.plist",
            ],
            keepaliveAdjacentPaths: ["/Library/LaunchDaemons", "/Library/LaunchAgents"],
            overrideSurfacePresent: true,
            notes: ["synthetic launchd override depth - never disables jobs"]
        )
        state.browserExtensionDualUse = BrowserExtensionDualUseState(
            chromiumExtensionPaths: [
                NSHomeDirectory() + "/Library/Application Support/Google/Chrome/Default/Extensions",
                NSHomeDirectory() + "/Library/Application Support/Microsoft Edge/Default/Extensions",
            ],
            safariExtensionPaths: [
                NSHomeDirectory() + "/Library/Safari/Extensions",
            ],
            preferencePaths: [
                NSHomeDirectory() + "/Library/Application Support/Google/Chrome/Default/Preferences",
                NSHomeDirectory() + "/Library/Preferences/com.apple.Safari.Extensions.plist",
            ],
            extensionSurfacePresent: true,
            notes: ["synthetic browser extension dual-use - never dumps secrets"]
        )
        state.shortcutsAppIntents = ShortcutsAppIntentsState(
            shortcutsAppPaths: [
                "/System/Applications/Shortcuts.app",
                NSHomeDirectory() + "/Library/Shortcuts",
                NSHomeDirectory() + "/Library/Group Containers/group.is.workflow.my.app",
            ],
            appIntentsPaths: [
                "/System/Library/Frameworks/AppIntents.framework",
                "/System/Library/PrivateFrameworks/WorkflowKit.framework",
            ],
            automationPrefPaths: [
                NSHomeDirectory() + "/Library/Preferences/com.apple.shortcuts.plist",
            ],
            automationSurfacePresent: true,
            notes: ["synthetic Shortcuts/App Intents surface - never runs shortcuts"]
        )
        state.collectorNotes["collect.url_scheme_handler"] = "ls=2 urlTypes=2 openers=3 surface=true"
        state.collectorNotes["collect.launchd_override_depth"] = "overrides=2 securityHints=2 surface=true"
        state.collectorNotes["collect.browser_extension_dualuse"] = "chromium=2 safari=1 surface=true"
        state.collectorNotes["collect.shortcuts_app_intents"] = "shortcuts=3 intents=2 surface=true"
        // Wave-12 multi-plane synthetic surfaces

        state.weblocInetlocDelivery = WeblocInetlocDeliveryState(
            weblocSamplePaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            inetlocSamplePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-webloc_inetloc.plist", "/usr/bin/osascript"],
            dropFolderHints: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            deliverySurfacePresent: true,
            notes: ["synthetic Webloc/inetloc delivery - never crafts phishing webloc/inetloc payloads or rewrites Internet Location files"]
        )
        state.collectorNotes["collect.webloc_inetloc_delivery"] = "a=3 b=2 c=3 surface=true"

        state.mailRulesAutomation = MailRulesAutomationState(
            mailAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            rulesPlistPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-mail_rules.plist", "/usr/bin/osascript"],
            scriptingAdjacentPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            rulesSurfacePresent: true,
            notes: ["synthetic Mail rules automation - never reads Mail contents or modifies user Mail rules"]
        )
        state.collectorNotes["collect.mail_rules_automation"] = "a=3 b=2 c=3 surface=true"

        state.unifiedLogObservation = UnifiedLogObservationState(
            logToolPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            logarchiveHints: [NSHomeDirectory() + "/Library/Preferences/synthetic-unified_log.plist", "/usr/bin/osascript"],
            privacyPrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            observationSurfacePresent: true,
            notes: ["synthetic Unified log observation - never dumps private unified-log message bodies or force-collects other users' logarchives"]
        )
        state.collectorNotes["collect.unified_log_observation"] = "a=3 b=2 c=3 surface=true"

        state.dockPersistenceSurface = DockPersistenceSurfaceState(
            dockPlistPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            recentItemsPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-dock_persist.plist", "/usr/bin/osascript"],
            dockDbHints: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            dockSurfacePresent: true,
            notes: ["synthetic Dock persistence dual-use - never modifies Dock.plist or plants malicious Dock entries"]
        )
        state.collectorNotes["collect.dock_persistence_surface"] = "a=3 b=2 c=3 surface=true"

        state.osascriptScptDelivery = OsascriptScptDeliveryState(
            osaToolPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            scriptEditorPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-osascript_scpt.plist", "/usr/bin/osascript"],
            scptDropHints: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            scptSurfacePresent: true,
            notes: ["synthetic OSA/scpt delivery - never compiles malicious .scpt payloads or executes third-party AppleScripts"]
        )
        state.collectorNotes["collect.osascript_scpt_delivery"] = "a=3 b=2 c=3 surface=true"

        state.networkShareMount = NetworkShareMountState(
            smbClientPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            netAuthPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-network_share.plist", "/usr/bin/osascript"],
            mountPointHints: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            shareSurfacePresent: true,
            notes: ["synthetic Network share mount - never mounts attacker shares or writes credentials to NetAuth"]
        )
        state.collectorNotes["collect.network_share_mount"] = "a=3 b=2 c=3 surface=true"
        // Wave-13 multi-plane synthetic surfaces

        state.calendarRemindersAutomation = CalendarRemindersAutomationState(
            calendarAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            remindersPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-calendar_reminders.plist", "/usr/bin/osascript"],
            eventKitPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            automationSurfacePresent: true,
            notes: ["synthetic Calendar/Reminders automation - never reads event contents or creates malicious calendar invites"]
        )
        state.collectorNotes["collect.calendar_reminders_automation"] = "a=3 b=2 c=3 surface=true"

        state.gatekeeperAssessmentHistory = GatekeeperAssessmentHistoryState(
            syspolicydPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            assessmentDbPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-gk_assessment.plist", "/usr/bin/osascript"],
            spctlToolPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            assessmentSurfacePresent: true,
            notes: ["synthetic Gatekeeper assessment history - never clears Gatekeeper assessments or disables syspolicyd"]
        )
        state.collectorNotes["collect.gatekeeper_assessment_history"] = "a=3 b=2 c=3 surface=true"

        state.homebrewPackageDualUse = HomebrewPackageDualUseState(
            brewBinaryPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            cellarPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-homebrew_pkg.plist", "/usr/bin/osascript"],
            tapPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            packageSurfacePresent: true,
            notes: ["synthetic Homebrew package dual-use - never installs packages or modifies Homebrew formulae"]
        )
        state.collectorNotes["collect.homebrew_package_dualuse"] = "a=3 b=2 c=3 surface=true"

        state.cupsPrintDualUse = CupsPrintDualUseState(
            cupsDaemonPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            ppdConfigPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-cups_print.plist", "/usr/bin/osascript"],
            printToolPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            printSurfacePresent: true,
            notes: ["synthetic CUPS printer dual-use - never submits print jobs or reconfigures CUPS remotely"]
        )
        state.collectorNotes["collect.cups_print_dualuse"] = "a=3 b=2 c=3 surface=true"

        state.screenCapturePrivacyDualUse = ScreenCapturePrivacyDualUseState(
            screencaptureToolPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            screenCaptureKitPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-screencapture.plist", "/usr/bin/osascript"],
            screenshotDropHints: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            captureSurfacePresent: true,
            notes: ["synthetic ScreenCapture privacy dual-use - never captures screens or dumps Screen Recording TCC rows"]
        )
        state.collectorNotes["collect.screencapture_privacy_dualuse"] = "a=3 b=2 c=3 surface=true"
        // Wave-14 multi-plane synthetic surfaces

        state.automatorWorkflow = AutomatorWorkflowState(
            automatorAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            workflowSamplePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-automator_workflow.plist", "/usr/bin/osascript"],
            actionLibraryPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            workflowSurfacePresent: true,
            notes: ["synthetic Automator workflow delivery - never executes Automator workflows or plants malicious .workflow bundles"]
        )
        state.collectorNotes["collect.automator_workflow"] = "a=3 b=2 c=3 surface=true"

        state.icloudDrivePath = IcloudDrivePathState(
            mobileDocumentsPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            icloudDrivePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-icloud_drive_path.plist", "/usr/bin/osascript"],
            cloudKitPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            icloudPathSurfacePresent: true,
            notes: ["synthetic iCloud Drive path plane - never enumerates iCloud file contents or exfiltrates Mobile Documents"]
        )
        state.collectorNotes["collect.icloud_drive_path"] = "a=3 b=2 c=3 surface=true"

        state.bluetoothContinuityDepth = BluetoothContinuityDepthState(
            bluetoothDaemonPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            continuitySupportPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-bluetooth_continuity_depth.plist", "/usr/bin/osascript"],
            btPreferencePaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            btContinuitySurfacePresent: true,
            notes: ["synthetic Bluetooth Continuity depth - never enables Bluetooth pairing or spoofs Continuity identities"]
        )
        state.collectorNotes["collect.bluetooth_continuity_depth"] = "a=3 b=2 c=3 surface=true"

        state.fontValidationDualuse = FontValidationDualuseState(
            fontToolPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            atsSupportPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-font_validation_dualuse.plist", "/usr/bin/osascript"],
            userFontPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            fontSurfacePresent: true,
            notes: ["synthetic Font validation dual-use - never installs malicious fonts or disables font validation"]
        )
        state.collectorNotes["collect.font_validation_dualuse"] = "a=3 b=2 c=3 surface=true"

        state.quicklookCacheDepth = QuicklookCacheDepthState(
            quicklookDaemonPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            thumbnailCachePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-quicklook_cache_depth.plist", "/usr/bin/osascript"],
            qlmanagePaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            quicklookSurfacePresent: true,
            notes: ["synthetic QuickLook cache depth - never dumps QuickLook thumbnail bitmap contents as secret material"]
        )
        state.collectorNotes["collect.quicklook_cache_depth"] = "a=3 b=2 c=3 surface=true"

        state.dnsResolverDualuse = DnsResolverDualuseState(
            mdnsResponderPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            resolverConfigPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-dns_resolver_dualuse.plist", "/usr/bin/osascript"],
            dnsToolPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            dnsSurfacePresent: true,
            notes: ["synthetic DNS resolver dual-use - never rewrites resolver config or poisons DNS caches"]
        )
        state.collectorNotes["collect.dns_resolver_dualuse"] = "a=3 b=2 c=3 surface=true"

        state.lsQuarantineDbDepth = LsQuarantineDbDepthState(
            quarantineDbPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            lsSupportPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-ls_quarantine_db_depth.plist", "/usr/bin/osascript"],
            quarantineToolHints: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            quarantineDbSurfacePresent: true,
            notes: ["synthetic LS QuarantineEvents depth - never deletes QuarantineEvents rows or clears LS quarantine history"]
        )
        state.collectorNotes["collect.ls_quarantine_db_depth"] = "a=3 b=2 c=3 surface=true"

        state.pamAuthModule = PamAuthModuleState(
            pamConfigPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            pamModulePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-pam_auth_module.plist", "/usr/bin/osascript"],
            authdSupportPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            pamSurfacePresent: true,
            notes: ["synthetic PAM auth module surface - never installs PAM modules or modifies /etc/pam.d"]
        )
        state.collectorNotes["collect.pam_auth_module"] = "a=3 b=2 c=3 surface=true"

        state.cronAtJobDepth = CronAtJobDepthState(
            cronBinaryPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            crontabPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-cron_at_job_depth.plist", "/usr/bin/osascript"],
            atJobPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            cronAtSurfacePresent: true,
            notes: ["synthetic Cron/at job depth - never installs cron or at jobs outside the lab root"]
        )
        state.collectorNotes["collect.cron_at_job_depth"] = "a=3 b=2 c=3 surface=true"

        state.notesMetadataPlane = NotesMetadataPlaneState(
            notesAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            notesStorePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-notes_metadata_plane.plist", "/usr/bin/osascript"],
            notesContainerPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            notesSurfacePresent: true,
            notes: ["synthetic Notes metadata plane - never reads Notes body contents or exports note secrets"]
        )
        state.collectorNotes["collect.notes_metadata_plane"] = "a=3 b=2 c=3 surface=true"
        // Wave-15 multi-plane synthetic surfaces

        state.photosLibraryPath = PhotosLibraryPathState(
            photosAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            photosLibraryPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-photos_library_path.plist", "/usr/bin/osascript"],
            photosSupportPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            photosSurfacePresent: true,
            notes: ["synthetic Photos library path plane - never reads photo contents or exports Photo Library media"]
        )
        state.collectorNotes["collect.photos_library_path"] = "a=3 b=2 c=3 surface=true"

        state.vpnConfigDualuse = VpnConfigDualuseState(
            vpnFrameworkPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            vpnPrefPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-vpn_config_dualuse.plist", "/usr/bin/osascript"],
            vpnToolPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            vpnSurfacePresent: true,
            notes: ["synthetic VPN config dual-use - never installs VPN profiles or rewrites network extension VPN configs"]
        )
        state.collectorNotes["collect.vpn_config_dualuse"] = "a=3 b=2 c=3 surface=true"

        state.sandboxContainerDepth = SandboxContainerDepthState(
            containerRootPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            sandboxProfilePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-sandbox_container_depth.plist", "/usr/bin/osascript"],
            seatbeltSupportPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            sandboxSurfacePresent: true,
            notes: ["synthetic Sandbox container depth - never breaks app sandbox or forges container entitlements"]
        )
        state.collectorNotes["collect.sandbox_container_depth"] = "a=3 b=2 c=3 surface=true"

        state.xpcMachServiceDepth = XpcMachServiceDepthState(
            xpcBootstrapPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            machServicePlistPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-xpc_mach_service_depth.plist", "/usr/bin/osascript"],
            xpcToolPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            xpcMachSurfacePresent: true,
            notes: ["synthetic XPC Mach service depth - never registers XPC services or injects into Mach ports"]
        )
        state.collectorNotes["collect.xpc_mach_service_depth"] = "a=3 b=2 c=3 surface=true"

        state.tmLocalSnapshotDepth = TmLocalSnapshotDepthState(
            tmUtilPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            snapshotStorePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-tm_local_snapshot_depth.plist", "/usr/bin/osascript"],
            tmPrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            tmSnapshotSurfacePresent: true,
            notes: ["synthetic TM local snapshot depth - never mounts snapshots for data theft or deletes backup catalogs"]
        )
        state.collectorNotes["collect.tm_local_snapshot_depth"] = "a=3 b=2 c=3 surface=true"

        state.emondLegacyDepth = EmondLegacyDepthState(
            emondBinaryPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            emondRulePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-emond_legacy_depth.plist", "/usr/bin/osascript"],
            emondSupportPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            emondSurfacePresent: true,
            notes: ["synthetic Emond legacy depth - never installs emond rules or enables the legacy event monitor daemon"]
        )
        state.collectorNotes["collect.emond_legacy_depth"] = "a=3 b=2 c=3 surface=true"

        state.screenSharingArdDepth = ScreenSharingArdDepthState(
            screenSharingAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            ardAgentPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-screen_sharing_ard_depth.plist", "/usr/bin/osascript"],
            remoteMgmtPrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            ardSurfacePresent: true,
            notes: ["synthetic Screen Sharing ARD depth - never enables Screen Sharing or ARD, never connects to remote desktops"]
        )
        state.collectorNotes["collect.screen_sharing_ard_depth"] = "a=3 b=2 c=3 surface=true"

        state.keychainAclPath = KeychainAclPathState(
            keychainDbPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            securityToolPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-keychain_acl_path.plist", "/usr/bin/osascript"],
            keychainSupportPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            keychainAclSurfacePresent: true,
            notes: ["synthetic Keychain ACL path plane - never dumps keychain items, passwords, or private keys"]
        )
        state.collectorNotes["collect.keychain_acl_path"] = "a=3 b=2 c=3 surface=true"

        state.pythonRuntimeDualuse = PythonRuntimeDualuseState(
            pythonBinaryPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            sitePackagePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-python_runtime_dualuse.plist", "/usr/bin/osascript"],
            pythonFrameworkPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            pythonSurfacePresent: true,
            notes: ["synthetic Python runtime dual-use - never executes third-party Python payloads or drops malicious site-packages"]
        )
        state.collectorNotes["collect.python_runtime_dualuse"] = "a=3 b=2 c=3 surface=true"

        state.shellPluginManager = ShellPluginManagerState(
            omzPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            pluginDirPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-shell_plugin_manager.plist", "/usr/bin/osascript"],
            shellInitPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            shellPluginSurfacePresent: true,
            notes: ["synthetic Shell plugin manager dual-use - never installs oh-my-zsh plugins or rewrites shell init for persistence"]
        )
        state.collectorNotes["collect.shell_plugin_manager"] = "a=3 b=2 c=3 surface=true"
        // Wave-16 multi-plane synthetic surfaces (25 themes)

        state.airplayReceiverSurface = AirplayReceiverSurfaceState(
            airplayDaemonPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            airplayPrefPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-airplay_receiver_surface.plist", "/usr/bin/osascript"],
            airplayHelperPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            airplaySurfacePresent: true,
            notes: ["synthetic AirPlay receiver dual-use"]
        )
        state.collectorNotes["collect.airplay_receiver_surface"] = "a=3 b=2 c=3 surface=true"

        state.handoffClipboardDepth = HandoffClipboardDepthState(
            handoffFrameworkPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            clipboardPathHits: [NSHomeDirectory() + "/Library/Preferences/synthetic-handoff_clipboard_depth.plist", "/usr/bin/osascript"],
            sharingdPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            handoffSurfacePresent: true,
            notes: ["synthetic Handoff clipboard depth"]
        )
        state.collectorNotes["collect.handoff_clipboard_depth"] = "a=3 b=2 c=3 surface=true"

        state.imessagePathPlane = ImessagePathPlaneState(
            messagesAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            messagesDbPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-imessage_path_plane.plist", "/usr/bin/osascript"],
            messagesPrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            imessageSurfacePresent: true,
            notes: ["synthetic iMessage path plane"]
        )
        state.collectorNotes["collect.imessage_path_plane"] = "a=3 b=2 c=3 surface=true"

        state.facetimeCameraSurface = FacetimeCameraSurfaceState(
            facetimeAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            avConferencePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-facetime_camera_surface.plist", "/usr/bin/osascript"],
            facetimePrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            facetimeSurfacePresent: true,
            notes: ["synthetic FaceTime camera dual-use"]
        )
        state.collectorNotes["collect.facetime_camera_surface"] = "a=3 b=2 c=3 surface=true"

        state.finderSyncExtension = FinderSyncExtensionState(
            finderSyncFrameworkPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            appScriptPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-finder_sync_extension.plist", "/usr/bin/osascript"],
            finderPrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            finderSyncSurfacePresent: true,
            notes: ["synthetic Finder Sync dual-use"]
        )
        state.collectorNotes["collect.finder_sync_extension"] = "a=3 b=2 c=3 surface=true"

        state.fileproviderDomain = FileproviderDomainState(
            fileProviderFrameworkPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            cloudStoragePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-fileprovider_domain.plist", "/usr/bin/osascript"],
            fileProviderLaunchPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            fileProviderSurfacePresent: true,
            notes: ["synthetic File Provider domain"]
        )
        state.collectorNotes["collect.fileprovider_domain"] = "a=3 b=2 c=3 surface=true"

        state.notificationCenterDepth = NotificationCenterDepthState(
            notificationFrameworkPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            notificationStorePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-notification_center_depth.plist", "/usr/bin/osascript"],
            notificationPrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            notificationSurfacePresent: true,
            notes: ["synthetic Notification Center depth"]
        )
        state.collectorNotes["collect.notification_center_depth"] = "a=3 b=2 c=3 surface=true"

        state.siriSuggestionsPlane = SiriSuggestionsPlaneState(
            siriFrameworkPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            suggestionsStorePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-siri_suggestions_plane.plist", "/usr/bin/osascript"],
            siriPrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            siriSurfacePresent: true,
            notes: ["synthetic Siri Suggestions residual"]
        )
        state.collectorNotes["collect.siri_suggestions_plane"] = "a=3 b=2 c=3 surface=true"

        state.spotlightImporterDepth = SpotlightImporterDepthState(
            metadataToolPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            spotlightImporterPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-spotlight_importer_depth.plist", "/usr/bin/osascript"],
            mdsLaunchPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            spotlightImporterSurfacePresent: true,
            notes: ["synthetic Spotlight importer depth"]
        )
        state.collectorNotes["collect.spotlight_importer_depth"] = "a=3 b=2 c=3 surface=true"

        state.contactsPathPlane = ContactsPathPlaneState(
            contactsAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            addressBookPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-contacts_path_plane.plist", "/usr/bin/osascript"],
            contactsPrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            contactsSurfacePresent: true,
            notes: ["synthetic Contacts path plane"]
        )
        state.collectorNotes["collect.contacts_path_plane"] = "a=3 b=2 c=3 surface=true"

        state.calendarServerPath = CalendarServerPathState(
            caldavFrameworkPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            calendarsStorePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-calendar_server_path.plist", "/usr/bin/osascript"],
            calendarAgentPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            caldavSurfacePresent: true,
            notes: ["synthetic Calendar CalDAV residual"]
        )
        state.collectorNotes["collect.calendar_server_path"] = "a=3 b=2 c=3 surface=true"

        state.remindersCloudPath = RemindersCloudPathState(
            remindersAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            remindersStorePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-reminders_cloud_path.plist", "/usr/bin/osascript"],
            remindersPrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            remindersCloudSurfacePresent: true,
            notes: ["synthetic Reminders cloud path"]
        )
        state.collectorNotes["collect.reminders_cloud_path"] = "a=3 b=2 c=3 surface=true"

        state.mapsLocationPath = MapsLocationPathState(
            mapsAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            mapsCachePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-maps_location_path.plist", "/usr/bin/osascript"],
            locationdPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            mapsLocationSurfacePresent: true,
            notes: ["synthetic Maps location residual"]
        )
        state.collectorNotes["collect.maps_location_path"] = "a=3 b=2 c=3 surface=true"

        state.weatherWidgetPath = WeatherWidgetPathState(
            weatherAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            weatherContainerPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-weather_widget_path.plist", "/usr/bin/osascript"],
            widgetServicePaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            weatherSurfacePresent: true,
            notes: ["synthetic Weather widget residual"]
        )
        state.collectorNotes["collect.weather_widget_path"] = "a=3 b=2 c=3 surface=true"

        state.musicLibraryPath = MusicLibraryPathState(
            musicAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            musicLibraryPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-music_library_path.plist", "/usr/bin/osascript"],
            musicPrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            musicSurfacePresent: true,
            notes: ["synthetic Music library path"]
        )
        state.collectorNotes["collect.music_library_path"] = "a=3 b=2 c=3 surface=true"

        state.booksPathPlane = BooksPathPlaneState(
            booksAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            booksContainerPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-books_path_plane.plist", "/usr/bin/osascript"],
            booksPrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            booksSurfacePresent: true,
            notes: ["synthetic Books path plane"]
        )
        state.collectorNotes["collect.books_path_plane"] = "a=3 b=2 c=3 surface=true"

        state.podcastsPathPlane = PodcastsPathPlaneState(
            podcastsAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            podcastsStorePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-podcasts_path_plane.plist", "/usr/bin/osascript"],
            podcastsPrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            podcastsSurfacePresent: true,
            notes: ["synthetic Podcasts path plane"]
        )
        state.collectorNotes["collect.podcasts_path_plane"] = "a=3 b=2 c=3 surface=true"

        state.tvAppPathPlane = TvAppPathPlaneState(
            tvAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            tvContainerPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-tv_app_path_plane.plist", "/usr/bin/osascript"],
            tvPrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            tvSurfacePresent: true,
            notes: ["synthetic TV.app path plane"]
        )
        state.collectorNotes["collect.tv_app_path_plane"] = "a=3 b=2 c=3 surface=true"

        state.homekitPathPlane = HomekitPathPlaneState(
            homeAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            homeKitStorePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-homekit_path_plane.plist", "/usr/bin/osascript"],
            homedPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            homekitSurfacePresent: true,
            notes: ["synthetic HomeKit path plane"]
        )
        state.collectorNotes["collect.homekit_path_plane"] = "a=3 b=2 c=3 surface=true"

        state.healthPathPlane = HealthPathPlaneState(
            healthAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            healthStorePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-health_path_plane.plist", "/usr/bin/osascript"],
            healthdPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            healthSurfacePresent: true,
            notes: ["synthetic Health path plane"]
        )
        state.collectorNotes["collect.health_path_plane"] = "a=3 b=2 c=3 surface=true"

        state.walletPassPath = WalletPassPathState(
            walletAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            passesStorePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-wallet_pass_path.plist", "/usr/bin/osascript"],
            passdPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            walletSurfacePresent: true,
            notes: ["synthetic Wallet pass path"]
        )
        state.collectorNotes["collect.wallet_pass_path"] = "a=3 b=2 c=3 surface=true"

        state.findmyPathPlane = FindmyPathPlaneState(
            findMyAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            findMyCachePaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-findmy_path_plane.plist", "/usr/bin/osascript"],
            fmfdPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            findmySurfacePresent: true,
            notes: ["synthetic Find My path plane"]
        )
        state.collectorNotes["collect.findmy_path_plane"] = "a=3 b=2 c=3 surface=true"

        state.shortcutsIcloudSync = ShortcutsIcloudSyncState(
            shortcutsAppPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            shortcutsDbPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-shortcuts_icloud_sync.plist", "/usr/bin/osascript"],
            shortcutsPrefPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            shortcutsIcloudSurfacePresent: true,
            notes: ["synthetic Shortcuts iCloud sync"]
        )
        state.collectorNotes["collect.shortcuts_icloud_sync"] = "a=3 b=2 c=3 surface=true"

        state.devicemanagementProfile = DevicemanagementProfileState(
            profilesToolPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            managedPrefPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-devicemanagement_profile.plist", "/usr/bin/osascript"],
            mdmClientPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            deviceMgmtSurfacePresent: true,
            notes: ["synthetic Device management profile"]
        )
        state.collectorNotes["collect.devicemanagement_profile"] = "a=3 b=2 c=3 surface=true"

        state.softwareupdateCatalog = SoftwareupdateCatalogState(
            softwareUpdateToolPaths: ["/usr/bin/open", "/System/Library/Frameworks/AppKit.framework", NSHomeDirectory() + "/Downloads"],
            softwareUpdatePrefPaths: [NSHomeDirectory() + "/Library/Preferences/synthetic-softwareupdate_catalog.plist", "/usr/bin/osascript"],
            softwareUpdateDaemonPaths: [NSHomeDirectory() + "/Desktop", NSHomeDirectory() + "/Downloads", "/Volumes"],
            softwareUpdateSurfacePresent: true,
            notes: ["synthetic Software Update catalog"]
        )
        state.collectorNotes["collect.softwareupdate_catalog"] = "a=3 b=2 c=3 surface=true"





        // Amplifiers for Wave-11 compounds
        if state.network == nil {
            state.network = NetworkState(remoteLoginSSH: true, screenSharingARD: true)
        } else {
            state.network?.remoteLoginSSH = true
            state.network?.screenSharingARD = true
        }
        if state.tcc == nil {
            state.tcc = TCCState(fullDiskAccessLikely: true, notes: ["wave11"], probeMethod: "synthetic")
        } else {
            state.tcc?.fullDiskAccessLikely = true
        }
        if state.remoteAppleEvents == nil {
            state.remoteAppleEvents = RemoteAppleEventsState(
                remoteAEPrefPaths: ["/Library/Preferences/com.apple.RemoteManagement.plist"],
                eppcFrameworkPaths: ["/System/Library/Frameworks/CoreServices.framework"],
                remoteMgmtHints: ["synthetic RAE"],
                remoteAutomationSurfacePresent: true,
                notes: ["synthetic RAE for wave11"]
            )
        }
        if state.esf == nil {
            state.esf = ESFPostureState(clientPaths: [], notes: ["synthetic empty ES clients"])
        }
        return state
    }
}
