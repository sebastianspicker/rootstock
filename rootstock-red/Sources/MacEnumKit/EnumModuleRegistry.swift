/// Assess collector registry: host inventory modules feeding CollectedState for vectors/checks.
import Foundation
import RootstockCore
import MacIdentityKit
import MacMdmKit
import MacPersistKit

/// Default assess collector set for RootstockRed.
public enum EnumModuleRegistry {
    public static func allCollectors() -> [any Collector] {
        [
            HostCollector(),
            SecurityProductsCollector(),
            RunningAppsCollector(),
            LaunchdCollector(),
            PersistAuditCollector(),
            TCCCollector(),
            CredPathsCollector(),
            LOOBinsCollector(),
            ProtectionsCollector(),
            MdmPostureCollector(),
            IdentityPostureCollector(),
            LoginItemsBTMCollector(),
            NetworkCollector(),
            CodesignCollector(),
            DylibRiskCollector(),
            InjectabilityCollector(),
            BrowserMetaCollector(),
            XPCHelpersCollector(),
            SystemExtensionsCollector(),
            // Wave-5 2026 coverage collectors
            ESFEndpointSecurityCollector(),
            PatchDebtCollector(),
            TCCPermissionGraphCollector(),
            LaunchConstraintCollector(),
            // Wave-6 2026 coverage collectors
            NetworkExtensionCollector(),
            AuthRightsCollector(),
            DeveloperToolchainCollector(),
            TimeMachineCollector(),
            ConfigProfileSideloadCollector(),
            // Wave-7 2026 coverage collectors
            AppSandboxEntitlementsCollector(),
            NotarizationStaplingCollector(),
            VirtualizationContainersCollector(),
            ContinuityAirDropCollector(),
            FileVaultEscrowCollector(),
            // Wave-8 2026 coverage collectors
            ClickFixTerminalDeliveryCollector(),
            RemoteAppleEventsCollector(),
            SpotlightAICacheCollector(),
            SecurityMgmtPlaneCollector(),
            ThirdPartyTCCInheritanceCollector(),
            SSHAgentKeyPathCollector(),
            // Wave-9 2026 coverage collectors
            PackageKitInstallerDesignCollector(),
            ArchiveQuarantineExtractorCollector(),
            InfoStealerPathPlaneCollector(),
            TCCESFVisibilityDepthCollector(),
            MDMProfileParseDepthCollector(),
            // Wave-11 2026 coverage multi-plane collectors
            URLSchemeHandlerCollector(),
            LaunchdOverrideDepthCollector(),
            BrowserExtensionDualUseCollector(),
            ShortcutsAppIntentsCollector(),
            // Wave-12 2026 coverage multi-plane collectors
            WeblocInetlocDeliveryCollector(),
            MailRulesAutomationCollector(),
            UnifiedLogObservationCollector(),
            DockPersistenceSurfaceCollector(),
            OsascriptScptDeliveryCollector(),
            NetworkShareMountCollector(),
            // Wave-13 2026 coverage multi-plane collectors
            CalendarRemindersAutomationCollector(),
            GatekeeperAssessmentHistoryCollector(),
            HomebrewPackageDualUseCollector(),
            CupsPrintDualUseCollector(),
            ScreenCapturePrivacyDualUseCollector(),
            // Wave-14 2026 coverage multi-plane collectors
            AutomatorWorkflowCollector(),
            IcloudDrivePathCollector(),
            BluetoothContinuityDepthCollector(),
            FontValidationDualuseCollector(),
            QuicklookCacheDepthCollector(),
            DnsResolverDualuseCollector(),
            LsQuarantineDbDepthCollector(),
            PamAuthModuleCollector(),
            CronAtJobDepthCollector(),
            NotesMetadataPlaneCollector(),
            // Wave-15 2026 coverage multi-plane collectors
            PhotosLibraryPathCollector(),
            VpnConfigDualuseCollector(),
            SandboxContainerDepthCollector(),
            XpcMachServiceDepthCollector(),
            TmLocalSnapshotDepthCollector(),
            EmondLegacyDepthCollector(),
            ScreenSharingArdDepthCollector(),
            KeychainAclPathCollector(),
            PythonRuntimeDualuseCollector(),
            ShellPluginManagerCollector(),
            // Wave-16 multi-plane collectors (25 themes / 50 half-pairs)
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
            SoftwareupdateCatalogCollector(),
        ]
    }

    public static func defaultRegistry(checks: [any Check] = []) -> ModuleRegistry {
        ModuleRegistry(collectors: allCollectors(), checks: checks)
    }
}
