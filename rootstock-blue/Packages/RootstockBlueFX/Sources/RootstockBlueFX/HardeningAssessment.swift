import Foundation
import RootstockBlueCore
import RootstockBlueCase

/// Automated **hardening / defense assessment** - product feature, not docs-only.
///
/// Consumes IR posture (+ optional parser) events and emits structured
/// `harden.finding` envelopes with **operator-visible remediation** text.
/// Pure offline path is fixture-complete (security_posture.json + ALF + sysext + remote).
///
/// Does not become MDM or AV: assessment + guidance only; no policy push, no quarantine.
public enum HardeningAssessment {
    public struct Finding: Sendable, Equatable {
        public var control: String
        public var status: String // pass | fail | warn | unknown
        public var severity: String
        public var title: String
        public var detail: String
        public var remediation: String
        public var evidence: String

        public init(
            control: String,
            status: String,
            severity: String,
            title: String,
            detail: String,
            remediation: String,
            evidence: String = ""
        ) {
            self.control = control
            self.status = status
            self.severity = severity
            self.title = title
            self.detail = detail
            self.remediation = remediation
            self.evidence = evidence
        }
    }

    /// Assess from pre-collected posture/parser events (unit-testable pure path).
    public static func assess(events: [EventEnvelope]) -> [Finding] {
        var findings: [Finding] = []
        findings.append(contentsOf: assessProtections(events))
        findings.append(contentsOf: assessRemoteAccess(events))
        findings.append(contentsOf: assessLaunchdOverrides(events))
        findings.append(contentsOf: assessSudoers(events))
        findings.append(contentsOf: assessShellProfiles(events))
        findings.append(contentsOf: assessEmond(events))
        findings.append(contentsOf: assessSystemExtensions(events))
        findings.append(contentsOf: assessSecurityCoverage(events))
        // Wave-4 persistence + access posture
        findings.append(contentsOf: assessPrivHelpers(events))
        findings.append(contentsOf: assessFolderActions(events))
        findings.append(contentsOf: assessLoginHooks(events))
        findings.append(contentsOf: assessAccountPosture(events))
        findings.append(contentsOf: assessSoftwareUpdate(events))
        findings.append(contentsOf: assessLockdownMode(events))
        // Wave-5 auth plugins / net usage / codesign / keychain meta / ARD
        findings.append(contentsOf: assessAuthPlugins(events))
        findings.append(contentsOf: assessNetUsage(events))
        findings.append(contentsOf: assessCodesign(events))
        findings.append(contentsOf: assessKeychainMeta(events))
        findings.append(contentsOf: assessARDAllLocalUsers(events))
        // Wave-6 forensics / PoL / cloud posture
        findings.append(contentsOf: assessTrashSensitive(events))
        findings.append(contentsOf: assessSpotlightSensitive(events))
        findings.append(contentsOf: assessFirefoxSuspiciousDownload(events))
        findings.append(contentsOf: assessNotificationSensitive(events))
        findings.append(contentsOf: assessQuickLookSensitive(events))
        findings.append(contentsOf: assessScreenTimeSuspicious(events))
        findings.append(contentsOf: assessICloudDesktopDocuments(events))
        findings.append(contentsOf: assessSavedStateSuspicious(events))
        // Wave-7 browser collab print notes backup rdp multi-cloud
        findings.append(contentsOf: assessCookieEvilDomain(events))
        findings.append(contentsOf: assessBookmarkEvilDomain(events))
        findings.append(contentsOf: assessOfficeMRUSensitive(events))
        findings.append(contentsOf: assessPrintSensitiveJob(events))
        findings.append(contentsOf: assessNotesSensitiveMarker(events))
        findings.append(contentsOf: assessIDeviceBackupUnencrypted(events))
        findings.append(contentsOf: assessMSRDCRemoteConnection(events))
        findings.append(contentsOf: assessCloudSyncExfilProvider(events))
        // Wave-8 residual red↔blue pair controls
        findings.append(contentsOf: assessPackageKitInstallerDesign(events))
        findings.append(contentsOf: assessArchiveQuarantineExtractor(events))
        findings.append(contentsOf: assessInfoStealerPathPlane(events))
        findings.append(contentsOf: assessTCCESFVisibilityDepth(events))
        // Wave-11 multi-plane red↔blue pair controls
        findings.append(contentsOf: assessURLSchemeHandler(events))
        findings.append(contentsOf: assessLaunchdOverrideDepth(events))
        findings.append(contentsOf: assessBrowserExtensionDualUse(events))
        findings.append(contentsOf: assessShortcutsAppIntents(events))
        // Wave-12 multi-plane red↔blue pair controls
        findings.append(contentsOf: assessWeblocInetloc(events))
        findings.append(contentsOf: assessMailRulesAutomation(events))
        findings.append(contentsOf: assessUnifiedLogObservation(events))
        findings.append(contentsOf: assessDockPersistenceSurface(events))
        findings.append(contentsOf: assessOsascriptScptDelivery(events))
        findings.append(contentsOf: assessNetworkShareMount(events))
        // Wave-13 multi-plane red↔blue pair controls
        findings.append(contentsOf: assessCalendarRemindersAutomation(events))
        findings.append(contentsOf: assessGatekeeperAssessmentHistory(events))
        findings.append(contentsOf: assessHomebrewPackageDualUse(events))
        findings.append(contentsOf: assessCupsPrintDualUse(events))
        findings.append(contentsOf: assessScreenCapturePrivacyDualUse(events))
        // Wave-14 multi-plane red↔blue pair controls
        findings.append(contentsOf: assessAutomatorWorkflow(events))
        findings.append(contentsOf: assessIcloudDrivePath(events))
        findings.append(contentsOf: assessBluetoothContinuityDepth(events))
        findings.append(contentsOf: assessFontValidationDualuse(events))
        findings.append(contentsOf: assessQuicklookCacheDepth(events))
        findings.append(contentsOf: assessDnsResolverDualuse(events))
        findings.append(contentsOf: assessLsQuarantineDbDepth(events))
        findings.append(contentsOf: assessPamAuthModule(events))
        findings.append(contentsOf: assessCronAtJobDepth(events))
        findings.append(contentsOf: assessNotesMetadataPlane(events))
        // Wave-15 multi-plane red↔blue pair controls
        findings.append(contentsOf: assessPhotosLibraryPath(events))
        findings.append(contentsOf: assessVpnConfigDualuse(events))
        findings.append(contentsOf: assessSandboxContainerDepth(events))
        findings.append(contentsOf: assessXpcMachServiceDepth(events))
        findings.append(contentsOf: assessTmLocalSnapshotDepth(events))
        findings.append(contentsOf: assessEmondLegacyDepth(events))
        findings.append(contentsOf: assessScreenSharingArdDepth(events))
        findings.append(contentsOf: assessKeychainAclPath(events))
        findings.append(contentsOf: assessPythonRuntimeDualuse(events))
        findings.append(contentsOf: assessShellPluginManager(events))
        // Wave-16 multi-plane controls
        findings.append(contentsOf: assessAirplayReceiverSurface(events))
        findings.append(contentsOf: assessHandoffClipboardDepth(events))
        findings.append(contentsOf: assessImessagePathPlane(events))
        findings.append(contentsOf: assessFacetimeCameraSurface(events))
        findings.append(contentsOf: assessFinderSyncExtension(events))
        findings.append(contentsOf: assessFileproviderDomain(events))
        findings.append(contentsOf: assessNotificationCenterDepth(events))
        findings.append(contentsOf: assessSiriSuggestionsPlane(events))
        findings.append(contentsOf: assessSpotlightImporterDepth(events))
        findings.append(contentsOf: assessContactsPathPlane(events))
        findings.append(contentsOf: assessCalendarServerPath(events))
        findings.append(contentsOf: assessRemindersCloudPath(events))
        findings.append(contentsOf: assessMapsLocationPath(events))
        findings.append(contentsOf: assessWeatherWidgetPath(events))
        findings.append(contentsOf: assessMusicLibraryPath(events))
        findings.append(contentsOf: assessBooksPathPlane(events))
        findings.append(contentsOf: assessPodcastsPathPlane(events))
        findings.append(contentsOf: assessTvAppPathPlane(events))
        findings.append(contentsOf: assessHomekitPathPlane(events))
        findings.append(contentsOf: assessHealthPathPlane(events))
        findings.append(contentsOf: assessWalletPassPath(events))
        findings.append(contentsOf: assessFindmyPathPlane(events))
        findings.append(contentsOf: assessShortcutsIcloudSync(events))
        findings.append(contentsOf: assessDevicemanagementProfile(events))
        findings.append(contentsOf: assessSoftwareupdateCatalog(events))
        return findings
    }

    /// Offline assess from artifact tree: posture + wave-3/4/5/6/7/8 parsers.
    public static func assessOffline(source: ImageSource) throws -> [Finding] {
        var events: [EventEnvelope] = []
        events.append(contentsOf: try HostIRPosture.enumerateOffline(source: source))
        events.append(contentsOf: try ShellProfilesParser().parse(source: source))
        events.append(contentsOf: try EmondParser().parse(source: source))
        events.append(contentsOf: try SudoersParser().parse(source: source))
        events.append(contentsOf: try LaunchdOverridesParser().parse(source: source))
        events.append(contentsOf: try SystemExtensionsParser().parse(source: source))
        events.append(contentsOf: try PrivHelpersParser().parse(source: source))
        events.append(contentsOf: try FolderActionsParser().parse(source: source))
        events.append(contentsOf: try LoginHooksParser().parse(source: source))
        // Wave-5
        events.append(contentsOf: try AuthPluginsParser().parse(source: source))
        events.append(contentsOf: try NetUsageParser().parse(source: source))
        events.append(contentsOf: try USBHistoryParser().parse(source: source))
        events.append(contentsOf: try KeychainMetaParser().parse(source: source))
        events.append(contentsOf: try CodesignParser().parse(source: source))
        events.append(contentsOf: try ARDParser().parse(source: source))
        // Wave-6
        events.append(contentsOf: try SpotlightParser().parse(source: source))
        events.append(contentsOf: try TrashParser().parse(source: source))
        events.append(contentsOf: try DocRevisionsParser().parse(source: source))
        events.append(contentsOf: try SavedStateParser().parse(source: source))
        events.append(contentsOf: try FirefoxParser().parse(source: source))
        events.append(contentsOf: try NotificationsParser().parse(source: source))
        events.append(contentsOf: try QuickLookParser().parse(source: source))
        events.append(contentsOf: try ScreenTimeParser().parse(source: source))
        events.append(contentsOf: try ICloudParser().parse(source: source))
        // Wave-7
        events.append(contentsOf: try CookiesParser().parse(source: source))
        events.append(contentsOf: try BookmarksParser().parse(source: source))
        events.append(contentsOf: try OfficeMRUParser().parse(source: source))
        events.append(contentsOf: try PrintJobsParser().parse(source: source))
        events.append(contentsOf: try NotesParser().parse(source: source))
        events.append(contentsOf: try IDeviceBackupParser().parse(source: source))
        events.append(contentsOf: try MSRDCParser().parse(source: source))
        events.append(contentsOf: try CloudSyncParser().parse(source: source))
        // Wave-8 residual red↔blue pairs
        events.append(contentsOf: try PackageKitDesignParser().parse(source: source))
        events.append(contentsOf: try ArchiveExtractorParser().parse(source: source))
        events.append(contentsOf: try InfoStealerPathParser().parse(source: source))
        events.append(contentsOf: try TCCESFVisibilityParser().parse(source: source))
        // Wave-11 multi-plane
        events.append(contentsOf: try URLSchemeHandlerParser().parse(source: source))
        events.append(contentsOf: try LaunchdOverrideDepthParser().parse(source: source))
        events.append(contentsOf: try BrowserExtensionDualUseParser().parse(source: source))
        events.append(contentsOf: try ShortcutsAppIntentsParser().parse(source: source))
        // Wave-12 multi-plane
        events.append(contentsOf: try WeblocInetlocParser().parse(source: source))
        events.append(contentsOf: try MailRulesAutomationParser().parse(source: source))
        events.append(contentsOf: try UnifiedLogObservationParser().parse(source: source))
        events.append(contentsOf: try DockPersistenceSurfaceParser().parse(source: source))
        events.append(contentsOf: try OsascriptScptDeliveryParser().parse(source: source))
        events.append(contentsOf: try NetworkShareMountParser().parse(source: source))
        // Wave-13 multi-plane
        events.append(contentsOf: try CalendarRemindersAutomationParser().parse(source: source))
        events.append(contentsOf: try GatekeeperAssessmentHistoryParser().parse(source: source))
        events.append(contentsOf: try HomebrewPackageDualUseParser().parse(source: source))
        events.append(contentsOf: try CupsPrintDualUseParser().parse(source: source))
        events.append(contentsOf: try ScreenCapturePrivacyDualUseParser().parse(source: source))
        // Wave-14 multi-plane
        events.append(contentsOf: try AutomatorWorkflowParser().parse(source: source))
        events.append(contentsOf: try IcloudDrivePathParser().parse(source: source))
        events.append(contentsOf: try BluetoothContinuityDepthParser().parse(source: source))
        events.append(contentsOf: try FontValidationDualuseParser().parse(source: source))
        events.append(contentsOf: try QuicklookCacheDepthParser().parse(source: source))
        events.append(contentsOf: try DnsResolverDualuseParser().parse(source: source))
        events.append(contentsOf: try LsQuarantineDbDepthParser().parse(source: source))
        events.append(contentsOf: try PamAuthModuleParser().parse(source: source))
        events.append(contentsOf: try CronAtJobDepthParser().parse(source: source))
        events.append(contentsOf: try NotesMetadataPlaneParser().parse(source: source))
        // Wave-15 multi-plane
        events.append(contentsOf: try PhotosLibraryPathParser().parse(source: source))
        events.append(contentsOf: try VpnConfigDualuseParser().parse(source: source))
        events.append(contentsOf: try SandboxContainerDepthParser().parse(source: source))
        events.append(contentsOf: try XpcMachServiceDepthParser().parse(source: source))
        events.append(contentsOf: try TmLocalSnapshotDepthParser().parse(source: source))
        events.append(contentsOf: try EmondLegacyDepthParser().parse(source: source))
        events.append(contentsOf: try ScreenSharingArdDepthParser().parse(source: source))
        events.append(contentsOf: try KeychainAclPathParser().parse(source: source))
        events.append(contentsOf: try PythonRuntimeDualuseParser().parse(source: source))
        events.append(contentsOf: try ShellPluginManagerParser().parse(source: source))
        // Wave-16 multi-plane
        events.append(contentsOf: try AirplayReceiverSurfaceParser().parse(source: source))
        events.append(contentsOf: try HandoffClipboardDepthParser().parse(source: source))
        events.append(contentsOf: try ImessagePathPlaneParser().parse(source: source))
        events.append(contentsOf: try FacetimeCameraSurfaceParser().parse(source: source))
        events.append(contentsOf: try FinderSyncExtensionParser().parse(source: source))
        events.append(contentsOf: try FileproviderDomainParser().parse(source: source))
        events.append(contentsOf: try NotificationCenterDepthParser().parse(source: source))
        events.append(contentsOf: try SiriSuggestionsPlaneParser().parse(source: source))
        events.append(contentsOf: try SpotlightImporterDepthParser().parse(source: source))
        events.append(contentsOf: try ContactsPathPlaneParser().parse(source: source))
        events.append(contentsOf: try CalendarServerPathParser().parse(source: source))
        events.append(contentsOf: try RemindersCloudPathParser().parse(source: source))
        events.append(contentsOf: try MapsLocationPathParser().parse(source: source))
        events.append(contentsOf: try WeatherWidgetPathParser().parse(source: source))
        events.append(contentsOf: try MusicLibraryPathParser().parse(source: source))
        events.append(contentsOf: try BooksPathPlaneParser().parse(source: source))
        events.append(contentsOf: try PodcastsPathPlaneParser().parse(source: source))
        events.append(contentsOf: try TvAppPathPlaneParser().parse(source: source))
        events.append(contentsOf: try HomekitPathPlaneParser().parse(source: source))
        events.append(contentsOf: try HealthPathPlaneParser().parse(source: source))
        events.append(contentsOf: try WalletPassPathParser().parse(source: source))
        events.append(contentsOf: try FindmyPathPlaneParser().parse(source: source))
        events.append(contentsOf: try ShortcutsIcloudSyncParser().parse(source: source))
        events.append(contentsOf: try DevicemanagementProfileParser().parse(source: source))
        events.append(contentsOf: try SoftwareupdateCatalogParser().parse(source: source))
        return assess(events: events)
    }

    /// Live assess using live IR posture probes (honest; no silent TCC bypass).
    public static func assessLive(runStatusProbes: Bool = true) -> [Finding] {
        let events = HostIRPosture.enumerateLive(runStatusProbes: runStatusProbes)
        return assess(events: events)
    }

    /// Convert findings to case-ready EventEnvelopes.
    public static func toEvents(_ findings: [Finding], mode: String) -> [EventEnvelope] {
        findings.map { f in
            EventEnvelope(
                eventTime: Date(),
                collectedAt: Date(),
                source: .collect,
                sourcePlugin: "HARDEN",
                eventType: "harden.finding",
                entityRefs: [EntityID(kind: .host, value: "harden=\(f.control)")],
                fields: [
                    "ir.mode": mode,
                    "harden.control": f.control,
                    "harden.status": f.status,
                    "harden.severity": f.severity,
                    "harden.title": f.title,
                    "harden.detail": f.detail,
                    "harden.remediation": f.remediation,
                    "harden.evidence": f.evidence,
                    FieldTaxonomy.eventType: "harden.finding",
                ],
                confidence: f.status == "unknown" ? 0.5 : 0.92
            )
        }
    }

    /// Write assessment events into a case package.
    @discardableResult
    public static func writeToCase(
        _ findings: [Finding],
        package: CasePackage,
        mode: String,
        actor: String = NSUserName()
    ) throws -> Int {
        let events = toEvents(findings, mode: mode)
        for event in events {
            try package.appendEventJSONL(event, stream: "es")
            try package.insertTimelineEvent(event)
        }
        try package.appendCustody(
            CustodyEvent(
                actor: actor,
                action: "harden_assess",
                detail: "Hardening assessment (\(mode)) findings=\(findings.count) fail=\(findings.filter { $0.status == "fail" }.count)"
            )
        )
        try package.updateHashes()
        return events.count
    }

    // MARK: - Control assessments

    private static func assessProtections(_ events: [EventEnvelope]) -> [Finding] {
        var findings: [Finding] = []
        let protections = events.filter {
            $0.eventType == "ir.posture.protection" || $0.fields["protection.name"] != nil
        }

        func status(for name: String) -> (enabled: String, evidence: String)? {
            for e in protections {
                let n = (e.fields["protection.name"] ?? "").lowercased()
                if n == name.lowercased() || n.contains(name.lowercased()) {
                    return (e.fields["protection.enabled"] ?? "unknown", e.fields["protection.raw"] ?? e.fields["protection.note"] ?? "")
                }
            }
            return nil
        }

        if let sip = status(for: "SIP") {
            if sip.enabled == "false" {
                findings.append(Finding(
                    control: "sip",
                    status: "fail",
                    severity: "critical",
                    title: "System Integrity Protection disabled",
                    detail: "SIP is reported disabled. Kernel and critical paths are less protected.",
                    remediation: "Re-enable SIP from Recovery: csrutil enable; reboot. Investigate who disabled it.",
                    evidence: sip.evidence
                ))
            } else if sip.enabled == "true" {
                findings.append(Finding(
                    control: "sip",
                    status: "pass",
                    severity: "info",
                    title: "SIP enabled",
                    detail: "System Integrity Protection appears enabled.",
                    remediation: "No action. Keep SIP enabled except during short, controlled maintenance.",
                    evidence: sip.evidence
                ))
            } else {
                findings.append(Finding(
                    control: "sip",
                    status: "unknown",
                    severity: "low",
                    title: "SIP status unknown",
                    detail: "Could not determine SIP state from available posture signals.",
                    remediation: "Run live: csrutil status. Prefer offline security_posture.json in images.",
                    evidence: sip.evidence
                ))
            }
        }

        if let fw = status(for: "Firewall") {
            if fw.enabled == "false" {
                findings.append(Finding(
                    control: "firewall",
                    status: "fail",
                    severity: "high",
                    title: "Application firewall disabled",
                    detail: "ALF / application firewall is reported off.",
                    remediation: "Enable Application Firewall (Security settings or /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on). Enforce via MDM where possible.",
                    evidence: fw.evidence
                ))
            } else if fw.enabled == "true" {
                findings.append(Finding(
                    control: "firewall",
                    status: "pass",
                    severity: "info",
                    title: "Firewall enabled",
                    detail: "Application firewall appears enabled.",
                    remediation: "Confirm stealth mode and block-all-incoming policy match org baseline.",
                    evidence: fw.evidence
                ))
            }
        }

        if let gk = status(for: "Gatekeeper") {
            if gk.enabled == "false" {
                findings.append(Finding(
                    control: "gatekeeper",
                    status: "fail",
                    severity: "high",
                    title: "Gatekeeper disabled",
                    detail: "Gatekeeper assessments appear disabled - unsigned/unknown code easier to run.",
                    remediation: "Re-enable: spctl --master-enable. Investigate recent Gatekeeper overrides and quarantine events.",
                    evidence: gk.evidence
                ))
            } else if gk.enabled == "true" {
                findings.append(Finding(
                    control: "gatekeeper",
                    status: "pass",
                    severity: "info",
                    title: "Gatekeeper enabled",
                    detail: "Gatekeeper appears enabled.",
                    remediation: "Monitor GATEKEEPER_USER_OVERRIDE and assessment history.",
                    evidence: gk.evidence
                ))
            }
        }

        if let fv = status(for: "FileVault") {
            if fv.enabled == "false" {
                findings.append(Finding(
                    control: "filevault",
                    status: "fail",
                    severity: "high",
                    title: "FileVault disk encryption disabled",
                    detail: "Volume encryption is reported off - data-at-rest risk if device is stolen.",
                    remediation: "Enable FileVault via System Settings or MDM escrow. Never attempt offline cryptanalysis (non-goal).",
                    evidence: fv.evidence
                ))
            } else if fv.enabled == "true" {
                findings.append(Finding(
                    control: "filevault",
                    status: "pass",
                    severity: "info",
                    title: "FileVault enabled",
                    detail: "Disk encryption appears enabled.",
                    remediation: "Verify institutional recovery key escrow with MDM.",
                    evidence: fv.evidence
                ))
            }
        }

        return findings
    }

    private static func assessRemoteAccess(_ events: [EventEnvelope]) -> [Finding] {
        var findings: [Finding] = []
        var seenControls = Set<String>()

        for e in events {
            let name = (e.fields["remote.name"] ?? e.fields["protection.name"] ?? "").lowercased()
            let service = (e.fields["remote.service"] ?? e.fields[FieldTaxonomy.remoteService] ?? name).lowercased()
            let enabled = e.fields["remote.enabled"]
                ?? e.fields[FieldTaxonomy.remoteEnabled]
                ?? e.fields["protection.enabled"]
                ?? ""
            guard enabled == "true" || enabled == "present" else { continue }

            let isScreen = name.contains("screen") || service.contains("screen")
            let isARD = name.contains("remote management") || name.contains("remotemanagement")
                || name.contains("ard") || service.contains("ard")
            let isRemoteLogin = name.contains("remotelogin") || name.contains("remote login")
                || service == "ssh" || service.contains("sshd") || name.contains("sshd")
            let isFileSharing = name.contains("filesharing") || name.contains("file sharing")
                || service.contains("file_sharing") || service.contains("smb")

            if isScreen && seenControls.insert("screen_sharing").inserted {
                findings.append(Finding(
                    control: "screen_sharing",
                    status: "fail",
                    severity: "high",
                    title: "Screen Sharing enabled",
                    detail: "Remote screen sharing appears enabled - increase remote-access attack surface.",
                    remediation: "Disable Screen Sharing unless required. Prefer MDM-managed ARD with MFA/VPN. Review /Library/Preferences/com.apple.RemoteManagement.plist and sharing prefs.",
                    evidence: e.rawRef ?? e.fields["remote.name"] ?? name
                ))
            }
            if isARD && seenControls.insert("remote_management").inserted {
                findings.append(Finding(
                    control: "remote_management",
                    status: "warn",
                    severity: "medium",
                    title: "Remote Management (ARD) enabled",
                    detail: "Apple Remote Desktop / remote management appears enabled.",
                    remediation: "Restrict to admin group; require VPN; audit who has ARD rights.",
                    evidence: e.rawRef ?? ""
                ))
            }
            if isRemoteLogin && seenControls.insert("remote_login").inserted {
                findings.append(Finding(
                    control: "remote_login",
                    status: "fail",
                    severity: "high",
                    title: "Remote Login (sshd) enabled",
                    detail: "Remote Login / SSH service appears enabled on this host/image.",
                    remediation: "Disable Remote Login in System Settings → General → Sharing unless required. Prefer VPN + key-only SSH; enforce via MDM. Audit authorized_keys (SSH parser).",
                    evidence: e.rawRef ?? service
                ))
            }
            if isFileSharing && seenControls.insert("file_sharing").inserted {
                findings.append(Finding(
                    control: "file_sharing",
                    status: "fail",
                    severity: "medium",
                    title: "File Sharing enabled",
                    detail: "SMB/AFP File Sharing appears enabled - lateral movement surface on laptops.",
                    remediation: "Disable File Sharing unless business-required; restrict users/shares; prefer managed file services over ad-hoc SMB.",
                    evidence: e.rawRef ?? service
                ))
            }
        }

        // security_posture-derived remote events from IRPOSTURE (legacy field names)
        for e in events where e.sourcePlugin == "IRPOSTURE" {
            if e.fields["remote.enabled"] == "true" || e.fields["screen_sharing_enabled"] == "true" {
                if seenControls.insert("screen_sharing").inserted {
                    let svc = e.fields["remote.name"] ?? e.fields["remote.service"] ?? e.fields["protection.name"] ?? "remote"
                    if svc.lowercased().contains("screen") || e.eventType.contains("remote") {
                        findings.append(Finding(
                            control: "screen_sharing",
                            status: "fail",
                            severity: "high",
                            title: "Screen Sharing / remote access enabled",
                            detail: "IR posture reports remote access service enabled (\(svc)).",
                            remediation: "Disable unneeded remote services; enforce via configuration profile.",
                            evidence: e.rawRef ?? svc
                        ))
                    }
                }
            }
        }
        return findings
    }

    private static func assessLaunchdOverrides(_ events: [EventEnvelope]) -> [Finding] {
        let disabledSecurity = events.filter {
            $0.eventType == "defense.launchd_override"
                && $0.fields["defense.disabled"] == "true"
                && $0.fields["defense.security_product_hint"] == "true"
        }
        guard !disabledSecurity.isEmpty else { return [] }
        let labels = disabledSecurity.compactMap { $0.fields["defense.label"] }.joined(separator: ", ")
        return [
            Finding(
                control: "launchd_security_disabled",
                status: "fail",
                severity: "critical",
                title: "Security-related launchd jobs disabled",
                detail: "One or more security/IR agents appear in launchd disabled overrides: \(labels)",
                remediation: "Re-enable legitimate agents (launchctl enable). Investigate who wrote disabled.plist. Preserve overrides for forensics before remediation.",
                evidence: labels
            ),
        ]
    }

    private static func assessSudoers(_ events: [EventEnvelope]) -> [Finding] {
        let risky = events.filter {
            $0.eventType == "privilege.sudoers"
                && ($0.fields["privilege.risk_tags"]?.contains("nopasswd") == true
                    || $0.fields["sudoers.risk"]?.contains("nopasswd") == true
                    || $0.fields["privilege.risk_tags"]?.contains("broad_grant") == true)
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap { $0.fields["privilege.line"] ?? $0.fields["sudoers.entry"] }.joined(separator: " | ")
        return [
            Finding(
                control: "sudoers_nopasswd",
                status: "fail",
                severity: "high",
                title: "Dangerous sudoers grant (NOPASSWD / broad ALL)",
                detail: "sudoers entries allow passwordless or overly broad privilege elevation (\(risky.count) matching lines).",
                remediation: "Remove NOPASSWD and ALL=(ALL) ALL grants not justified by break-glass policy. Prefer group-scoped, command-limited sudo. Audit /etc/sudoers.d regularly.",
                evidence: sample
            ),
        ]
    }

    private static func assessShellProfiles(_ events: [EventEnvelope]) -> [Finding] {
        let risky = events.filter {
            $0.sourcePlugin == "SHELLPROFILES"
                && $0.fields["persistence.risk_tags"] != nil
                && !($0.fields["persistence.risk_tags"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let tags = Set(risky.flatMap { ($0.fields["persistence.risk_tags"] ?? "").split(separator: ",").map(String.init) })
        return [
            Finding(
                control: "shell_profile_risk",
                status: "fail",
                severity: tags.contains("curl_pipe_shell") || tags.contains("dyld_insert") ? "high" : "medium",
                title: "Suspicious shell profile content",
                detail: "Shell init files contain high-risk patterns: \(tags.sorted().joined(separator: ", "))",
                remediation: "Inspect user/system profiles for unauthorized PATH, DYLD_INSERT_LIBRARIES, curl|sh, or /tmp payloads. Diff against golden images / MDM baselines.",
                evidence: risky.prefix(3).compactMap { $0.fields["persistence.command"] }.joined(separator: " | ")
            ),
        ]
    }

    private static func assessEmond(_ events: [EventEnvelope]) -> [Finding] {
        let emond = events.filter {
            $0.sourcePlugin == "EMOND" || $0.fields["persistence.kind"] == "emond"
        }
        guard !emond.isEmpty else { return [] }
        // Non-Apple / tmp commands are higher risk
        let suspicious = emond.filter {
            let cmd = ($0.fields["persistence.command"] ?? "").lowercased()
            return cmd.contains("/tmp/") || cmd.contains("curl") || cmd.contains("evil")
                || !cmd.contains("com.apple")
        }
        if !suspicious.isEmpty {
            return [
                Finding(
                    control: "emond_rules",
                    status: "fail",
                    severity: "high",
                    title: "Emond rules present (potential persistence)",
                    detail: "Event Monitor Daemon rules found (\(emond.count)); \(suspicious.count) look non-default/suspicious.",
                    remediation: "Inventory /etc/emond.d/rules. Remove unauthorized rules. Emond is rare on modern fleets - treat unexpected rules as high priority.",
                    evidence: suspicious.prefix(3).compactMap { $0.fields["persistence.command"] ?? $0.fields["emond.rule_name"] }.joined(separator: " | ")
                ),
            ]
        }
        return [
            Finding(
                control: "emond_rules",
                status: "warn",
                severity: "low",
                title: "Emond rules inventory non-empty",
                detail: "\(emond.count) emond rule(s) present - review for legitimacy.",
                remediation: "Confirm rules are organization-approved; otherwise remove.",
                evidence: ""
            ),
        ]
    }

    private static func assessSystemExtensions(_ events: [EventEnvelope]) -> [Finding] {
        let sysext = events.filter {
            $0.eventType.contains("sysext")
                || $0.fields["extension.bundle_id"] != nil
                || $0.sourcePlugin == "SYSTEMEXTENSIONS"
        }
        let unknown = sysext.filter {
            let team = ($0.fields["extension.team_id"] ?? $0.fields[FieldTaxonomy.extensionTeamID] ?? "").lowercased()
            let bundle = ($0.fields["extension.bundle_id"] ?? $0.fields[FieldTaxonomy.extensionBundleID] ?? "").lowercased()
            return bundle.contains("evil") || bundle.contains("unknown")
                || team == "unknown" || team.isEmpty && !bundle.hasPrefix("com.apple")
        }
        guard !unknown.isEmpty else { return [] }
        return [
            Finding(
                control: "system_extensions",
                status: "warn",
                severity: "medium",
                title: "Unknown or suspicious system extensions",
                detail: "\(unknown.count) system extension(s) lack trusted team/bundle signals.",
                remediation: "systemextensionsctl list; remove unauthorized sysexts; require notarization + MDM allowlist for ES/NE peers.",
                evidence: unknown.prefix(3).compactMap { $0.fields["extension.bundle_id"] ?? $0.fields[FieldTaxonomy.extensionBundleID] }.joined(separator: ", ")
            ),
        ]
    }

    private static func assessSecurityCoverage(_ events: [EventEnvelope]) -> [Finding] {
        let products = events.filter { $0.eventType == "ir.posture.security_product" || $0.fields["security.product"] != nil }
        if products.isEmpty {
            // Only warn if we have some host posture so we know we scanned
            let hasHost = events.contains { $0.eventType == "ir.posture.host" }
            if hasHost {
                return [
                    Finding(
                        control: "edr_coverage",
                        status: "warn",
                        severity: "medium",
                        title: "No known security product detected on host/image",
                        detail: "Catalog paths for Falcon/Santa/MDE/osquery/etc. were not present.",
                        remediation: "Confirm fleet EDR/osquery/Santa deployment. RootstockBlue is Mac depth beside EDR - not a replacement.",
                        evidence: "security product catalog empty"
                    ),
                ]
            }
        }
        return []
    }

    // MARK: - Wave-4 assessments

    private static func assessPrivHelpers(_ events: [EventEnvelope]) -> [Finding] {
        let helpers = events.filter {
            $0.sourcePlugin == "PRIVHELPERS" || $0.fields["persistence.kind"] == "privileged_helper"
        }
        guard !helpers.isEmpty else { return [] }
        let risky = helpers.filter {
            let tags = ($0.fields["persistence.risk_tags"] ?? "").lowercased()
            let label = ($0.fields["privhelper.label"] ?? $0.fields["persistence.label"] ?? "").lowercased()
            let team = ($0.fields["privhelper.team_id"] ?? $0.fields["helper.team_id"] ?? "").lowercased()
            return tags.contains("unknown_team") || tags.contains("orphan") || tags.contains("tmp_path")
                || label.contains("evil") || team == "unknown" || team.isEmpty && label.contains("evil")
        }
        if !risky.isEmpty {
            let labels = risky.prefix(5).compactMap {
                $0.fields["privhelper.label"] ?? $0.fields["persistence.label"]
            }.joined(separator: ", ")
            return [
                Finding(
                    control: "privileged_helper_unknown",
                    status: "fail",
                    severity: "high",
                    title: "Unknown or risky privileged helper tools",
                    detail: "\(risky.count) privileged helper(s) with orphan/unknown-team/tmp risk tags (of \(helpers.count) total).",
                    remediation: "Inventory /Library/PrivilegedHelperTools and paired LaunchDaemons. Remove orphaned helpers after validating no required app depends on them. Prefer vendors that uninstall helpers cleanly.",
                    evidence: labels
                ),
            ]
        }
        return [
            Finding(
                control: "privileged_helper_unknown",
                status: "warn",
                severity: "low",
                title: "Privileged helper tools present",
                detail: "\(helpers.count) privileged helper(s) inventoried - review for legitimacy.",
                remediation: "Baseline known SMJobBless helpers; alert on new labels/TeamIDs.",
                evidence: helpers.prefix(3).compactMap { $0.fields["persistence.label"] }.joined(separator: ", ")
            ),
        ]
    }

    private static func assessFolderActions(_ events: [EventEnvelope]) -> [Finding] {
        let actions = events.filter {
            $0.sourcePlugin == "FOLDERACTIONS" || $0.fields["persistence.kind"] == "folder_action"
        }
        guard !actions.isEmpty else { return [] }
        let risky = actions.filter {
            let tags = ($0.fields["persistence.risk_tags"] ?? $0.fields["folder_action.risk_tags"] ?? "").lowercased()
            return tags.contains("do_shell_script") || tags.contains("downloads_watch")
                || tags.contains("tmp_payload") || tags.contains("network_fetch")
                || tags.contains("desktop_watch")
        }
        if !risky.isEmpty {
            return [
                Finding(
                    control: "folder_action_risky",
                    status: "fail",
                    severity: "high",
                    title: "Risky Folder Action / Automator workflow",
                    detail: "\(risky.count) folder action(s) with LotL or high-risk watch paths.",
                    remediation: "Review Folder Actions Setup; remove unknown scripts under ~/Library/Scripts/Folder Action Scripts and workflows under ~/Library/Workflows/Applications/Folder Actions. Investigate Automation TCC grants.",
                    evidence: risky.prefix(3).compactMap {
                        $0.fields["folder_action.script_path"] ?? $0.fields["persistence.command"]
                    }.joined(separator: " | ")
                ),
            ]
        }
        return [
            Finding(
                control: "folder_action_risky",
                status: "warn",
                severity: "low",
                title: "Folder Actions inventory non-empty",
                detail: "\(actions.count) folder action(s) present - review for legitimacy.",
                remediation: "Confirm actions are organization-approved; otherwise remove.",
                evidence: ""
            ),
        ]
    }

    private static func assessLoginHooks(_ events: [EventEnvelope]) -> [Finding] {
        let hooks = events.filter {
            $0.sourcePlugin == "LOGINHOOKS"
                || $0.fields["persistence.kind"] == "login_hook"
                || $0.fields["persistence.kind"] == "logout_hook"
        }
        guard !hooks.isEmpty else { return [] }
        let paths = hooks.compactMap { $0.fields["loginwindow.script_path"] ?? $0.fields["persistence.command"] }
        return [
            Finding(
                control: "login_hook_present",
                status: "fail",
                severity: "high",
                title: "Login/Logout hook configured",
                detail: "loginwindow LoginHook/LogoutHook is set (\(hooks.count) hook(s)) - root-context script at interactive boundary (T1037.002).",
                remediation: "Remove with sudo defaults delete com.apple.loginwindow LoginHook (and LogoutHook). Replace legitimate needs with LaunchDaemon/Agent or MDM. Preserve script path and hash for IR before deletion.",
                evidence: paths.prefix(3).joined(separator: " | ")
            ),
        ]
    }

    private static func assessAccountPosture(_ events: [EventEnvelope]) -> [Finding] {
        var findings: [Finding] = []
        let accounts = events.filter {
            $0.eventType == "ir.posture.account" || $0.fields["account.kind"] != nil
                || $0.fields["account.guest_enabled"] != nil || $0.fields["account.auto_login_enabled"] != nil
                || $0.fields["account.kcpassword_present"] == "true"
        }

        let guestOn = accounts.contains {
            ($0.fields["account.kind"] == "guest" && $0.fields["account.enabled"] == "true")
                || $0.fields["account.guest_enabled"] == "true"
                || $0.fields[FieldTaxonomy.accountGuestEnabled] == "true"
        }
        if guestOn {
            findings.append(Finding(
                control: "guest_account",
                status: "fail",
                severity: "medium",
                title: "Guest account enabled",
                detail: "Guest User login appears enabled.",
                remediation: "Disable Guest User in Users & Groups / via MDM. Guest sessions leave residual risk on shared or stolen devices.",
                evidence: "guest_account_enabled"
            ))
        }

        let autoOn = accounts.contains {
            ($0.fields["account.kind"] == "auto_login" && $0.fields["account.enabled"] == "true")
                || $0.fields["account.auto_login_enabled"] == "true"
                || $0.fields["account.kcpassword_present"] == "true"
                || !($0.fields["account.auto_login_user"] ?? "").isEmpty
        }
        if autoOn {
            let user = accounts.compactMap { $0.fields["account.auto_login_user"] ?? $0.fields[FieldTaxonomy.accountAutoLogin] }.first ?? ""
            findings.append(Finding(
                control: "auto_login",
                status: "fail",
                severity: "high",
                title: "Automatic login enabled",
                detail: "Auto-login appears configured\(user.isEmpty ? "" : " for user \(user)"). kcpassword presence implies credential material at rest (bytes not exported).",
                remediation: "Disable automatic login via System Settings or sysadminctl -autologin off. Treat /etc/kcpassword presence as credential material - collect under custody, do not export password bytes.",
                evidence: user.isEmpty ? "auto_login_enabled" : "autoLoginUser=\(user)"
            ))
        }
        return findings
    }

    private static func assessSoftwareUpdate(_ events: [EventEnvelope]) -> [Finding] {
        var findings: [Finding] = []

        let customCatalog = events.filter {
            $0.fields["su.catalog_non_apple"] == "true"
                || (($0.fields["su.catalog_url"] ?? "").isEmpty == false
                    && !($0.fields["su.catalog_url"] ?? "").contains("apple.com"))
        }
        if let hit = customCatalog.first {
            findings.append(Finding(
                control: "software_update_catalog",
                status: "fail",
                severity: "high",
                title: "Non-Apple software update catalog",
                detail: "Software Update CatalogURL points away from Apple defaults - supply-chain / misconfig risk.",
                remediation: "Reset software update catalog to Apple default (softwareupdate --clear-catalog / remove CatalogURL). Investigate who set the custom catalog (malware, rouge MDM, misconfig).",
                evidence: hit.fields["su.catalog_url"] ?? hit.rawRef ?? ""
            ))
        }

        let autoOff = events.filter {
            ($0.fields["protection.name"] ?? "").lowercased().contains("softwareupdateauto")
                && $0.fields["protection.enabled"] == "false"
        }
        if !autoOff.isEmpty {
            findings.append(Finding(
                control: "software_update_auto",
                status: "fail",
                severity: "medium",
                title: "Automatic software update check disabled",
                detail: "AutomaticCheckEnabled appears off - hosts may miss XProtect/security updates.",
                remediation: "Re-enable automatic security updates and XProtect/config data updates. If deferrals are intentional, document MDM deferral window and enforcement plan.",
                evidence: autoOff.first?.rawRef ?? "AutomaticCheckEnabled=false"
            ))
        }
        return findings
    }

    private static func assessLockdownMode(_ events: [EventEnvelope]) -> [Finding] {
        let ldm = events.filter {
            ($0.fields["protection.name"] ?? "").lowercased().contains("lockdown")
                || $0.fields["lockdown.enabled"] != nil
        }
        guard let hit = ldm.first else { return [] }
        let enabled = hit.fields["lockdown.enabled"] ?? hit.fields["protection.enabled"] ?? "unknown"
        if enabled == "true" {
            return [
                Finding(
                    control: "lockdown_mode",
                    status: "pass",
                    severity: "info",
                    title: "Lockdown Mode enabled",
                    detail: "Lockdown Mode appears enabled for at least one user profile.",
                    remediation: "No action for high-risk personas. Expect app/web feature breakage.",
                    evidence: hit.rawRef ?? ""
                ),
            ]
        }
        if enabled == "false" {
            return [
                Finding(
                    control: "lockdown_mode",
                    status: "warn",
                    severity: "low",
                    title: "Lockdown Mode not enabled",
                    detail: "LDMGlobalEnabled indicates Lockdown Mode is off (persona-dependent; not a fleet-wide fail).",
                    remediation: "Consider Lockdown Mode (Privacy & Security) for high-risk users; expect app/web breakage. Not a fleet-wide mandate.",
                    evidence: hit.rawRef ?? "lockdown_mode=disabled"
                ),
            ]
        }
        return []
    }

    // MARK: - Wave-5 assessments

    private static func assessAuthPlugins(_ events: [EventEnvelope]) -> [Finding] {
        let plugins = events.filter {
            $0.sourcePlugin == "AUTHPLUGINS"
                || $0.fields["persistence.kind"] == "authorization_plugin"
                || $0.fields["persistence.kind"] == "auth_plugin"
        }
        guard !plugins.isEmpty else { return [] }
        let risky = plugins.filter {
            let tags = ($0.fields["persistence.risk_tags"] ?? "").lowercased()
            let name = ($0.fields["auth.plugin_name"] ?? $0.fields["persistence.label"] ?? "").lowercased()
            return !tags.isEmpty
                || tags.contains("unknown_vendor") || tags.contains("unsigned") || tags.contains("tmp_path")
                || name.contains("evil") || name.contains("unknown")
        }
        if !risky.isEmpty {
            let names = risky.prefix(5).compactMap {
                $0.fields["auth.plugin_name"] ?? $0.fields["persistence.label"]
            }.joined(separator: ", ")
            return [
                Finding(
                    control: "auth_plugin_unknown",
                    status: "fail",
                    severity: "high",
                    title: "Unknown or risky authorization plugin",
                    detail: "\(risky.count) SecurityAgent/authorization plugin(s) with unknown_vendor/unsigned/tmp risk or non-default names (of \(plugins.count) total).",
                    remediation: "Inventory Library/Security/SecurityAgentPlugins and authorizationdb rights. Remove unauthorized plugins; prefer Apple/MDM-approved auth stacks only. Preserve plugin path and hash before removal (T1556.001-class).",
                    evidence: names
                ),
            ]
        }
        return [
            Finding(
                control: "auth_plugin_unknown",
                status: "warn",
                severity: "low",
                title: "Authorization plugins present",
                detail: "\(plugins.count) authorization plugin(s) inventoried - review for legitimacy.",
                remediation: "Baseline known SecurityAgent plugins; alert on new bundle IDs or paths outside Apple defaults.",
                evidence: plugins.prefix(3).compactMap { $0.fields["auth.plugin_name"] }.joined(separator: ", ")
            ),
        ]
    }

    private static func assessNetUsage(_ events: [EventEnvelope]) -> [Finding] {
        let usage = events.filter {
            $0.sourcePlugin == "NETUSAGE"
                || $0.eventType == "network.usage"
                || $0.fields["net.usage.process"] != nil
        }
        guard !usage.isEmpty else { return [] }
        let anomalous = usage.filter {
            let tags = ($0.fields["net.risk_tags"] ?? "").lowercased()
            let domain = ($0.fields["net.usage.domain"] ?? "").lowercased()
            let proc = ($0.fields["net.usage.process"] ?? "").lowercased()
            return tags.contains("anomalous_egress") || tags.contains("high_volume")
                || tags.contains("suspicious_process")
                || domain.contains("evil") || proc.contains("evil")
        }
        guard !anomalous.isEmpty else { return [] }
        let sample = anomalous.prefix(3).compactMap {
            let p = $0.fields["net.usage.process"] ?? "?"
            let d = $0.fields["net.usage.domain"] ?? ""
            let b = $0.fields["net.usage.bytes_out"] ?? ""
            return "\(p)→\(d) bytes_out=\(b)"
        }.joined(separator: " | ")
        return [
            Finding(
                control: "netusage_anomalous_egress",
                status: "fail",
                severity: "high",
                title: "Anomalous process network usage / egress",
                detail: "\(anomalous.count) process network-usage row(s) with anomalous_egress, high_volume, or suspicious destination signals.",
                remediation: "Correlate net.usage.process with persistence inventory and codesign. Block unexpected egress via ALF/NE/EDR; capture flow metadata (not full PCAP by default). Investigate C2-like domains and unsigned binaries.",
                evidence: sample
            ),
        ]
    }

    private static func assessCodesign(_ events: [EventEnvelope]) -> [Finding] {
        let assessments = events.filter {
            $0.sourcePlugin == "CODESIGN"
                || $0.eventType == "codesign.assessment"
                || $0.fields["codesign.path"] != nil
        }
        guard !assessments.isEmpty else { return [] }
        let unsigned = assessments.filter {
            let tags = ($0.fields["codesign.risk_tags"] ?? "").lowercased()
            let signed = ($0.fields["codesign.signed"] ?? "").lowercased()
            let notarized = ($0.fields["codesign.notarized"] ?? "").lowercased()
            return tags.contains("unsigned") || tags.contains("not_notarized") || tags.contains("adhoc")
                || signed == "false" || notarized == "false" && tags.contains("unsigned")
        }
        guard !unsigned.isEmpty else { return [] }
        let paths = unsigned.prefix(5).compactMap { $0.fields["codesign.path"] }.joined(separator: ", ")
        return [
            Finding(
                control: "unsigned_persistence_binary",
                status: "fail",
                severity: "high",
                title: "Unsigned or non-notarized persistence binary",
                detail: "\(unsigned.count) codesign assessment(s) on persistence-linked paths report unsigned/ad-hoc/not-notarized.",
                remediation: "Quarantine or remove unauthorized unsigned persistence binaries. Prefer notarized, TeamID-allowlisted software. Re-run CODESIGN inventory after remediation; enforce Gatekeeper and MDM software restrictions.",
                evidence: paths
            ),
        ]
    }

    private static func assessKeychainMeta(_ events: [EventEnvelope]) -> [Finding] {
        let meta = events.filter {
            $0.sourcePlugin == "KEYCHAINMETA"
                || $0.eventType == "keychain.metadata"
                || $0.fields["keychain.label"] != nil
        }
        guard !meta.isEmpty else { return [] }
        let risky = meta.filter {
            let tags = ($0.fields["keychain.risk_tags"] ?? "").lowercased()
            let label = ($0.fields["keychain.label"] ?? "").lowercased()
            let group = ($0.fields["keychain.access_group"] ?? "").lowercased()
            return !tags.isEmpty
                || tags.contains("suspicious") || tags.contains("unexpected") || tags.contains("evil")
                || label.contains("evil") || group.contains("evil")
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let label = $0.fields["keychain.label"] ?? "?"
            let group = $0.fields["keychain.access_group"] ?? ""
            return "\(label) group=\(group)"
        }.joined(separator: " | ")
        return [
            Finding(
                control: "keychain_metadata_anomaly",
                status: "fail",
                severity: "medium",
                title: "Keychain metadata anomaly (no secrets exported)",
                detail: "\(risky.count) keychain metadata row(s) with suspicious labels/access groups or risk tags. Metadata-only - passwords and private keys are never exported.",
                remediation: "Review keychain item class/label/access_group/mtime against app inventory. Delete unexpected items via Keychain Access or security CLI under change control. Do not dump keychain secrets or private keys into SIEM/JSONL (product non-goal).",
                evidence: sample
            ),
        ]
    }

    private static func assessARDAllLocalUsers(_ events: [EventEnvelope]) -> [Finding] {
        let ard = events.filter {
            $0.sourcePlugin == "ARD"
                || $0.eventType == "remote.management"
                || ($0.eventType == "ir.posture.remote_access"
                    && (($0.fields["remote.service"] ?? "").lowercased().contains("ard")
                        || ($0.fields["protection.name"] ?? "").lowercased().contains("remotemanagement")
                        || ($0.fields["protection.name"] ?? "").lowercased().contains("remote management")))
                || $0.fields["ard.all_local_users"] != nil
                || $0.fields["ard.enabled"] != nil
        }
        let allUsers = ard.contains {
            $0.fields["ard.all_local_users"] == "true"
                || ($0.fields["ard.users"] ?? "").lowercased().contains("all")
                || ($0.fields["ard.allow_all_local_users"] == "true")
        }
        // Also fail when RemoteManagement plist path implies ARD_AllLocalUsers via IR posture note
        let postureAll = events.contains {
            ($0.fields["ard.all_local_users"] == "true")
                || (($0.fields["protection.note"] ?? "").contains("ARD_AllLocalUsers")
                    && ($0.fields["protection.enabled"] == "true" || $0.fields["remote.enabled"] == "true"))
        }
        guard allUsers || postureAll else { return [] }
        let evidence = ard.prefix(3).compactMap {
            $0.rawRef ?? $0.fields["protection.marker_path"] ?? $0.fields["remote.service"]
        }.joined(separator: " | ")
        return [
            Finding(
                control: "ard_all_local_users",
                status: "fail",
                severity: "high",
                title: "ARD allows all local users",
                detail: "Apple Remote Desktop / Remote Management is configured with ARD_AllLocalUsers (or equivalent all-local-users access policy).",
                remediation: "Disable ARD_AllLocalUsers in com.apple.RemoteManagement.plist; restrict Remote Management to named admin groups via MDM. Prefer VPN-backed ARD with MFA. Audit who has remote-control rights.",
                evidence: evidence.isEmpty ? "ard.all_local_users=true" : evidence
            ),
        ]
    }

    // MARK: - Wave-6 assessments

    private static func assessTrashSensitive(_ events: [EventEnvelope]) -> [Finding] {
        let trash = events.filter {
            $0.sourcePlugin == "TRASH" || $0.eventType == "filesystem.trash"
        }
        guard !trash.isEmpty else { return [] }
        let risky = trash.filter {
            let tags = ($0.fields["trash.risk_tags"] ?? "").lowercased()
            let name = ($0.fields["trash.filename"] ?? "").lowercased()
            let orig = ($0.fields["trash.original_path"] ?? "").lowercased()
            return tags.contains("credential") || tags.contains("sensitive")
                || tags.contains("executable") || tags.contains("suspicious")
                || name.contains("id_rsa") || name.contains("evil") || name.contains("payload")
                || orig.contains(".ssh/") || orig.contains("password")
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let n = $0.fields["trash.filename"] ?? "?"
            let o = $0.fields["trash.original_path"] ?? ""
            return o.isEmpty ? n : "\(n)←\(o)"
        }.joined(separator: " | ")
        return [
            Finding(
                control: "trash_sensitive_artifact",
                status: "fail",
                severity: "high",
                title: "Sensitive or suspicious artifacts in Trash",
                detail: "\(risky.count) trash item(s) with credential/executable/suspicious risk tags (of \(trash.count) inventoried).",
                remediation: "Preserve Trash contents before emptying (custody). Recover credential material under change control; do not re-export private keys into SIEM. Investigate deleted payloads/executables against persistence inventory and browser downloads.",
                evidence: sample
            ),
        ]
    }

    private static func assessSpotlightSensitive(_ events: [EventEnvelope]) -> [Finding] {
        let items = events.filter {
            $0.sourcePlugin == "SPOTLIGHT" || $0.eventType == "filesystem.spotlight"
        }
        guard !items.isEmpty else { return [] }
        let risky = items.filter {
            let tags = ($0.fields["spotlight.risk_tags"] ?? "").lowercased()
            let path = ($0.fields["spotlight.path"] ?? "").lowercased()
            let name = ($0.fields["spotlight.display_name"] ?? "").lowercased()
            return tags.contains("sensitive") || tags.contains("credential")
                || tags.contains("suspicious")
                || path.contains("password") || name.contains("password")
                || path.contains("evil") || name.contains("payload")
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            $0.fields["spotlight.path"] ?? $0.fields["spotlight.display_name"]
        }.joined(separator: " | ")
        return [
            Finding(
                control: "spotlight_sensitive_index",
                status: "fail",
                severity: "medium",
                title: "Sensitive paths present in Spotlight inventory",
                detail: "\(risky.count) Spotlight index row(s) reference credential-like or suspicious paths.",
                remediation: "Correlate with Trash/QuickLook/DocumentRevisions for recovery. Restrict Spotlight privacy exclusions for highly sensitive volumes via MDM where policy allows. Investigate unexpected DMG/payload paths in Downloads.",
                evidence: sample
            ),
        ]
    }

    private static func assessFirefoxSuspiciousDownload(_ events: [EventEnvelope]) -> [Finding] {
        let firefox = events.filter { $0.sourcePlugin == "FIREFOX" }
        guard !firefox.isEmpty else { return [] }
        let risky = firefox.filter { event in
            let tags = (event.fields["browser.risk_tags"] ?? "").lowercased()
            let url = (event.fields["browser.url"] ?? "").lowercased()
            let path = (event.fields["browser.download_path"] ?? "").lowercased()
            return tags.contains("evil") || tags.contains("script_download") || tags.contains("tmp_path")
                || url.contains("evil") || path.contains("payload") || path.contains("evil")
                || path.hasSuffix(".sh") || path.hasSuffix(".command")
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let u = $0.fields["browser.url"] ?? ""
            let p = $0.fields["browser.download_path"] ?? ""
            return p.isEmpty ? u : "\(u)→\(p)"
        }.joined(separator: " | ")
        return [
            Finding(
                control: "firefox_suspicious_download",
                status: "fail",
                severity: "high",
                title: "Suspicious Firefox download or evil-domain visit",
                detail: "\(risky.count) Firefox browser event(s) with evil_domain/script_download/tmp risk (of \(firefox.count) Firefox rows).",
                remediation: "Quarantine downloaded scripts; correlate with Trash, QuarantineEvents, and persistence. Block evil.example-class domains via DNS/EDR. Prefer Firefox enterprise policies for download restrictions.",
                evidence: sample
            ),
        ]
    }

    private static func assessNotificationSensitive(_ events: [EventEnvelope]) -> [Finding] {
        let notifs = events.filter {
            $0.sourcePlugin == "NOTIFICATIONS" || $0.eventType == "notification.delivered"
        }
        guard !notifs.isEmpty else { return [] }
        let risky = notifs.filter {
            let tags = ($0.fields["notif.risk_tags"] ?? "").lowercased()
            let app = ($0.fields["notif.app_id"] ?? "").lowercased()
            let title = ($0.fields["notif.title_marker"] ?? "").lowercased()
            return tags.contains("suspicious") || tags.contains("security_sensitive")
                || app.contains("evil") || app.contains("implant")
                || title.contains("remote access") || title.contains("password")
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let a = $0.fields["notif.app_id"] ?? "?"
            let t = $0.fields["notif.title_marker"] ?? ""
            return "\(a): \(t)"
        }.joined(separator: " | ")
        return [
            Finding(
                control: "notification_sensitive_marker",
                status: "fail",
                severity: "medium",
                title: "Security-sensitive or suspicious Notification Center markers",
                detail: "\(risky.count) notification metadata row(s) from suspicious apps or security-sensitive titles. Full notification bodies are not exported (privacy non-goal).",
                remediation: "Inventory the delivering app bundle; remove unauthorized apps that post security-like notifications. Correlate with SAVEDSTATE/SCREENTIME for the same bundle_id. Do not dump full notification bodies into SIEM by default.",
                evidence: sample
            ),
        ]
    }

    private static func assessQuickLookSensitive(_ events: [EventEnvelope]) -> [Finding] {
        let ql = events.filter {
            $0.sourcePlugin == "QUICKLOOK" || $0.eventType == "filesystem.quicklook"
        }
        guard !ql.isEmpty else { return [] }
        let risky = ql.filter {
            let tags = ($0.fields["ql.risk_tags"] ?? "").lowercased()
            let path = ($0.fields["ql.path"] ?? "").lowercased()
            return tags.contains("sensitive") || tags.contains("credential")
                || tags.contains("suspicious")
                || path.contains("password") || path.contains("secret") || path.contains("evil")
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap { $0.fields["ql.path"] }.joined(separator: " | ")
        return [
            Finding(
                control: "quicklook_sensitive_cache",
                status: "fail",
                severity: "medium",
                title: "Sensitive paths in QuickLook thumbnail cache",
                detail: "\(risky.count) QuickLook cache row(s) reference credential-like or suspicious files (files may have been previewed even if later deleted).",
                remediation: "Preserve QL cache before wipe. Correlate with Trash/Spotlight/DocumentRevisions. Investigate who previewed credential files; rotate secrets if exfil is suspected.",
                evidence: sample
            ),
        ]
    }

    private static func assessScreenTimeSuspicious(_ events: [EventEnvelope]) -> [Finding] {
        let st = events.filter {
            $0.sourcePlugin == "SCREENTIME"
                && ($0.eventType == "pol.screentime" || $0.fields["screentime.app_id"] != nil)
        }
        guard !st.isEmpty else { return [] }
        let risky = st.filter {
            let tags = ($0.fields["screentime.risk_tags"] ?? "").lowercased()
            let app = ($0.fields["screentime.app_id"] ?? "").lowercased()
            let path = ($0.fields["screentime.bundle_path"] ?? "").lowercased()
            return tags.contains("suspicious") || tags.contains("tmp_path")
                || app.contains("evil") || app.contains("implant")
                || path.contains("/tmp/")
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let a = $0.fields["screentime.app_id"] ?? "?"
            let u = $0.fields["screentime.usage_seconds"] ?? ""
            return "\(a) usage=\(u)s"
        }.joined(separator: " | ")
        return [
            Finding(
                control: "screentime_suspicious_app",
                status: "fail",
                severity: "high",
                title: "Suspicious app usage in Screen Time markers",
                detail: "\(risky.count) Screen Time app row(s) with suspicious_app/tmp_path risk. Metadata only - no private activity content dump.",
                remediation: "Remove unauthorized bundles under /tmp. Correlate with SAVEDSTATE, NOTIFICATIONS, and persistence inventory for the same bundle_id. Enforce app allowlisting (Santa) for non-App-Store executables.",
                evidence: sample
            ),
        ]
    }

    private static func assessICloudDesktopDocuments(_ events: [EventEnvelope]) -> [Finding] {
        let cloud = events.filter {
            $0.sourcePlugin == "ICLOUD" || $0.eventType == "cloud.sync_posture"
        }
        guard !cloud.isEmpty else { return [] }
        let risky = cloud.filter {
            $0.fields["icloud.desktop_documents_sync"] == "true"
                || ($0.fields["icloud.risk_tags"] ?? "").contains("desktop_documents_sync")
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(2).compactMap {
            let u = $0.fields["icloud.signed_in_user"] ?? ""
            let d = $0.fields["icloud.drive_enabled"] ?? ""
            return "user=\(u) drive=\(d) desktop_docs=true"
        }.joined(separator: " | ")
        return [
            Finding(
                control: "icloud_desktop_documents_sync",
                status: "fail",
                severity: "medium",
                title: "iCloud Desktop & Documents sync enabled",
                detail: "iCloud Desktop and Documents folder sync is enabled - potential bulk data staging/exfil path and dual-device evidence split.",
                remediation: "For high-sensitivity hosts, disable Desktop & Documents via MDM configuration profile. Inventory CloudDocs leftovers; correlate with Drive enablement and recent large uploads. Document account presence without exporting full Apple ID secrets.",
                evidence: sample
            ),
        ]
    }

    private static func assessSavedStateSuspicious(_ events: [EventEnvelope]) -> [Finding] {
        let states = events.filter {
            $0.sourcePlugin == "SAVEDSTATE" || $0.eventType == "app.saved_state"
        }
        guard !states.isEmpty else { return [] }
        let risky = states.filter {
            let tags = ($0.fields["savedstate.risk_tags"] ?? "").lowercased()
            let bid = ($0.fields["savedstate.bundle_id"] ?? "").lowercased()
            let app = ($0.fields["savedstate.app_path"] ?? "").lowercased()
            return tags.contains("suspicious") || tags.contains("tmp_path")
                || bid.contains("evil") || bid.contains("implant")
                || app.contains("/tmp/")
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            $0.fields["savedstate.bundle_id"] ?? $0.fields["savedstate.path"]
        }.joined(separator: " | ")
        return [
            Finding(
                control: "saved_state_suspicious_app",
                status: "fail",
                severity: "medium",
                title: "Suspicious Saved Application State",
                detail: "\(risky.count) Saved Application State row(s) for suspicious/tmp-backed apps.",
                remediation: "Remove unauthorized .savedState directories after custody copy. Correlate bundle_id with Screen Time, notifications, and persistence. Block tmp-path app execution via Santa/MDM.",
                evidence: sample
            ),
        ]
    }

    // MARK: - Wave-7 assessments

    private static func assessCookieEvilDomain(_ events: [EventEnvelope]) -> [Finding] {
        let cookies = events.filter {
            $0.sourcePlugin == "COOKIES" || $0.eventType == "browser.cookie"
        }
        guard !cookies.isEmpty else { return [] }
        let risky = cookies.filter {
            let tags = ($0.fields["cookie.risk_tags"] ?? "").lowercased()
            let domain = ($0.fields["cookie.domain"] ?? "").lowercased()
            return tags.contains("evil_domain") || tags.contains("suspicious_domain")
                || domain.contains("evil") || domain.contains("malware") || domain.contains("c2.")
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let d = $0.fields["cookie.domain"] ?? "?"
            let n = $0.fields["cookie.name_marker"] ?? ""
            return n.isEmpty ? d : "\(d)/\(n)"
        }.joined(separator: " | ")
        return [
            Finding(
                control: "cookie_evil_domain",
                status: "fail",
                severity: "high",
                title: "Browser cookies for evil or suspicious domains",
                detail: "\(risky.count) cookie domain row(s) with evil_domain/suspicious_domain risk (of \(cookies.count) inventoried). Raw cookie values are not exported.",
                remediation: "Clear browser cookies for listed domains under custody. Force re-auth for enterprise SSO sessions. Block evil.example-class domains via DNS/EDR. Correlate with COOKIES + BOOKMARKS + browser history. Do not export raw session cookie values into SIEM.",
                evidence: sample
            ),
        ]
    }

    private static func assessBookmarkEvilDomain(_ events: [EventEnvelope]) -> [Finding] {
        let bookmarks = events.filter {
            $0.sourcePlugin == "BOOKMARKS" || $0.eventType == "browser.bookmark"
        }
        guard !bookmarks.isEmpty else { return [] }
        let risky = bookmarks.filter {
            let tags = ($0.fields["bookmark.risk_tags"] ?? "").lowercased()
            let url = ($0.fields["bookmark.url"] ?? "").lowercased()
            return tags.contains("evil_domain") || tags.contains("suspicious_domain")
                || tags.contains("script_bookmark")
                || url.contains("evil") || url.contains("malware")
                || url.hasPrefix("javascript:")
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            $0.fields["bookmark.url"] ?? $0.fields["bookmark.title"]
        }.joined(separator: " | ")
        return [
            Finding(
                control: "bookmark_evil_domain",
                status: "fail",
                severity: "medium",
                title: "Browser bookmarks pointing to evil or suspicious URLs",
                detail: "\(risky.count) bookmark(s) with evil_domain/suspicious/script risk tags.",
                remediation: "Remove malicious bookmarks; educate user on phishing bookmarking. Correlate with cookie domains and download history. Block listed domains fleet-wide.",
                evidence: sample
            ),
        ]
    }

    private static func assessOfficeMRUSensitive(_ events: [EventEnvelope]) -> [Finding] {
        let mru = events.filter {
            $0.sourcePlugin == "OFFICEMRU" || $0.eventType == "mru.office"
        }
        guard !mru.isEmpty else { return [] }
        let risky = mru.filter {
            let tags = ($0.fields["office.risk_tags"] ?? "").lowercased()
            let path = ($0.fields["office.path"] ?? "").lowercased()
            let title = ($0.fields["office.title"] ?? "").lowercased()
            return tags.contains("sensitive") || tags.contains("tmp_path")
                || tags.contains("suspicious")
                || path.contains("/tmp/") || path.contains("password")
                || path.contains("evil") || title.contains("password")
                || title.contains("secret")
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let a = $0.fields["office.app"] ?? "?"
            let p = $0.fields["office.path"] ?? $0.fields["office.title"] ?? ""
            return "\(a): \(p)"
        }.joined(separator: " | ")
        return [
            Finding(
                control: "office_mru_sensitive",
                status: "fail",
                severity: "medium",
                title: "Sensitive or suspicious Office/collaboration MRU entries",
                detail: "\(risky.count) Office/Teams/Slack MRU row(s) reference sensitive, tmp, or suspicious documents.",
                remediation: "Preserve MRU lists before wipe. Investigate tmp-path and credential-named documents. Correlate with cloud sync (CLOUDSYNC/ICLOUD) and print jobs. Restrict Office macro policies via MDM.",
                evidence: sample
            ),
        ]
    }

    private static func assessPrintSensitiveJob(_ events: [EventEnvelope]) -> [Finding] {
        let jobs = events.filter {
            $0.sourcePlugin == "PRINTJOBS" || $0.eventType == "print.job"
        }
        guard !jobs.isEmpty else { return [] }
        let risky = jobs.filter {
            let tags = ($0.fields["print.risk_tags"] ?? "").lowercased()
            let doc = ($0.fields["print.document"] ?? "").lowercased()
            return tags.contains("sensitive") || tags.contains("suspicious")
                || doc.contains("password") || doc.contains("secret")
                || doc.contains("payroll") || doc.contains("credential")
                || doc.contains("evil")
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let d = $0.fields["print.document"] ?? "?"
            let p = $0.fields["print.printer"] ?? ""
            return p.isEmpty ? d : "\(d)@\(p)"
        }.joined(separator: " | ")
        return [
            Finding(
                control: "print_sensitive_job",
                status: "fail",
                severity: "medium",
                title: "Sensitive documents in print job history",
                detail: "\(risky.count) print job(s) with sensitive/suspicious document names (of \(jobs.count) inventoried).",
                remediation: "Preserve CUPS job history. Interview user and correlate with physical access. Disable unnecessary remote printers. Treat payroll/credential prints as potential data leakage.",
                evidence: sample
            ),
        ]
    }

    private static func assessNotesSensitiveMarker(_ events: [EventEnvelope]) -> [Finding] {
        let notes = events.filter {
            $0.sourcePlugin == "NOTES" || $0.eventType == "notes.metadata"
        }
        guard !notes.isEmpty else { return [] }
        let risky = notes.filter {
            let tags = ($0.fields["notes.risk_tags"] ?? "").lowercased()
            let title = ($0.fields["notes.title_marker"] ?? "").lowercased()
            return tags.contains("sensitive") || tags.contains("suspicious")
                || title.contains("password") || title.contains("credential")
                || title.contains("secret") || title.contains("api key")
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            $0.fields["notes.title_marker"]
        }.joined(separator: " | ")
        return [
            Finding(
                control: "notes_sensitive_marker",
                status: "fail",
                severity: "medium",
                title: "Sensitive title markers in Apple Notes metadata",
                detail: "\(risky.count) Notes metadata row(s) with credential-like titles. Full note bodies are not exported (privacy non-goal).",
                remediation: "Acquire full Notes content only under legal authority with a dedicated tool. Rotate any credentials implied by titles. Prefer password managers over Notes for secrets. Do not dump note bodies into SIEM by default.",
                evidence: sample
            ),
        ]
    }

    private static func assessIDeviceBackupUnencrypted(_ events: [EventEnvelope]) -> [Finding] {
        let backups = events.filter {
            $0.sourcePlugin == "IDEVICEBACKUP" || $0.eventType == "backup.idevice"
        }
        guard !backups.isEmpty else { return [] }
        let risky = backups.filter {
            $0.fields["backup.encrypted"] == "false"
                || ($0.fields["backup.risk_tags"] ?? "").contains("unencrypted_backup")
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let n = $0.fields["backup.device_name"] ?? "?"
            let e = $0.fields["backup.encrypted"] ?? "?"
            return "\(n) encrypted=\(e)"
        }.joined(separator: " | ")
        return [
            Finding(
                control: "idevice_backup_unencrypted",
                status: "fail",
                severity: "high",
                title: "Unencrypted iDevice backup present",
                detail: "\(risky.count) iDevice backup marker(s) report encryption disabled - full device content may be readable offline.",
                remediation: "Enable encrypted backups (Finder/iTunes) with a strong password under custody. Inventory backup paths; restrict access ACLs. For IR, image encrypted backups with consent rather than leaving unencrypted copies on disk.",
                evidence: sample
            ),
        ]
    }

    private static func assessMSRDCRemoteConnection(_ events: [EventEnvelope]) -> [Finding] {
        let rdp = events.filter {
            $0.sourcePlugin == "MSRDC" || $0.eventType == "remote.rdp_connection"
        }
        guard !rdp.isEmpty else { return [] }
        let risky = rdp.filter {
            let tags = ($0.fields["rdp.risk_tags"] ?? "").lowercased()
            let host = ($0.fields["rdp.host"] ?? "").lowercased()
            return tags.contains("remote_connection") || tags.contains("suspicious_host")
                || tags.contains("external_host")
                || host.contains("evil") || host.contains("c2")
                || !host.isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let h = $0.fields["rdp.host"] ?? "?"
            let u = $0.fields["rdp.user"] ?? ""
            return u.isEmpty ? h : "\(u)@\(h)"
        }.joined(separator: " | ")
        return [
            Finding(
                control: "msrdc_remote_connection",
                status: "fail",
                severity: "medium",
                title: "Remote desktop client connection history present",
                detail: "\(risky.count) MSRDC/RDP client connection(s) inventoried - lateral movement / remote-access residue.",
                remediation: "Validate each host against asset inventory. Remove unauthorized RDP clients (MSRDC). Correlate with ARD/SSH remote access posture. Block unexpected egress to :3389 via host firewall/MDM.",
                evidence: sample
            ),
        ]
    }

    private static func assessCloudSyncExfilProvider(_ events: [EventEnvelope]) -> [Finding] {
        let cloud = events.filter {
            $0.sourcePlugin == "CLOUDSYNC" || $0.eventType == "cloud.provider_sync"
        }
        guard !cloud.isEmpty else { return [] }
        let risky = cloud.filter {
            let tags = ($0.fields["cloud.risk_tags"] ?? "").lowercased()
            let enabled = $0.fields["cloud.sync_enabled"] == "true"
            let provider = ($0.fields["cloud.provider"] ?? "").lowercased()
            return enabled
                && (tags.contains("exfil_capable") || tags.contains("sync_enabled")
                    || ["dropbox", "onedrive", "google_drive", "gdrive", "box", "mega"]
                    .contains(provider))
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let p = $0.fields["cloud.provider"] ?? "?"
            let a = $0.fields["cloud.account_marker"] ?? ""
            let f = $0.fields["cloud.folder_path"] ?? ""
            return "\(p) \(a) \(f)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [
            Finding(
                control: "cloudsync_exfil_provider",
                status: "fail",
                severity: "medium",
                title: "Third-party cloud sync provider enabled",
                detail: "\(risky.count) multi-provider cloud sync row(s) enabled (Dropbox/OneDrive/GDrive/Box class) - bulk staging/exfil surface beyond iCloud.",
                remediation: "Inventory authorized cloud providers via MDM allowlist. Disable unauthorized Dropbox/OneDrive/GDrive/Box clients. Correlate with ICLOUD Desktop&Documents and Office MRU cloud docs. Monitor large uploads via EDR/NE.",
                evidence: sample
            ),
        ]
    }

    // MARK: - Wave-8 residual red↔blue pair assessments

    private static func assessPackageKitInstallerDesign(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "PACKAGEKITDESIGN" || $0.eventType == "packagekit.design"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["packagekit.risk_tags"] ?? "").lowercased()
            let service = $0.fields["packagekit.service_present"] == "true"
            let receipts = $0.fields["packagekit.receipt_paths"] ?? ""
            let hasReceipts = !receipts.isEmpty && receipts != "0"
            return tags.contains("design_surface")
                || (service && hasReceipts)
                || tags.contains("installer_service")
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let svc = $0.fields["packagekit.service_present"] ?? "?"
            let tags = $0.fields["packagekit.risk_tags"] ?? ""
            let notes = $0.fields["packagekit.notes"] ?? ""
            return "service=\(svc) tags=\(tags) \(notes)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [
            Finding(
                control: "packagekit_installer_design",
                status: "fail",
                severity: "medium",
                title: "PackageKit installer design surface present",
                detail: "\(risky.count) PackageKit design-surface marker(s) - installer services/receipts/plugins inventory for design-based persistence IR. Path presence only; does not build packages.",
                remediation: "Inventory InstallHistory and /var/db/receipts for unexpected package identifiers. Review Installer Plugins directories for non-Apple plugins. Correlate package_script_service / installd activity with ESF if available. Restrict ad-hoc package installs via policy; do not run untrusted pkgs. Assessment guidance only - not MDM enforcement.",
                evidence: sample
            ),
        ]
    }

    private static func assessArchiveQuarantineExtractor(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "ARCHIVEEXTRACTOR" || $0.eventType == "archive.extractor"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["archive.risk_tags"] ?? "").lowercased()
            let third = $0.fields["archive.third_party"] == "true"
            return third
                || tags.contains("third_party_extractor")
                || tags.contains("quarantine_non_inherit")
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let n = $0.fields["archive.extractor_name"] ?? "?"
            let p = $0.fields["archive.extractor_path"] ?? ""
            let d = $0.fields["archive.drop_hint"] ?? ""
            return "\(n) \(p) drop=\(d)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        let severity = risky.contains {
            ($0.fields["archive.risk_tags"] ?? "").contains("quarantine_non_inherit")
        } ? "high" : "medium"
        return [
            Finding(
                control: "archive_quarantine_extractor",
                status: "fail",
                severity: severity,
                title: "Third-party archive extractor (quarantine non-inherit risk)",
                detail: "\(risky.count) third-party archive extractor(s) - extracted payloads may not inherit com.apple.quarantine (Unit 42 / Jamf class research).",
                remediation: "Prefer stock Archive Utility for untrusted archives. Inventory Keka/The Unarchiver/BetterZip-class tools. After third-party extraction, re-apply quarantine or scan drop folders (Downloads/Desktop/tmp). Correlate with QuarantineEvents and Gatekeeper history. Operator assessment only - not automated quarantine strip/rewrite.",
                evidence: sample
            ),
        ]
    }

    private static func assessInfoStealerPathPlane(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "INFOSTEALERPATH" || $0.eventType == "stealer.path"
        }
        guard !rows.isEmpty else { return [] }
        let families = Set(rows.compactMap { $0.fields["stealer.path_family"] })
        let multiApp = families.count >= 2
            || rows.contains {
                ($0.fields["stealer.risk_tags"] ?? "").lowercased().contains("multi_app_collection")
            }
        let fdaAdj = rows.contains { $0.fields["stealer.fda_adjacent"] == "true" }
        let risky = rows.filter {
            let tags = ($0.fields["stealer.risk_tags"] ?? "").lowercased()
            let tagCount = tags.split(separator: ",").filter { !$0.isEmpty }.count
            return tags.contains("multi_app_collection")
                || $0.fields["stealer.fda_adjacent"] == "true"
                || tagCount >= 2
                || multiApp
        }
        guard multiApp || !risky.isEmpty else { return [] }
        let sample = rows.prefix(5).compactMap {
            let f = $0.fields["stealer.path_family"] ?? "?"
            let p = $0.fields["stealer.path"] ?? ""
            return "\(f):\(p)"
        }.joined(separator: " | ")
        // Never include secret material in evidence/detail
        let safeEvidence = sample
            .replacingOccurrences(of: "password", with: "path", options: .caseInsensitive)
        return [
            Finding(
                control: "infostealer_path_plane",
                status: "fail",
                severity: (multiApp && fdaAdj) ? "high" : "medium",
                title: "Info-stealer multi-app path plane exposed",
                detail: "\(rows.count) stealer-path marker(s) across \(families.count) family(ies) (browser/messaging/vault/wallet/sync). Path presence only - secrets not exported.",
                remediation: "Harden FDA grants; review TCC for unexpected full-disk accessors. Enable FileVault; restrict browser/password-manager backup paths. Monitor multi-family file access via EDR/ESF. Rotate credentials if stealer activity suspected. Do not dump cookies, passwords, keychains, or wallet seeds into case exports.",
                evidence: safeEvidence
            ),
        ]
    }

    private static func assessTCCESFVisibilityDepth(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "TCCESFVISIBILITY" || $0.eventType == "tcc_esf.visibility"
        }
        guard !rows.isEmpty else { return [] }
        let thinOrPartial = rows.filter {
            let depth = ($0.fields["visibility.depth"] ?? "").lowercased()
            let tags = ($0.fields["visibility.risk_tags"] ?? "").lowercased()
            return depth == "thin"
                || tags.contains("thin_visibility")
                || tags.contains("sensor_gap_adjacent")
                || depth == "partial"
        }
        guard !thinOrPartial.isEmpty else { return [] }
        let worstThin = thinOrPartial.contains {
            let d = ($0.fields["visibility.depth"] ?? "").lowercased()
            let tags = ($0.fields["visibility.risk_tags"] ?? "").lowercased()
            return d == "thin" || tags.contains("thin_visibility")
        }
        let sample = thinOrPartial.prefix(3).compactMap {
            let d = $0.fields["visibility.depth"] ?? "?"
            let t = $0.fields["visibility.tool_path"] ?? ""
            let listable = $0.fields["visibility.tcc_path_listable"] ?? "?"
            return "depth=\(d) tcc_listable=\(listable) tool=\(t)"
        }.joined(separator: " | ")
        return [
            Finding(
                control: "tcc_esf_visibility_depth",
                status: worstThin ? "fail" : "warn",
                severity: worstThin ? "high" : "medium",
                title: worstThin
                    ? "TCC/ESF operator visibility is thin"
                    : "TCC/ESF operator visibility is only partial",
                detail: "\(thinOrPartial.count) visibility-depth marker(s) indicate limited TCC path listability and/or missing ESF/eslogger tooling - sensor gap for grant and process telemetry IR.",
                remediation: "Ensure IR tooling can list TCC.db paths (with proper authorization). Deploy ESF-capable sensor or eslogger where ROE allows. Document visibility depth in IR runbooks. Prefer EDR that surfaces TCC grant changes. Do not dump raw TCC.db rows into unsecured exports; assess depth only.",
                evidence: sample
            ),
        ]
    }

    // MARK: - Wave-11 multi-plane red↔blue pair assessments

    private static func assessURLSchemeHandler(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "URLSCHEMEHANDLER" || $0.eventType == "url_scheme.handler"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["url_scheme.risk_tags"] ?? "").lowercased()
            return tags.contains("handler_surface")
                || tags.contains("third_party_handler")
                || tags.contains("custom_scheme")
                || !($0.fields["url_scheme.handler_path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["url_scheme.handler_path"] ?? ""
            let scheme = $0.fields["url_scheme.scheme"] ?? ""
            let tags = $0.fields["url_scheme.risk_tags"] ?? ""
            return "scheme=\(scheme) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [
            Finding(
                control: "url_scheme_handler",
                status: "fail",
                severity: "medium",
                title: "URL scheme / document-handler surface present",
                detail: "\(risky.count) URL scheme/document-handler marker(s) - LaunchServices / custom scheme delivery IR surface. Path presence only; does not register schemes.",
                remediation: "Inventory non-default CFBundleURLTypes and LaunchServices handlers after software installs. Restrict untrusted apps that register custom URL schemes via MDM allowlists. Correlate handler changes with phishing delivery. Do not rewrite handlers from IR tooling without change control.",
                evidence: sample
            ),
        ]
    }

    private static func assessLaunchdOverrideDepth(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "LAUNCHDOVERRIDEDEPTH" || $0.eventType == "launchd.override_depth"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["launchd_depth.risk_tags"] ?? "").lowercased()
            let sec = $0.fields["launchd_depth.security_product_hint"] == "true"
            return sec
                || tags.contains("security_product_disabled")
                || tags.contains("override_depth")
        }
        guard !risky.isEmpty else { return [] }
        let securityHit = risky.contains {
            $0.fields["launchd_depth.security_product_hint"] == "true"
                || ($0.fields["launchd_depth.risk_tags"] ?? "").contains("security_product_disabled")
        }
        let sample = risky.prefix(4).compactMap {
            let label = $0.fields["launchd_depth.label"] ?? "?"
            let path = $0.fields["launchd_depth.override_path"] ?? ""
            return "\(label) @ \(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [
            Finding(
                control: "launchd_override_depth",
                status: "fail",
                severity: securityHit ? "high" : "medium",
                title: securityHit
                    ? "Launchd override depth shows security-product disable hints"
                    : "Launchd disabled / override depth surface present",
                detail: "\(risky.count) launchd override-depth marker(s) - disabled.plist / overrides inventory for defense-evasion IR. Does not disable jobs.",
                remediation: "Audit /var/db/com.apple.xpc.launchd/disabled*.plist for unexpected Santa/Falcon/osquery/Jamf labels. Alert on launchctl disable of security products via ESF/MDM. Restore disabled security agents via approved change control. Assessment guidance only - not an unload toolkit.",
                evidence: sample
            ),
        ]
    }

    private static func assessBrowserExtensionDualUse(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "BROWSEREXTDUALUSE" || $0.eventType == "browser.extension_dualuse"
        }
        guard !rows.isEmpty else { return [] }
        let browsers = Set(rows.compactMap { $0.fields["ext_dualuse.browser"] })
        let risky = rows.filter {
            let tags = ($0.fields["ext_dualuse.risk_tags"] ?? "").lowercased()
            return tags.contains("dual_use_surface")
                || tags.contains("broad_permissions")
                || tags.contains("fda_adjacent")
        }
        guard !risky.isEmpty || browsers.count >= 2 else { return [] }
        let sample = rows.prefix(5).compactMap {
            let browser = $0.fields["ext_dualuse.browser"] ?? "?"
            let path = $0.fields["ext_dualuse.path"] ?? ""
            let extID = $0.fields["ext_dualuse.extension_id"] ?? ""
            return "\(browser):\(extID.isEmpty ? path : extID)"
        }.joined(separator: " | ")
        let safe = sample.replacingOccurrences(of: "password", with: "path", options: .caseInsensitive)
        let broad = risky.contains {
            ($0.fields["ext_dualuse.risk_tags"] ?? "").contains("broad_permissions")
        }
        return [
            Finding(
                control: "browser_extension_dualuse",
                status: "fail",
                severity: (browsers.count >= 2 || broad) ? "high" : "medium",
                title: "Browser extension dual-use persistence/collection plane",
                detail: "\(rows.count) browser-extension dual-use marker(s) across \(browsers.count) browser(s). Path/meta only - secrets not exported.",
                remediation: "Enforce enterprise extension allowlists via MDM/Chrome enterprise policy. Remove unapproved extensions; monitor Secure Preferences changes. Correlate extension installs with phishing. Do not export extension storage, cookies, or tokens into case packages.",
                evidence: safe
            ),
        ]
    }

    private static func assessShortcutsAppIntents(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "SHORTCUTSAPPINTENTS" || $0.eventType == "shortcuts.automation"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["shortcuts.risk_tags"] ?? "").lowercased()
            return tags.contains("automation_surface")
                || tags.contains("scripting_action")
                || tags.contains("remote_adjacent")
                || !($0.fields["shortcuts.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let scripting = risky.contains {
            ($0.fields["shortcuts.risk_tags"] ?? "").contains("scripting_action")
        }
        let sample = risky.prefix(4).compactMap {
            let name = $0.fields["shortcuts.name"] ?? "?"
            let path = $0.fields["shortcuts.path"] ?? ""
            return "\(name) \(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [
            Finding(
                control: "shortcuts_app_intents",
                status: "fail",
                severity: scripting ? "high" : "medium",
                title: scripting
                    ? "Shortcuts / App Intents automation with scripting risk"
                    : "Shortcuts / App Intents automation surface present",
                detail: "\(risky.count) Shortcuts/App Intents marker(s) - automation lateral IR surface. Does not execute shortcuts.",
                remediation: "Review personal automations and shared Shortcuts for shell/scripting actions. Restrict Shortcuts network/scripting via MDM where available. Correlate Shortcuts database changes with delivery timelines. Do not run untrusted Shortcuts during IR without sandboxing.",
                evidence: sample
            ),
        ]
    }
    // MARK: - Wave-12 multi-plane red↔blue pair assessments

    private static func assessWeblocInetloc(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "WEBLOCINETLOC" || $0.eventType == "webloc.delivery"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["webloc.risk_tags"] ?? "").lowercased()
            return tags.contains("delivery_surface")
                || !($0.fields["webloc.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["webloc.path"] ?? ""
            let name = $0.fields["webloc.name"] ?? ""
            let tags = $0.fields["webloc.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [
            Finding(
                control: "webloc_inetloc_delivery",
                status: "fail",
                severity: "medium",
                title: "Webloc / Internet Location file delivery surface present",
                detail: "\(risky.count) Webloc/inetloc delivery marker(s) - IR surface. Path/meta only; never crafts phishing webloc/inetloc payloads or rewrites Internet Location files.",
                remediation: "Inventory and baseline Webloc/inetloc delivery artifacts. Correlate unexpected markers with delivery or lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
                evidence: sample
            ),
        ]
    }


    private static func assessMailRulesAutomation(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "MAILRULESAUTO" || $0.eventType == "mail.rules"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["mail_rules.risk_tags"] ?? "").lowercased()
            return tags.contains("rules_surface")
                || !($0.fields["mail_rules.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["mail_rules.path"] ?? ""
            let name = $0.fields["mail_rules.name"] ?? ""
            let tags = $0.fields["mail_rules.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [
            Finding(
                control: "mail_rules_automation",
                status: "fail",
                severity: "medium",
                title: "Mail rules / Apple Mail automation persistence surface present",
                detail: "\(risky.count) Mail rules automation marker(s) - IR surface. Path/meta only; never reads Mail contents or modifies user Mail rules.",
                remediation: "Inventory and baseline Mail rules automation artifacts. Correlate unexpected markers with delivery or lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
                evidence: sample
            ),
        ]
    }


    private static func assessUnifiedLogObservation(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "UNIFIEDLOGOBS" || $0.eventType == "unified_log.observation"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["ulog.risk_tags"] ?? "").lowercased()
            return tags.contains("observation_surface")
                || !($0.fields["ulog.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["ulog.path"] ?? ""
            let name = $0.fields["ulog.name"] ?? ""
            let tags = $0.fields["ulog.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [
            Finding(
                control: "unified_log_observation",
                status: "fail",
                severity: "medium",
                title: "Unified log / logarchive observation depth surface present",
                detail: "\(risky.count) Unified log observation marker(s) - IR surface. Path/meta only; never dumps private unified-log message bodies or force-collects other users' logarchives.",
                remediation: "Inventory and baseline Unified log observation artifacts. Correlate unexpected markers with delivery or lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
                evidence: sample
            ),
        ]
    }


    private static func assessDockPersistenceSurface(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "DOCKPERSIST" || $0.eventType == "dock.persistence"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["dock.risk_tags"] ?? "").lowercased()
            return tags.contains("dock_surface")
                || !($0.fields["dock.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["dock.path"] ?? ""
            let name = $0.fields["dock.name"] ?? ""
            let tags = $0.fields["dock.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [
            Finding(
                control: "dock_persistence_surface",
                status: "fail",
                severity: "medium",
                title: "Dock persistent apps / recent items dual-use surface present",
                detail: "\(risky.count) Dock persistence dual-use marker(s) - IR surface. Path/meta only; never modifies Dock.plist or plants malicious Dock entries.",
                remediation: "Inventory and baseline Dock persistence dual-use artifacts. Correlate unexpected markers with delivery or lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
                evidence: sample
            ),
        ]
    }


    private static func assessOsascriptScptDelivery(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "OSASCRIPTSCPT" || $0.eventType == "osascript.scpt"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["osa.risk_tags"] ?? "").lowercased()
            return tags.contains("scpt_surface")
                || !($0.fields["osa.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["osa.path"] ?? ""
            let name = $0.fields["osa.name"] ?? ""
            let tags = $0.fields["osa.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [
            Finding(
                control: "osascript_scpt_delivery",
                status: "fail",
                severity: "medium",
                title: "Compiled AppleScript / OSA delivery residual surface present",
                detail: "\(risky.count) OSA/scpt delivery marker(s) - IR surface. Path/meta only; never compiles malicious .scpt payloads or executes third-party AppleScripts.",
                remediation: "Inventory and baseline OSA/scpt delivery artifacts. Correlate unexpected markers with delivery or lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
                evidence: sample
            ),
        ]
    }


    private static func assessNetworkShareMount(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "NETWORKSHAREMOUNT" || $0.eventType == "network.share_mount"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["share.risk_tags"] ?? "").lowercased()
            return tags.contains("share_surface")
                || !($0.fields["share.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["share.path"] ?? ""
            let name = $0.fields["share.name"] ?? ""
            let tags = $0.fields["share.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [
            Finding(
                control: "network_share_mount",
                status: "fail",
                severity: "medium",
                title: "Network share / SMB mount dual-use lateral surface present",
                detail: "\(risky.count) Network share mount marker(s) - IR surface. Path/meta only; never mounts attacker shares or writes credentials to NetAuth.",
                remediation: "Inventory and baseline Network share mount artifacts. Correlate unexpected markers with delivery or lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
                evidence: sample
            ),
        ]
    }
    // MARK: - Wave-13 multi-plane red↔blue pair assessments

    private static func assessCalendarRemindersAutomation(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "CALENDARREMINDERS" || $0.eventType == "calendar.reminders"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["calrem.risk_tags"] ?? "").lowercased()
            return tags.contains("automation_surface") || !($0.fields["calrem.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["calrem.path"] ?? ""
            let name = $0.fields["calrem.name"] ?? ""
            let tags = $0.fields["calrem.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "calendar_reminders_automation", status: "fail", severity: "medium",
            title: "Calendar / Reminders automation lateral surface surface present",
            detail: "\(risky.count) Calendar/Reminders automation marker(s) - IR surface. Path/meta only; never reads event contents or creates malicious calendar invites.",
            remediation: "Inventory and baseline Calendar/Reminders automation artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    private static func assessGatekeeperAssessmentHistory(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "GKASSESSMENTHIST" || $0.eventType == "gatekeeper.assessment"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["gkh.risk_tags"] ?? "").lowercased()
            return tags.contains("assessment_surface") || !($0.fields["gkh.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["gkh.path"] ?? ""
            let name = $0.fields["gkh.name"] ?? ""
            let tags = $0.fields["gkh.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "gatekeeper_assessment_history", status: "fail", severity: "medium",
            title: "Gatekeeper assessment / syspolicyd history depth surface present",
            detail: "\(risky.count) Gatekeeper assessment history marker(s) - IR surface. Path/meta only; never clears Gatekeeper assessments or disables syspolicyd.",
            remediation: "Inventory and baseline Gatekeeper assessment history artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    private static func assessHomebrewPackageDualUse(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "HOMEBREWPKG" || $0.eventType == "homebrew.package"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["brew.risk_tags"] ?? "").lowercased()
            return tags.contains("package_surface") || !($0.fields["brew.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["brew.path"] ?? ""
            let name = $0.fields["brew.name"] ?? ""
            let tags = $0.fields["brew.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "homebrew_package_dualuse", status: "fail", severity: "medium",
            title: "Homebrew / third-party package manager dual-use surface present",
            detail: "\(risky.count) Homebrew package dual-use marker(s) - IR surface. Path/meta only; never installs packages or modifies Homebrew formulae.",
            remediation: "Inventory and baseline Homebrew package dual-use artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    private static func assessCupsPrintDualUse(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "CUPSPRINTDUAL" || $0.eventType == "cups.print"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["cups.risk_tags"] ?? "").lowercased()
            return tags.contains("print_surface") || !($0.fields["cups.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["cups.path"] ?? ""
            let name = $0.fields["cups.name"] ?? ""
            let tags = $0.fields["cups.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "cups_print_dualuse", status: "fail", severity: "medium",
            title: "CUPS / printer dual-use residual surface surface present",
            detail: "\(risky.count) CUPS printer dual-use marker(s) - IR surface. Path/meta only; never submits print jobs or reconfigures CUPS remotely.",
            remediation: "Inventory and baseline CUPS printer dual-use artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    private static func assessScreenCapturePrivacyDualUse(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "SCREENCAPTUREPRIV" || $0.eventType == "screencapture.privacy"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["scpriv.risk_tags"] ?? "").lowercased()
            return tags.contains("capture_surface") || !($0.fields["scpriv.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["scpriv.path"] ?? ""
            let name = $0.fields["scpriv.name"] ?? ""
            let tags = $0.fields["scpriv.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "screencapture_privacy_dualuse", status: "fail", severity: "medium",
            title: "ScreenCapture / screenshot privacy dual-use depth surface present",
            detail: "\(risky.count) ScreenCapture privacy dual-use marker(s) - IR surface. Path/meta only; never captures screens or dumps Screen Recording TCC rows.",
            remediation: "Inventory and baseline ScreenCapture privacy dual-use artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }
    // MARK: - Wave-14 multi-plane red↔blue pair assessments

    private static func assessAutomatorWorkflow(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "AUTOMATORWF" || $0.eventType == "automator.workflow"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["automator.risk_tags"] ?? "").lowercased()
            return tags.contains("workflow_surface") || !($0.fields["automator.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["automator.path"] ?? ""
            let name = $0.fields["automator.name"] ?? ""
            let tags = $0.fields["automator.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "automator_workflow", status: "fail", severity: "medium",
            title: "Automator workflow delivery residual surface present",
            detail: "\(risky.count) Automator workflow delivery marker(s) - IR surface. Path/meta only; never executes Automator workflows or plants malicious .workflow bundles.",
            remediation: "Inventory and baseline Automator workflow delivery artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    private static func assessIcloudDrivePath(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "ICLOUDDRIVEPATH" || $0.eventType == "icloud.drive_path"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["icldrv.risk_tags"] ?? "").lowercased()
            return tags.contains("icloud_path_surface") || !($0.fields["icldrv.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["icldrv.path"] ?? ""
            let name = $0.fields["icldrv.name"] ?? ""
            let tags = $0.fields["icldrv.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "icloud_drive_path", status: "fail", severity: "medium",
            title: "iCloud Drive / Mobile Documents path plane surface present",
            detail: "\(risky.count) iCloud Drive path plane marker(s) - IR surface. Path/meta only; never enumerates iCloud file contents or exfiltrates Mobile Documents.",
            remediation: "Inventory and baseline iCloud Drive path plane artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    private static func assessBluetoothContinuityDepth(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "BTCONTINUITY" || $0.eventType == "bluetooth.continuity"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["btcont.risk_tags"] ?? "").lowercased()
            return tags.contains("bt_continuity_surface") || !($0.fields["btcont.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["btcont.path"] ?? ""
            let name = $0.fields["btcont.name"] ?? ""
            let tags = $0.fields["btcont.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "bluetooth_continuity_depth", status: "fail", severity: "medium",
            title: "Bluetooth / Continuity proximity residual depth surface present",
            detail: "\(risky.count) Bluetooth Continuity depth marker(s) - IR surface. Path/meta only; never enables Bluetooth pairing or spoofs Continuity identities.",
            remediation: "Inventory and baseline Bluetooth Continuity depth artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    private static func assessFontValidationDualuse(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "FONTVALIDATION" || $0.eventType == "font.validation"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["fontval.risk_tags"] ?? "").lowercased()
            return tags.contains("font_surface") || !($0.fields["fontval.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["fontval.path"] ?? ""
            let name = $0.fields["fontval.name"] ?? ""
            let tags = $0.fields["fontval.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "font_validation_dualuse", status: "fail", severity: "medium",
            title: "Font validation / ATS dual-use surface surface present",
            detail: "\(risky.count) Font validation dual-use marker(s) - IR surface. Path/meta only; never installs malicious fonts or disables font validation.",
            remediation: "Inventory and baseline Font validation dual-use artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    private static func assessQuicklookCacheDepth(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "QUICKLOOKCACHE" || $0.eventType == "quicklook.cache"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["qlcache.risk_tags"] ?? "").lowercased()
            return tags.contains("quicklook_surface") || !($0.fields["qlcache.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["qlcache.path"] ?? ""
            let name = $0.fields["qlcache.name"] ?? ""
            let tags = $0.fields["qlcache.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "quicklook_cache_depth", status: "fail", severity: "medium",
            title: "QuickLook thumbnail cache residual depth surface present",
            detail: "\(risky.count) QuickLook cache depth marker(s) - IR surface. Path/meta only; never dumps QuickLook thumbnail bitmap contents as secret material.",
            remediation: "Inventory and baseline QuickLook cache depth artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    private static func assessDnsResolverDualuse(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "DNSRESOLVER" || $0.eventType == "dns.resolver"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["dnsres.risk_tags"] ?? "").lowercased()
            return tags.contains("dns_surface") || !($0.fields["dnsres.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["dnsres.path"] ?? ""
            let name = $0.fields["dnsres.name"] ?? ""
            let tags = $0.fields["dnsres.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "dns_resolver_dualuse", status: "fail", severity: "medium",
            title: "DNS resolver / mDNSResponder dual-use surface surface present",
            detail: "\(risky.count) DNS resolver dual-use marker(s) - IR surface. Path/meta only; never rewrites resolver config or poisons DNS caches.",
            remediation: "Inventory and baseline DNS resolver dual-use artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    private static func assessLsQuarantineDbDepth(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "LSQUARANTINEDB" || $0.eventType == "ls.quarantine_db"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["lsqdb.risk_tags"] ?? "").lowercased()
            return tags.contains("quarantine_db_surface") || !($0.fields["lsqdb.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["lsqdb.path"] ?? ""
            let name = $0.fields["lsqdb.name"] ?? ""
            let tags = $0.fields["lsqdb.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "ls_quarantine_db_depth", status: "fail", severity: "medium",
            title: "LaunchServices QuarantineEvents DB residual depth surface present",
            detail: "\(risky.count) LS QuarantineEvents depth marker(s) - IR surface. Path/meta only; never deletes QuarantineEvents rows or clears LS quarantine history.",
            remediation: "Inventory and baseline LS QuarantineEvents depth artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    private static func assessPamAuthModule(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "PAMAUTHMODULE" || $0.eventType == "pam.module"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["pammod.risk_tags"] ?? "").lowercased()
            return tags.contains("pam_surface") || !($0.fields["pammod.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["pammod.path"] ?? ""
            let name = $0.fields["pammod.name"] ?? ""
            let tags = $0.fields["pammod.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "pam_auth_module", status: "fail", severity: "medium",
            title: "PAM authentication module residual surface surface present",
            detail: "\(risky.count) PAM auth module surface marker(s) - IR surface. Path/meta only; never installs PAM modules or modifies /etc/pam.d.",
            remediation: "Inventory and baseline PAM auth module surface artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    private static func assessCronAtJobDepth(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "CRONATJOB" || $0.eventType == "cron.at_job"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["cronat.risk_tags"] ?? "").lowercased()
            return tags.contains("cron_at_surface") || !($0.fields["cronat.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["cronat.path"] ?? ""
            let name = $0.fields["cronat.name"] ?? ""
            let tags = $0.fields["cronat.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "cron_at_job_depth", status: "fail", severity: "medium",
            title: "Cron / at job dual-use residual depth surface present",
            detail: "\(risky.count) Cron/at job depth marker(s) - IR surface. Path/meta only; never installs cron or at jobs outside the lab root.",
            remediation: "Inventory and baseline Cron/at job depth artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    private static func assessNotesMetadataPlane(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "NOTESMETADATA" || $0.eventType == "notes.metadata"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["notesmeta.risk_tags"] ?? "").lowercased()
            return tags.contains("notes_surface") || !($0.fields["notesmeta.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["notesmeta.path"] ?? ""
            let name = $0.fields["notesmeta.name"] ?? ""
            let tags = $0.fields["notesmeta.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "notes_metadata_plane", status: "fail", severity: "medium",
            title: "Notes.app metadata collection path plane surface present",
            detail: "\(risky.count) Notes metadata plane marker(s) - IR surface. Path/meta only; never reads Notes body contents or exports note secrets.",
            remediation: "Inventory and baseline Notes metadata plane artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }
    // MARK: - Wave-15 multi-plane red↔blue pair assessments

    private static func assessPhotosLibraryPath(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "PHOTOSLIBRARY" || $0.eventType == "photos.library"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["photoslib.risk_tags"] ?? "").lowercased()
            return tags.contains("photos_surface") || !($0.fields["photoslib.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["photoslib.path"] ?? ""
            let name = $0.fields["photoslib.name"] ?? ""
            let tags = $0.fields["photoslib.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "photos_library_path", status: "fail", severity: "medium",
            title: "Photos.app library collection path plane surface present",
            detail: "\(risky.count) Photos library path plane marker(s) - IR surface. Path/meta only; never reads photo contents or exports Photo Library media.",
            remediation: "Inventory and baseline Photos library path plane artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    private static func assessVpnConfigDualuse(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "VPNCONFIGDUAL" || $0.eventType == "vpn.config"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["vpncfg.risk_tags"] ?? "").lowercased()
            return tags.contains("vpn_surface") || !($0.fields["vpncfg.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["vpncfg.path"] ?? ""
            let name = $0.fields["vpncfg.name"] ?? ""
            let tags = $0.fields["vpncfg.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "vpn_config_dualuse", status: "fail", severity: "medium",
            title: "VPN configuration dual-use residual surface surface present",
            detail: "\(risky.count) VPN config dual-use marker(s) - IR surface. Path/meta only; never installs VPN profiles or rewrites network extension VPN configs.",
            remediation: "Inventory and baseline VPN config dual-use artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    private static func assessSandboxContainerDepth(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "SANDBOXCONTAINER" || $0.eventType == "sandbox.container"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["sbxctr.risk_tags"] ?? "").lowercased()
            return tags.contains("sandbox_surface") || !($0.fields["sbxctr.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["sbxctr.path"] ?? ""
            let name = $0.fields["sbxctr.name"] ?? ""
            let tags = $0.fields["sbxctr.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "sandbox_container_depth", status: "fail", severity: "medium",
            title: "App sandbox container residual depth surface present",
            detail: "\(risky.count) Sandbox container depth marker(s) - IR surface. Path/meta only; never breaks app sandbox or forges container entitlements.",
            remediation: "Inventory and baseline Sandbox container depth artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    private static func assessXpcMachServiceDepth(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "XPCMACHSERVICE" || $0.eventType == "xpc.mach_service"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["xpcmach.risk_tags"] ?? "").lowercased()
            return tags.contains("xpc_mach_surface") || !($0.fields["xpcmach.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["xpcmach.path"] ?? ""
            let name = $0.fields["xpcmach.name"] ?? ""
            let tags = $0.fields["xpcmach.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "xpc_mach_service_depth", status: "fail", severity: "medium",
            title: "XPC Mach service residual depth surface present",
            detail: "\(risky.count) XPC Mach service depth marker(s) - IR surface. Path/meta only; never registers XPC services or injects into Mach ports.",
            remediation: "Inventory and baseline XPC Mach service depth artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    private static func assessTmLocalSnapshotDepth(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "TMLOCALSNAPSHOT" || $0.eventType == "tm.local_snapshot"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["tmsnap.risk_tags"] ?? "").lowercased()
            return tags.contains("tm_snapshot_surface") || !($0.fields["tmsnap.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["tmsnap.path"] ?? ""
            let name = $0.fields["tmsnap.name"] ?? ""
            let tags = $0.fields["tmsnap.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "tm_local_snapshot_depth", status: "fail", severity: "medium",
            title: "Time Machine local snapshot residual depth surface present",
            detail: "\(risky.count) TM local snapshot depth marker(s) - IR surface. Path/meta only; never mounts snapshots for data theft or deletes backup catalogs.",
            remediation: "Inventory and baseline TM local snapshot depth artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    private static func assessEmondLegacyDepth(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "EMONDLEGACY" || $0.eventType == "emond.legacy"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["emondleg.risk_tags"] ?? "").lowercased()
            return tags.contains("emond_surface") || !($0.fields["emondleg.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["emondleg.path"] ?? ""
            let name = $0.fields["emondleg.name"] ?? ""
            let tags = $0.fields["emondleg.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "emond_legacy_depth", status: "fail", severity: "medium",
            title: "Emond legacy rules residual depth surface present",
            detail: "\(risky.count) Emond legacy depth marker(s) - IR surface. Path/meta only; never installs emond rules or enables the legacy event monitor daemon.",
            remediation: "Inventory and baseline Emond legacy depth artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    private static func assessScreenSharingArdDepth(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "SCREENSHARINGARD" || $0.eventType == "ard.screen_sharing"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["ardss.risk_tags"] ?? "").lowercased()
            return tags.contains("ard_surface") || !($0.fields["ardss.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["ardss.path"] ?? ""
            let name = $0.fields["ardss.name"] ?? ""
            let tags = $0.fields["ardss.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "screen_sharing_ard_depth", status: "fail", severity: "medium",
            title: "Screen Sharing / ARD residual depth surface present",
            detail: "\(risky.count) Screen Sharing ARD depth marker(s) - IR surface. Path/meta only; never enables Screen Sharing or ARD, never connects to remote desktops.",
            remediation: "Inventory and baseline Screen Sharing ARD depth artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    private static func assessKeychainAclPath(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "KEYCHAINACLPATH" || $0.eventType == "keychain.acl_path"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["kcacl.risk_tags"] ?? "").lowercased()
            return tags.contains("keychain_acl_surface") || !($0.fields["kcacl.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["kcacl.path"] ?? ""
            let name = $0.fields["kcacl.name"] ?? ""
            let tags = $0.fields["kcacl.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "keychain_acl_path", status: "fail", severity: "medium",
            title: "Keychain ACL path residual surface surface present",
            detail: "\(risky.count) Keychain ACL path plane marker(s) - IR surface. Path/meta only; never dumps keychain items, passwords, or private keys.",
            remediation: "Inventory and baseline Keychain ACL path plane artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    private static func assessPythonRuntimeDualuse(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "PYTHONRUNTIME" || $0.eventType == "python.runtime"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["pyrun.risk_tags"] ?? "").lowercased()
            return tags.contains("python_surface") || !($0.fields["pyrun.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["pyrun.path"] ?? ""
            let name = $0.fields["pyrun.name"] ?? ""
            let tags = $0.fields["pyrun.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "python_runtime_dualuse", status: "fail", severity: "medium",
            title: "Python runtime dual-use residual surface surface present",
            detail: "\(risky.count) Python runtime dual-use marker(s) - IR surface. Path/meta only; never executes third-party Python payloads or drops malicious site-packages.",
            remediation: "Inventory and baseline Python runtime dual-use artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }


    private static func assessShellPluginManager(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "SHELLPLUGINMGR" || $0.eventType == "shell.plugin_manager"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["shplug.risk_tags"] ?? "").lowercased()
            return tags.contains("shell_plugin_surface") || !($0.fields["shplug.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(4).compactMap {
            let path = $0.fields["shplug.path"] ?? ""
            let name = $0.fields["shplug.name"] ?? ""
            let tags = $0.fields["shplug.risk_tags"] ?? ""
            return "\(name) path=\(path) tags=\(tags)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "shell_plugin_manager", status: "fail", severity: "medium",
            title: "Shell plugin manager dual-use residual surface present",
            detail: "\(risky.count) Shell plugin manager dual-use marker(s) - IR surface. Path/meta only; never installs oh-my-zsh plugins or rewrites shell init for persistence.",
            remediation: "Inventory and baseline Shell plugin manager dual-use artifacts. Correlate unexpected markers with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages. Assessment guidance only.",
            evidence: sample
        )]
    }
    // MARK: - Wave-16 multi-plane red↔blue pair assessments

    private static func assessAirplayReceiverSurface(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "AIRPLAYRX" || $0.eventType == "airplay.receiver"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["airplayrx.risk_tags"] ?? "").lowercased()
            return tags.contains("airplay_surface") || !($0.fields["airplayrx.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["airplayrx.path"] ?? ""
            let name = $0.fields["airplayrx.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "airplay_receiver_surface", status: "fail", severity: "medium",
            title: "AirPlay receiver dual-use residual surface present",
            detail: "\(risky.count) AirPlay receiver dual-use marker(s) - IR surface. Path/meta only; never enables AirPlay Receiver or spoofs AirPlay targets.",
            remediation: "Inventory and baseline AirPlay receiver dual-use artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    private static func assessHandoffClipboardDepth(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "HANDOFFCB" || $0.eventType == "handoff.clipboard"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["hdoffcb.risk_tags"] ?? "").lowercased()
            return tags.contains("handoff_surface") || !($0.fields["hdoffcb.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["hdoffcb.path"] ?? ""
            let name = $0.fields["hdoffcb.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "handoff_clipboard_depth", status: "fail", severity: "medium",
            title: "Handoff / Universal Clipboard residual depth surface present",
            detail: "\(risky.count) Handoff clipboard depth marker(s) - IR surface. Path/meta only; never reads Universal Clipboard contents or forges Handoff activity.",
            remediation: "Inventory and baseline Handoff clipboard depth artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    private static func assessImessagePathPlane(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "IMSGPATH" || $0.eventType == "imessage.path"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["imsgpath.risk_tags"] ?? "").lowercased()
            return tags.contains("imessage_surface") || !($0.fields["imsgpath.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["imsgpath.path"] ?? ""
            let name = $0.fields["imsgpath.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "imessage_path_plane", status: "fail", severity: "medium",
            title: "iMessage / Messages path collection plane surface present",
            detail: "\(risky.count) iMessage path plane marker(s) - IR surface. Path/meta only; never reads Messages database contents or exports chat transcripts.",
            remediation: "Inventory and baseline iMessage path plane artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    private static func assessFacetimeCameraSurface(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "FTCAM" || $0.eventType == "facetime.camera"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["ftcam.risk_tags"] ?? "").lowercased()
            return tags.contains("facetime_surface") || !($0.fields["ftcam.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["ftcam.path"] ?? ""
            let name = $0.fields["ftcam.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "facetime_camera_surface", status: "fail", severity: "medium",
            title: "FaceTime / camera pipeline dual-use surface surface present",
            detail: "\(risky.count) FaceTime camera dual-use marker(s) - IR surface. Path/meta only; never activates camera/mic or dumps FaceTime call history contents.",
            remediation: "Inventory and baseline FaceTime camera dual-use artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    private static func assessFinderSyncExtension(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "FNDSYNC" || $0.eventType == "finder.sync_ext"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["fndsync.risk_tags"] ?? "").lowercased()
            return tags.contains("finder_sync_surface") || !($0.fields["fndsync.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["fndsync.path"] ?? ""
            let name = $0.fields["fndsync.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "finder_sync_extension", status: "fail", severity: "medium",
            title: "Finder Sync extension dual-use surface surface present",
            detail: "\(risky.count) Finder Sync dual-use marker(s) - IR surface. Path/meta only; never installs Finder Sync extensions or rewrites Finder preferences for abuse.",
            remediation: "Inventory and baseline Finder Sync dual-use artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    private static func assessFileproviderDomain(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "FPDOM" || $0.eventType == "fileprovider.domain"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["fpdom.risk_tags"] ?? "").lowercased()
            return tags.contains("fileprovider_surface") || !($0.fields["fpdom.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["fpdom.path"] ?? ""
            let name = $0.fields["fpdom.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "fileprovider_domain", status: "fail", severity: "medium",
            title: "File Provider domain residual surface surface present",
            detail: "\(risky.count) File Provider domain marker(s) - IR surface. Path/meta only; never registers malicious File Provider domains or exfiltrates provider caches.",
            remediation: "Inventory and baseline File Provider domain artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    private static func assessNotificationCenterDepth(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "NOTICTR" || $0.eventType == "notification.center"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["notictr.risk_tags"] ?? "").lowercased()
            return tags.contains("notification_surface") || !($0.fields["notictr.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["notictr.path"] ?? ""
            let name = $0.fields["notictr.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "notification_center_depth", status: "fail", severity: "medium",
            title: "Notification Center residual depth surface present",
            detail: "\(risky.count) Notification Center depth marker(s) - IR surface. Path/meta only; never dumps notification body contents or forges notification payloads.",
            remediation: "Inventory and baseline Notification Center depth artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    private static func assessSiriSuggestionsPlane(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "SIRISUG" || $0.eventType == "siri.suggestions"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["sirisug.risk_tags"] ?? "").lowercased()
            return tags.contains("siri_surface") || !($0.fields["sirisug.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["sirisug.path"] ?? ""
            let name = $0.fields["sirisug.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "siri_suggestions_plane", status: "fail", severity: "medium",
            title: "Siri / Suggestions data-access residual surface present",
            detail: "\(risky.count) Siri Suggestions residual marker(s) - IR surface. Path/meta only; never dumps Siri transcripts or Suggestions databases contents.",
            remediation: "Inventory and baseline Siri Suggestions residual artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    private static func assessSpotlightImporterDepth(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "SPIMP" || $0.eventType == "spotlight.importer"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["spimp.risk_tags"] ?? "").lowercased()
            return tags.contains("spotlight_importer_surface") || !($0.fields["spimp.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["spimp.path"] ?? ""
            let name = $0.fields["spimp.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "spotlight_importer_depth", status: "fail", severity: "medium",
            title: "Spotlight importer residual depth surface present",
            detail: "\(risky.count) Spotlight importer depth marker(s) - IR surface. Path/meta only; never installs malicious Spotlight importers or dumps mdworker index contents.",
            remediation: "Inventory and baseline Spotlight importer depth artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    private static func assessContactsPathPlane(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "CTPATH" || $0.eventType == "contacts.path"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["ctpath.risk_tags"] ?? "").lowercased()
            return tags.contains("contacts_surface") || !($0.fields["ctpath.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["ctpath.path"] ?? ""
            let name = $0.fields["ctpath.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "contacts_path_plane", status: "fail", severity: "medium",
            title: "Contacts database path residual plane surface present",
            detail: "\(risky.count) Contacts path plane marker(s) - IR surface. Path/meta only; never exports contact cards or dumps AddressBook database contents.",
            remediation: "Inventory and baseline Contacts path plane artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    private static func assessCalendarServerPath(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "CALDAV" || $0.eventType == "calendar.caldav"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["caldav.risk_tags"] ?? "").lowercased()
            return tags.contains("caldav_surface") || !($0.fields["caldav.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["caldav.path"] ?? ""
            let name = $0.fields["caldav.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "calendar_server_path", status: "fail", severity: "medium",
            title: "Calendar server / CalDAV residual surface surface present",
            detail: "\(risky.count) Calendar CalDAV residual marker(s) - IR surface. Path/meta only; never reads calendar event bodies or credentials from CalDAV stores.",
            remediation: "Inventory and baseline Calendar CalDAV residual artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    private static func assessRemindersCloudPath(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "REMCLOUD" || $0.eventType == "reminders.cloud"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["remcloud.risk_tags"] ?? "").lowercased()
            return tags.contains("reminders_cloud_surface") || !($0.fields["remcloud.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["remcloud.path"] ?? ""
            let name = $0.fields["remcloud.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "reminders_cloud_path", status: "fail", severity: "medium",
            title: "Reminders cloud path residual plane surface present",
            detail: "\(risky.count) Reminders cloud path marker(s) - IR surface. Path/meta only; never reads reminder titles/bodies or exports Reminders databases.",
            remediation: "Inventory and baseline Reminders cloud path artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    private static func assessMapsLocationPath(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "MAPSLOC" || $0.eventType == "maps.location"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["mapsloc.risk_tags"] ?? "").lowercased()
            return tags.contains("maps_location_surface") || !($0.fields["mapsloc.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["mapsloc.path"] ?? ""
            let name = $0.fields["mapsloc.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "maps_location_path", status: "fail", severity: "medium",
            title: "Maps / location services residual plane surface present",
            detail: "\(risky.count) Maps location residual marker(s) - IR surface. Path/meta only; never dumps location history or spoofs CoreLocation positions.",
            remediation: "Inventory and baseline Maps location residual artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    private static func assessWeatherWidgetPath(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "WTHRWDG" || $0.eventType == "weather.widget"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["wthrwdg.risk_tags"] ?? "").lowercased()
            return tags.contains("weather_surface") || !($0.fields["wthrwdg.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["wthrwdg.path"] ?? ""
            let name = $0.fields["wthrwdg.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "weather_widget_path", status: "fail", severity: "medium",
            title: "Weather / widget data residual plane surface present",
            detail: "\(risky.count) Weather widget residual marker(s) - IR surface. Path/meta only; never dumps weather personalization data or widget timeline contents.",
            remediation: "Inventory and baseline Weather widget residual artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    private static func assessMusicLibraryPath(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "MUSLIB" || $0.eventType == "music.library"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["muslib.risk_tags"] ?? "").lowercased()
            return tags.contains("music_surface") || !($0.fields["muslib.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["muslib.path"] ?? ""
            let name = $0.fields["muslib.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "music_library_path", status: "fail", severity: "medium",
            title: "Music / media library path residual surface present",
            detail: "\(risky.count) Music library path marker(s) - IR surface. Path/meta only; never exports Music library media or DRM material.",
            remediation: "Inventory and baseline Music library path artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    private static func assessBooksPathPlane(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "BKPATH" || $0.eventType == "books.path"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["bkpath.risk_tags"] ?? "").lowercased()
            return tags.contains("books_surface") || !($0.fields["bkpath.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["bkpath.path"] ?? ""
            let name = $0.fields["bkpath.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "books_path_plane", status: "fail", severity: "medium",
            title: "Books / EPUB path residual plane surface present",
            detail: "\(risky.count) Books path plane marker(s) - IR surface. Path/meta only; never extracts EPUB contents or Books annotations as bulk export.",
            remediation: "Inventory and baseline Books path plane artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    private static func assessPodcastsPathPlane(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "PODPATH" || $0.eventType == "podcasts.path"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["podpath.risk_tags"] ?? "").lowercased()
            return tags.contains("podcasts_surface") || !($0.fields["podpath.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["podpath.path"] ?? ""
            let name = $0.fields["podpath.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "podcasts_path_plane", status: "fail", severity: "medium",
            title: "Podcasts library path residual surface present",
            detail: "\(risky.count) Podcasts path plane marker(s) - IR surface. Path/meta only; never dumps podcast episode files or account tokens.",
            remediation: "Inventory and baseline Podcasts path plane artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    private static func assessTvAppPathPlane(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "TVPATH" || $0.eventType == "tv.path"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["tvpath.risk_tags"] ?? "").lowercased()
            return tags.contains("tv_surface") || !($0.fields["tvpath.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["tvpath.path"] ?? ""
            let name = $0.fields["tvpath.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "tv_app_path_plane", status: "fail", severity: "medium",
            title: "TV.app residual path plane surface present",
            detail: "\(risky.count) TV.app path plane marker(s) - IR surface. Path/meta only; never dumps TV.app media caches or account material.",
            remediation: "Inventory and baseline TV.app path plane artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    private static func assessHomekitPathPlane(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "HKPATH" || $0.eventType == "homekit.path"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["hkpath.risk_tags"] ?? "").lowercased()
            return tags.contains("homekit_surface") || !($0.fields["hkpath.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["hkpath.path"] ?? ""
            let name = $0.fields["hkpath.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "homekit_path_plane", status: "fail", severity: "medium",
            title: "HomeKit residual path plane surface present",
            detail: "\(risky.count) HomeKit path plane marker(s) - IR surface. Path/meta only; never enumerates HomeKit accessory secrets or pairs devices.",
            remediation: "Inventory and baseline HomeKit path plane artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    private static func assessHealthPathPlane(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "HLTHPATH" || $0.eventType == "health.path"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["hlthpath.risk_tags"] ?? "").lowercased()
            return tags.contains("health_surface") || !($0.fields["hlthpath.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["hlthpath.path"] ?? ""
            let name = $0.fields["hlthpath.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "health_path_plane", status: "fail", severity: "medium",
            title: "Health app residual path plane surface present",
            detail: "\(risky.count) Health path plane marker(s) - IR surface. Path/meta only; never exports HealthKit samples or medical records.",
            remediation: "Inventory and baseline Health path plane artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    private static func assessWalletPassPath(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "WLTPASS" || $0.eventType == "wallet.pass"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["wltpass.risk_tags"] ?? "").lowercased()
            return tags.contains("wallet_surface") || !($0.fields["wltpass.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["wltpass.path"] ?? ""
            let name = $0.fields["wltpass.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "wallet_pass_path", status: "fail", severity: "medium",
            title: "Wallet / pass residual path plane surface present",
            detail: "\(risky.count) Wallet pass path marker(s) - IR surface. Path/meta only; never dumps pass contents, payment tokens, or card data.",
            remediation: "Inventory and baseline Wallet pass path artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    private static func assessFindmyPathPlane(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "FMPATH" || $0.eventType == "findmy.path"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["fmpath.risk_tags"] ?? "").lowercased()
            return tags.contains("findmy_surface") || !($0.fields["fmpath.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["fmpath.path"] ?? ""
            let name = $0.fields["fmpath.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "findmy_path_plane", status: "fail", severity: "medium",
            title: "Find My residual path plane surface present",
            detail: "\(risky.count) Find My path plane marker(s) - IR surface. Path/meta only; never queries Find My device locations or dumps owner tokens.",
            remediation: "Inventory and baseline Find My path plane artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    private static func assessShortcutsIcloudSync(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "SCICLOUD" || $0.eventType == "shortcuts.icloud"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["scicloud.risk_tags"] ?? "").lowercased()
            return tags.contains("shortcuts_icloud_surface") || !($0.fields["scicloud.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["scicloud.path"] ?? ""
            let name = $0.fields["scicloud.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "shortcuts_icloud_sync", status: "fail", severity: "medium",
            title: "Shortcuts iCloud sync residual depth surface present",
            detail: "\(risky.count) Shortcuts iCloud sync marker(s) - IR surface. Path/meta only; never executes Shortcuts or dumps iCloud-synced automation databases.",
            remediation: "Inventory and baseline Shortcuts iCloud sync artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    private static func assessDevicemanagementProfile(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "MDMPROF" || $0.eventType == "mdm.profile_depth"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["mdmprof.risk_tags"] ?? "").lowercased()
            return tags.contains("device_mgmt_surface") || !($0.fields["mdmprof.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["mdmprof.path"] ?? ""
            let name = $0.fields["mdmprof.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "devicemanagement_profile", status: "fail", severity: "medium",
            title: "Device management profile residual depth surface present",
            detail: "\(risky.count) Device management profile marker(s) - IR surface. Path/meta only; never installs configuration profiles or enrolls hosts in MDM.",
            remediation: "Inventory and baseline Device management profile artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }


    private static func assessSoftwareupdateCatalog(_ events: [EventEnvelope]) -> [Finding] {
        let rows = events.filter {
            $0.sourcePlugin == "SUCAT" || $0.eventType == "softwareupdate.catalog"
        }
        guard !rows.isEmpty else { return [] }
        let risky = rows.filter {
            let tags = ($0.fields["sucat.risk_tags"] ?? "").lowercased()
            return tags.contains("softwareupdate_surface") || !($0.fields["sucat.path"] ?? "").isEmpty
        }
        guard !risky.isEmpty else { return [] }
        let sample = risky.prefix(3).compactMap {
            let path = $0.fields["sucat.path"] ?? ""
            let name = $0.fields["sucat.name"] ?? ""
            return "\(name) path=\(path)".trimmingCharacters(in: .whitespaces)
        }.joined(separator: " | ")
        return [Finding(
            control: "softwareupdate_catalog", status: "fail", severity: "medium",
            title: "Software Update catalog residual surface surface present",
            detail: "\(risky.count) Software Update catalog marker(s) - IR surface. Path/meta only; never points SUS catalogs at attacker mirrors or tampers with update plists.",
            remediation: "Inventory and baseline Software Update catalog artifacts. Correlate with delivery/lateral timelines. Restrict dual-use paths via MDM where available. Do not export secrets into case packages.",
            evidence: sample
        )]
    }

}
