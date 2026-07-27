/// Versioned host snapshot filled by collectors and ranked by vectors/checks (path/meta only).
import Foundation

/// Host identity snapshot.
public struct HostState: Codable, Sendable, Equatable {
    public var hostname: String
    public var username: String
    public var osVersion: String
    public var osBuild: String?
    public var arch: String
    public var processArch: String
    public var uptimeSeconds: TimeInterval?
    public var isRoot: Bool

    public init(
        hostname: String,
        username: String,
        osVersion: String,
        osBuild: String? = nil,
        arch: String,
        processArch: String,
        uptimeSeconds: TimeInterval? = nil,
        isRoot: Bool = false
    ) {
        self.hostname = hostname
        self.username = username
        self.osVersion = osVersion
        self.osBuild = osBuild
        self.arch = arch
        self.processArch = processArch
        self.uptimeSeconds = uptimeSeconds
        self.isRoot = isRoot
    }
}

/// Detected security product presence (path/bundle existence only).
public struct SecurityProductHit: Codable, Sendable, Equatable {
    public var name: String
    public var path: String
    public var present: Bool

    public init(name: String, path: String, present: Bool) {
        self.name = name
        self.path = path
        self.present = present
    }
}

/// User LaunchAgent inventory entry.
public struct LaunchAgentEntry: Codable, Sendable, Equatable {
    public var label: String?
    public var path: String
    public var programArguments: [String]

    public init(label: String?, path: String, programArguments: [String] = []) {
        self.label = label
        self.path = path
        self.programArguments = programArguments
    }
}

/// BTM / login-items evidence (no binary format reverse-engineering).
public struct LoginItemsState: Codable, Sendable, Equatable {
    public var btmStorePresent: Bool
    public var btmDirectoryPath: String?
    public var btmDirectorySizeBytes: Int64?
    public var backgroundItemsBtmPath: String?
    public var backgroundItemsBtmSizeBytes: Int64?
    public var loginItemPaths: [String]
    public var notes: [String]

    public init(
        btmStorePresent: Bool = false,
        btmDirectoryPath: String? = nil,
        btmDirectorySizeBytes: Int64? = nil,
        backgroundItemsBtmPath: String? = nil,
        backgroundItemsBtmSizeBytes: Int64? = nil,
        loginItemPaths: [String] = [],
        notes: [String] = []
    ) {
        self.btmStorePresent = btmStorePresent
        self.btmDirectoryPath = btmDirectoryPath
        self.btmDirectorySizeBytes = btmDirectorySizeBytes
        self.backgroundItemsBtmPath = backgroundItemsBtmPath
        self.backgroundItemsBtmSizeBytes = backgroundItemsBtmSizeBytes
        self.loginItemPaths = loginItemPaths
        self.notes = notes
    }
}

/// Browser DB metadata only - never row contents / cookies / passwords.
public struct BrowserMetaEntry: Codable, Sendable, Equatable {
    public var browser: String
    public var kind: String
    public var path: String
    public var exists: Bool
    public var sizeBytes: Int64?
    public var modifiedAt: Date?

    public init(
        browser: String,
        kind: String,
        path: String,
        exists: Bool,
        sizeBytes: Int64? = nil,
        modifiedAt: Date? = nil
    ) {
        self.browser = browser
        self.kind = kind
        self.path = path
        self.exists = exists
        self.sizeBytes = sizeBytes
        self.modifiedAt = modifiedAt
    }
}

/// Codesign / entitlement sample for an app or binary path.
public struct CodesignSample: Codable, Sendable, Equatable {
    public var path: String
    public var signed: Bool?
    public var identifier: String?
    public var teamIdentifier: String?
    public var hardenedRuntime: Bool?
    public var getTaskAllow: Bool?
    public var disableLibraryValidation: Bool?
    public var allowDyldEnvironmentVariables: Bool?
    public var allowUnsignedExecutableMemory: Bool?
    public var notes: [String]

    public init(
        path: String,
        signed: Bool? = nil,
        identifier: String? = nil,
        teamIdentifier: String? = nil,
        hardenedRuntime: Bool? = nil,
        getTaskAllow: Bool? = nil,
        disableLibraryValidation: Bool? = nil,
        allowDyldEnvironmentVariables: Bool? = nil,
        allowUnsignedExecutableMemory: Bool? = nil,
        notes: [String] = []
    ) {
        self.path = path
        self.signed = signed
        self.identifier = identifier
        self.teamIdentifier = teamIdentifier
        self.hardenedRuntime = hardenedRuntime
        self.getTaskAllow = getTaskAllow
        self.disableLibraryValidation = disableLibraryValidation
        self.allowDyldEnvironmentVariables = allowDyldEnvironmentVariables
        self.allowUnsignedExecutableMemory = allowUnsignedExecutableMemory
        self.notes = notes
    }
}

/// Lightweight dylib / load-command risk signal.
public struct DylibRiskHit: Codable, Sendable, Equatable {
    public var path: String
    public var executablePath: String?
    public var weakDylibs: [String]
    public var notes: [String]

    public init(
        path: String,
        executablePath: String? = nil,
        weakDylibs: [String] = [],
        notes: [String] = []
    ) {
        self.path = path
        self.executablePath = executablePath
        self.weakDylibs = weakDylibs
        self.notes = notes
    }
}

/// Injectability surface derived from HR / dangerous entitlements.
public struct InjectabilityHit: Codable, Sendable, Equatable {
    public var path: String
    public var hardenedRuntime: Bool?
    public var getTaskAllow: Bool?
    public var disableLibraryValidation: Bool?
    public var allowDyldEnvironmentVariables: Bool?
    public var allowUnsignedExecutableMemory: Bool?
    public var riskFlags: [String]
    public var notes: [String]

    public init(
        path: String,
        hardenedRuntime: Bool? = nil,
        getTaskAllow: Bool? = nil,
        disableLibraryValidation: Bool? = nil,
        allowDyldEnvironmentVariables: Bool? = nil,
        allowUnsignedExecutableMemory: Bool? = nil,
        riskFlags: [String] = [],
        notes: [String] = []
    ) {
        self.path = path
        self.hardenedRuntime = hardenedRuntime
        self.getTaskAllow = getTaskAllow
        self.disableLibraryValidation = disableLibraryValidation
        self.allowDyldEnvironmentVariables = allowDyldEnvironmentVariables
        self.allowUnsignedExecutableMemory = allowUnsignedExecutableMemory
        self.riskFlags = riskFlags
        self.notes = notes
    }
}

/// TCC / permission probe summary (non-prompting).
public struct TCCState: Codable, Sendable, Equatable {
    public var fullDiskAccessLikely: Bool?
    public var notes: [String]
    public var probeMethod: String
    /// Multi-domain TCC graph signals (e.g. `ScreenCapture=likely`, `Accessibility=unknown`).
    /// Presence/absence heuristics only - never dumps TCC.db rows or forces prompts.
    public var domainSignals: [String]

    public init(
        fullDiskAccessLikely: Bool? = nil,
        notes: [String] = [],
        probeMethod: String = "stub",
        domainSignals: [String] = []
    ) {
        self.fullDiskAccessLikely = fullDiskAccessLikely
        self.notes = notes
        self.probeMethod = probeMethod
        self.domainSignals = domainSignals
    }
}

/// Endpoint Security / system-extension sensor posture (path heuristics only).
public struct ESFPostureState: Codable, Sendable, Equatable {
    /// Whether EndpointSecurity.framework / ES-related support paths are present.
    public var frameworkPresent: Bool?
    /// Paths that look like ES clients, EDR system extensions, or ES tooling.
    public var clientPaths: [String]
    /// Count of system-extension paths observed (may be filled from sibling collector merge).
    public var systemExtensionCount: Int
    /// Vendor/product hints inferred from path names (not process injection).
    public var edrHints: [String]
    public var notes: [String]

    public init(
        frameworkPresent: Bool? = nil,
        clientPaths: [String] = [],
        systemExtensionCount: Int = 0,
        edrHints: [String] = [],
        notes: [String] = []
    ) {
        self.frameworkPresent = frameworkPresent
        self.clientPaths = clientPaths
        self.systemExtensionCount = systemExtensionCount
        self.edrHints = edrHints
        self.notes = notes
    }
}

/// OS patch-debt / Software Update heuristics for CVE suggester context (not an exploit pack).
public struct PatchDebtState: Codable, Sendable, Equatable {
    public var osVersion: String?
    public var osBuild: String?
    public var softwareUpdatePlistPresent: Bool?
    /// Opaque install-history / SUS presence notes (no private package dump).
    public var lastUpdateHints: [String]
    /// Heuristic major-version lag vs a conservative known-current baseline (nil = unknown).
    public var majorVersionLag: Int?
    public var notes: [String]

    public init(
        osVersion: String? = nil,
        osBuild: String? = nil,
        softwareUpdatePlistPresent: Bool? = nil,
        lastUpdateHints: [String] = [],
        majorVersionLag: Int? = nil,
        notes: [String] = []
    ) {
        self.osVersion = osVersion
        self.osBuild = osBuild
        self.softwareUpdatePlistPresent = softwareUpdatePlistPresent
        self.lastUpdateHints = lastUpdateHints
        self.majorVersionLag = majorVersionLag
        self.notes = notes
    }
}

/// Launch-constraint / library-validation injectability truth notes.
public struct LaunchConstraintState: Codable, Sendable, Equatable {
    /// Paths where launch-constraint / constraint-ish plists or codesign notes were observed.
    public var constrainedPaths: [String]
    /// Paths with dangerous entitlement / HR composite without constraint evidence.
    public var unconstrainedRiskPaths: [String]
    public var notes: [String]

    public init(
        constrainedPaths: [String] = [],
        unconstrainedRiskPaths: [String] = [],
        notes: [String] = []
    ) {
        self.constrainedPaths = constrainedPaths
        self.unconstrainedRiskPaths = unconstrainedRiskPaths
        self.notes = notes
    }
}

/// NetworkExtension / VPN / content-filter posture (path heuristics only).
public struct NetworkExtensionState: Codable, Sendable, Equatable {
    public var frameworkPresent: Bool?
    public var vpnConfigPaths: [String]
    public var contentFilterHints: [String]
    public var packetTunnelHints: [String]
    public var neAppPaths: [String]
    public var notes: [String]

    public init(
        frameworkPresent: Bool? = nil,
        vpnConfigPaths: [String] = [],
        contentFilterHints: [String] = [],
        packetTunnelHints: [String] = [],
        neAppPaths: [String] = [],
        notes: [String] = []
    ) {
        self.frameworkPresent = frameworkPresent
        self.vpnConfigPaths = vpnConfigPaths
        self.contentFilterHints = contentFilterHints
        self.packetTunnelHints = packetTunnelHints
        self.neAppPaths = neAppPaths
        self.notes = notes
    }
}

/// Authorization rights / auth.db / packagekit privilege surface (path only).
public struct AuthRightsState: Codable, Sendable, Equatable {
    public var authDbPresent: Bool?
    public var authDbPath: String?
    public var authorizationPlistPaths: [String]
    public var packageKitPaths: [String]
    public var rightsHintCount: Int
    public var notes: [String]

    public init(
        authDbPresent: Bool? = nil,
        authDbPath: String? = nil,
        authorizationPlistPaths: [String] = [],
        packageKitPaths: [String] = [],
        rightsHintCount: Int = 0,
        notes: [String] = []
    ) {
        self.authDbPresent = authDbPresent
        self.authDbPath = authDbPath
        self.authorizationPlistPaths = authorizationPlistPaths
        self.packageKitPaths = packageKitPaths
        self.rightsHintCount = rightsHintCount
        self.notes = notes
    }
}

/// Developer toolchain dual-use inventory (path presence only).
public struct DeveloperToolchainState: Codable, Sendable, Equatable {
    public var xcodePresent: Bool?
    public var commandLineToolsPresent: Bool?
    /// Xcode / CLT / SDK root paths observed.
    public var toolchainPaths: [String]
    /// Dual-use bins (lldb, dtrace, codesign, otool, nm, …) path inventory.
    public var dualUseBinaries: [String]
    public var notes: [String]

    public init(
        xcodePresent: Bool? = nil,
        commandLineToolsPresent: Bool? = nil,
        toolchainPaths: [String] = [],
        dualUseBinaries: [String] = [],
        notes: [String] = []
    ) {
        self.xcodePresent = xcodePresent
        self.commandLineToolsPresent = commandLineToolsPresent
        self.toolchainPaths = toolchainPaths
        self.dualUseBinaries = dualUseBinaries
        self.notes = notes
    }
}

/// Time Machine / local snapshot data-access surface (no backup dump).
public struct TimeMachineState: Codable, Sendable, Equatable {
    public var preferencesPresent: Bool?
    /// Backup destination / TM machine-dir path hints.
    public var backupPaths: [String]
    /// Local snapshot volume / `.localsnapshots` hints.
    public var localSnapshotHints: [String]
    /// Mounted TM / backup volume path hints.
    public var volumeMountHints: [String]
    public var notes: [String]

    public init(
        preferencesPresent: Bool? = nil,
        backupPaths: [String] = [],
        localSnapshotHints: [String] = [],
        volumeMountHints: [String] = [],
        notes: [String] = []
    ) {
        self.preferencesPresent = preferencesPresent
        self.backupPaths = backupPaths
        self.localSnapshotHints = localSnapshotHints
        self.volumeMountHints = volumeMountHints
        self.notes = notes
    }
}

/// User-space mobileconfig / profile sideload surface (no profile payload dump).
public struct ConfigProfileSideloadState: Codable, Sendable, Equatable {
    /// User-owned `.mobileconfig` paths (e.g. Desktop/Documents).
    public var userMobileconfigPaths: [String]
    /// Downloads / browser-drop profile path hints.
    public var downloadsProfileHints: [String]
    /// Whether a system profile-install DB / store path was observed.
    public var profileInstallDbPresent: Bool?
    public var notes: [String]

    public init(
        userMobileconfigPaths: [String] = [],
        downloadsProfileHints: [String] = [],
        profileInstallDbPresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.userMobileconfigPaths = userMobileconfigPaths
        self.downloadsProfileHints = downloadsProfileHints
        self.profileInstallDbPresent = profileInstallDbPresent
        self.notes = notes
    }
}

// MARK: - state types

/// App sandbox / entitlement thick-client inventory (no entitlement mutation).
public struct AppSandboxEntitlementState: Codable, Sendable, Equatable {
    /// Sample app paths inspected for sandbox/entitlement posture.
    public var appSamples: [String]
    /// Paths or labels indicating app-sandbox entitlement present.
    public var sandboxedHints: [String]
    /// Paths or labels with dangerous entitlement class (get-task-allow, disable-library-validation, etc.).
    public var dangerousEntitlementHints: [String]
    /// Unsandboxed or hardened-runtime-off thick-client samples.
    public var unsandboxedRiskPaths: [String]
    public var notes: [String]

    public init(
        appSamples: [String] = [],
        sandboxedHints: [String] = [],
        dangerousEntitlementHints: [String] = [],
        unsandboxedRiskPaths: [String] = [],
        notes: [String] = []
    ) {
        self.appSamples = appSamples
        self.sandboxedHints = sandboxedHints
        self.dangerousEntitlementHints = dangerousEntitlementHints
        self.unsandboxedRiskPaths = unsandboxedRiskPaths
        self.notes = notes
    }
}

/// Notarization / stapling trust-depth surface (no ticket forgery).
public struct NotarizationStaplingState: Codable, Sendable, Equatable {
    /// Notarization/stapling tooling paths present (stapler, spctl, etc.).
    public var toolingPaths: [String]
    /// Ticket/cache path hints when listable.
    public var ticketCacheHints: [String]
    /// App samples lacking team ID / ad-hoc / unstapled class signals.
    public var unstapledOrAdHocHints: [String]
    /// Whether notarization assessment tooling appears available.
    public var assessmentToolsPresent: Bool?
    public var notes: [String]

    public init(
        toolingPaths: [String] = [],
        ticketCacheHints: [String] = [],
        unstapledOrAdHocHints: [String] = [],
        assessmentToolsPresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.toolingPaths = toolingPaths
        self.ticketCacheHints = ticketCacheHints
        self.unstapledOrAdHocHints = unstapledOrAdHocHints
        self.assessmentToolsPresent = assessmentToolsPresent
        self.notes = notes
    }
}

/// Virtualization / container dual-use surface (no container start / secret harvest).
public struct VirtualizationContainerState: Codable, Sendable, Equatable {
    /// Docker / Colima / Lima / OrbStack / podman path hits.
    public var containerToolPaths: [String]
    /// UTM / Parallels / VMware / VirtualBox / multipass app paths.
    public var hypervisorAppPaths: [String]
    /// Virtualization.framework / related framework path hints.
    public var frameworkPaths: [String]
    /// Whether any virt/container dual-use tooling was observed.
    public var dualUsePresent: Bool?
    public var notes: [String]

    public init(
        containerToolPaths: [String] = [],
        hypervisorAppPaths: [String] = [],
        frameworkPaths: [String] = [],
        dualUsePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.containerToolPaths = containerToolPaths
        self.hypervisorAppPaths = hypervisorAppPaths
        self.frameworkPaths = frameworkPaths
        self.dualUsePresent = dualUsePresent
        self.notes = notes
    }
}

/// Continuity / AirDrop proximity transfer posture (no pasteboard / payload abuse).
public struct ContinuityAirDropState: Codable, Sendable, Equatable {
    /// Preference / domain path hints for AirDrop / sharing.
    public var airdropPrefPaths: [String]
    /// Continuity / Handoff framework or support path hints.
    public var continuityFrameworkPaths: [String]
    /// Bluetooth / nearby-sharing adjacency path hints (presence only).
    public var nearbyShareHints: [String]
    /// Whether a proximity-transfer surface was observed.
    public var proximitySurfacePresent: Bool?
    public var notes: [String]

    public init(
        airdropPrefPaths: [String] = [],
        continuityFrameworkPaths: [String] = [],
        nearbyShareHints: [String] = [],
        proximitySurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.airdropPrefPaths = airdropPrefPaths
        self.continuityFrameworkPaths = continuityFrameworkPaths
        self.nearbyShareHints = nearbyShareHints
        self.proximitySurfacePresent = proximitySurfacePresent
        self.notes = notes
    }
}

/// FileVault / recovery escrow posture (never recovery-key material).
public struct FileVaultEscrowState: Codable, Sendable, Equatable {
    /// FileVault on/off when known (may mirror ProtectionsState).
    public var fileVaultOn: Bool?
    /// Escrow / recovery preference or support path hints (paths only).
    public var escrowPathHints: [String]
    /// MDM / institutional recovery artifact path hints.
    public var institutionalEscrowHints: [String]
    /// fdesetup / related tooling path presence.
    public var fdesetupPresent: Bool?
    public var notes: [String]

    public init(
        fileVaultOn: Bool? = nil,
        escrowPathHints: [String] = [],
        institutionalEscrowHints: [String] = [],
        fdesetupPresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.fileVaultOn = fileVaultOn
        self.escrowPathHints = escrowPathHints
        self.institutionalEscrowHints = institutionalEscrowHints
        self.fdesetupPresent = fdesetupPresent
        self.notes = notes
    }
}

// MARK: - Wave-8 2026 coverage residual surfaces

/// ClickFix / paste-and-run Terminal delivery posture (never builds lures/payloads).
public struct ClickFixTerminalDeliveryState: Codable, Sendable, Equatable {
    /// Terminal.app / shell path hits used for paste-run delivery class.
    public var terminalAppPaths: [String]
    /// Script Editor / AppleScript URL-scheme adjacent path hits.
    public var scriptEditorPaths: [String]
    /// Dual-use loader binaries (curl, osascript, sh, zsh, bash) path hits.
    public var loaderBinaryPaths: [String]
    /// Paste-warning / Terminal security preference path hints when listable.
    public var pasteWarningHints: [String]
    /// Whether a paste-run delivery surface was observed.
    public var deliverySurfacePresent: Bool?
    public var notes: [String]

    public init(
        terminalAppPaths: [String] = [],
        scriptEditorPaths: [String] = [],
        loaderBinaryPaths: [String] = [],
        pasteWarningHints: [String] = [],
        deliverySurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.terminalAppPaths = terminalAppPaths
        self.scriptEditorPaths = scriptEditorPaths
        self.loaderBinaryPaths = loaderBinaryPaths
        self.pasteWarningHints = pasteWarningHints
        self.deliverySurfacePresent = deliverySurfacePresent
        self.notes = notes
    }
}

/// Remote Apple Events / EPPC / Automation lateral posture (never enables RAE or sends AE).
public struct RemoteAppleEventsState: Codable, Sendable, Equatable {
    /// Preference / Sharing path hints for Remote Apple Events.
    public var remoteAEPrefPaths: [String]
    /// EPPC / AppleEvents framework or support path hints.
    public var eppcFrameworkPaths: [String]
    /// ARD / remote management adjacency path hints.
    public var remoteMgmtHints: [String]
    /// Whether a remote-automation lateral surface was observed.
    public var remoteAutomationSurfacePresent: Bool?
    public var notes: [String]

    public init(
        remoteAEPrefPaths: [String] = [],
        eppcFrameworkPaths: [String] = [],
        remoteMgmtHints: [String] = [],
        remoteAutomationSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.remoteAEPrefPaths = remoteAEPrefPaths
        self.eppcFrameworkPaths = eppcFrameworkPaths
        self.remoteMgmtHints = remoteMgmtHints
        self.remoteAutomationSurfacePresent = remoteAutomationSurfacePresent
        self.notes = notes
    }
}

/// Spotlight / mdworker / on-device AI-cache data-access class (never dumps index/cache contents).
public struct SpotlightAICacheState: Codable, Sendable, Equatable {
    /// Spotlight / mds / mdworker binary and store path hits.
    public var spotlightPaths: [String]
    /// CoreSpotlight / metadata framework path hits.
    public var metadataFrameworkPaths: [String]
    /// On-device AI / Apple Intelligence–class cache directory path hints (presence only).
    public var aiCachePathHints: [String]
    /// Whether an index/cache data-access surface was observed.
    public var dataAccessSurfacePresent: Bool?
    public var notes: [String]

    public init(
        spotlightPaths: [String] = [],
        metadataFrameworkPaths: [String] = [],
        aiCachePathHints: [String] = [],
        dataAccessSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.spotlightPaths = spotlightPaths
        self.metadataFrameworkPaths = metadataFrameworkPaths
        self.aiCachePathHints = aiCachePathHints
        self.dataAccessSurfacePresent = dataAccessSurfacePresent
        self.notes = notes
    }
}

/// Security-product management-plane / privileged-XPC unload class (never unloads sensors).
public struct SecurityMgmtPlaneState: Codable, Sendable, Equatable {
    /// Management CLI / systemextensionsctl / vendor uninstaller path hits.
    public var managementCLIPaths: [String]
    /// Privileged helper tools associated with security products (paths only).
    public var privilegedHelperPaths: [String]
    /// Uninstall / unload adjacency path hints.
    public var unloadAdjacentHints: [String]
    /// Whether a management-plane surface was observed.
    public var managementPlanePresent: Bool?
    public var notes: [String]

    public init(
        managementCLIPaths: [String] = [],
        privilegedHelperPaths: [String] = [],
        unloadAdjacentHints: [String] = [],
        managementPlanePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.managementCLIPaths = managementCLIPaths
        self.privilegedHelperPaths = privilegedHelperPaths
        self.unloadAdjacentHints = unloadAdjacentHints
        self.managementPlanePresent = managementPlanePresent
        self.notes = notes
    }
}

/// Third-party TCC-inheritance / embedded-interpreter class (never forges TCC grants).
public struct ThirdPartyTCCInheritanceState: Codable, Sendable, Equatable {
    /// High-value thick-client app paths sampled for inheritance class.
    public var thickClientAppPaths: [String]
    /// Embedded interpreter path hits (Node/Python/Ruby inside apps).
    public var embeddedInterpreterPaths: [String]
    /// Electron / CEF / helper path hits.
    public var electronHelperPaths: [String]
    /// Whether a TCC-inheritance surface was observed.
    public var inheritanceSurfacePresent: Bool?
    public var notes: [String]

    public init(
        thickClientAppPaths: [String] = [],
        embeddedInterpreterPaths: [String] = [],
        electronHelperPaths: [String] = [],
        inheritanceSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.thickClientAppPaths = thickClientAppPaths
        self.embeddedInterpreterPaths = embeddedInterpreterPaths
        self.electronHelperPaths = electronHelperPaths
        self.inheritanceSurfacePresent = inheritanceSurfacePresent
        self.notes = notes
    }
}

/// SSH-agent / key path lateral posture depth (never reads key material).
public struct SSHAgentKeyPathState: Codable, Sendable, Equatable {
    /// ssh-agent socket / agent plist path hits.
    public var agentSocketPaths: [String]
    /// authorized_keys / known_hosts / config path hits (paths only).
    public var keyPathHits: [String]
    /// sshd / OpenSSH support path hits.
    public var sshdSupportPaths: [String]
    /// Whether an SSH agent/key path lateral surface was observed.
    public var lateralPathSurfacePresent: Bool?
    public var notes: [String]

    public init(
        agentSocketPaths: [String] = [],
        keyPathHits: [String] = [],
        sshdSupportPaths: [String] = [],
        lateralPathSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.agentSocketPaths = agentSocketPaths
        self.keyPathHits = keyPathHits
        self.sshdSupportPaths = sshdSupportPaths
        self.lateralPathSurfacePresent = lateralPathSurfacePresent
        self.notes = notes
    }
}

// MARK: - Wave-9 2026 coverage residual surfaces

/// PackageKit installer design-based persistence posture (never builds pkgs or invokes installd).
public struct PackageKitInstallerDesignState: Codable, Sendable, Equatable {
    /// package_script_service / installd / system_installd path hits.
    public var installerServicePaths: [String]
    /// InstallerSandboxes / receipt DB / InstallHistory path hits.
    public var receiptAndHistoryPaths: [String]
    /// Installer Plugins path hits.
    public var installerPluginPaths: [String]
    /// pkgutil / installer / PackageKit tooling path hits.
    public var toolingPaths: [String]
    /// Whether an installer design surface was observed.
    public var designSurfacePresent: Bool?
    public var notes: [String]

    public init(
        installerServicePaths: [String] = [],
        receiptAndHistoryPaths: [String] = [],
        installerPluginPaths: [String] = [],
        toolingPaths: [String] = [],
        designSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.installerServicePaths = installerServicePaths
        self.receiptAndHistoryPaths = receiptAndHistoryPaths
        self.installerPluginPaths = installerPluginPaths
        self.toolingPaths = toolingPaths
        self.designSurfacePresent = designSurfacePresent
        self.notes = notes
    }
}

/// Archive / quarantine third-party extractor surface (never strips quarantine or crafts bypass archives).
public struct ArchiveQuarantineExtractorState: Codable, Sendable, Equatable {
    /// Third-party extractor app path hits (The Unarchiver, Keka, etc.).
    public var thirdPartyExtractorPaths: [String]
    /// Stock Archive Utility / ditto / tar path hits.
    public var stockExtractorPaths: [String]
    /// Downloads / archive drop path hints.
    public var archiveDropHints: [String]
    /// Whether an extractor surface was observed.
    public var extractorSurfacePresent: Bool?
    public var notes: [String]

    public init(
        thirdPartyExtractorPaths: [String] = [],
        stockExtractorPaths: [String] = [],
        archiveDropHints: [String] = [],
        extractorSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.thirdPartyExtractorPaths = thirdPartyExtractorPaths
        self.stockExtractorPaths = stockExtractorPaths
        self.archiveDropHints = archiveDropHints
        self.extractorSurfacePresent = extractorSurfacePresent
        self.notes = notes
    }
}

/// Info-stealer multi-app collection path plane (never dumps secrets/cookies/wallets).
public struct InfoStealerPathPlaneState: Codable, Sendable, Equatable {
    /// Browser-adjacent high-value path hits (beyond browser meta reuse).
    public var browserAdjacentPaths: [String]
    /// Mail / Messages / Notes / password-manager path hits.
    public var messagingAndVaultPaths: [String]
    /// Crypto wallet / cloud sync / Desktop-Documents scoop path hits.
    public var walletAndSyncPaths: [String]
    /// Whether a multi-app stealer collection surface was observed.
    public var collectionSurfacePresent: Bool?
    public var notes: [String]

    public init(
        browserAdjacentPaths: [String] = [],
        messagingAndVaultPaths: [String] = [],
        walletAndSyncPaths: [String] = [],
        collectionSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.browserAdjacentPaths = browserAdjacentPaths
        self.messagingAndVaultPaths = messagingAndVaultPaths
        self.walletAndSyncPaths = walletAndSyncPaths
        self.collectionSurfacePresent = collectionSurfacePresent
        self.notes = notes
    }
}

/// TCC / ESF visibility-depth posture (never dumps TCC.db rows or live-subscribes ESF without ROE).
public struct TCCESFVisibilityDepthState: Codable, Sendable, Equatable {
    /// TCC.db / TCC support path hits with listability flags encoded in notes.
    public var tccDbPathHits: [String]
    /// eslogger / log / unified-logging tooling path hits.
    public var visibilityToolPaths: [String]
    /// Privacy / logging preference path hits.
    public var privacyPrefPaths: [String]
    /// Heuristic depth label: strong / partial / thin.
    public var visibilityDepth: String?
    /// Whether a visibility-depth surface was observed.
    public var visibilitySurfacePresent: Bool?
    public var notes: [String]

    public init(
        tccDbPathHits: [String] = [],
        visibilityToolPaths: [String] = [],
        privacyPrefPaths: [String] = [],
        visibilityDepth: String? = nil,
        visibilitySurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.tccDbPathHits = tccDbPathHits
        self.visibilityToolPaths = visibilityToolPaths
        self.privacyPrefPaths = privacyPrefPaths
        self.visibilityDepth = visibilityDepth
        self.visibilitySurfacePresent = visibilitySurfacePresent
        self.notes = notes
    }
}

/// MDM profile shallow parse depth (PayloadType inventory only - never dumps secrets).
public struct MDMProfileParseDepthState: Codable, Sendable, Equatable {
    /// Paths of listable `.mobileconfig` / profile plists examined.
    public var examinedProfilePaths: [String]
    /// Distinct PayloadType strings observed (shallow).
    public var payloadTypes: [String]
    /// Count of profiles successfully shallow-parsed.
    public var parsedProfileCount: Int
    /// Whether any PayloadDisplayName keys were present (boolean class).
    public var displayNamePresent: Bool?
    /// Whether a parse-depth surface was observed.
    public var parseSurfacePresent: Bool?
    public var notes: [String]

    public init(
        examinedProfilePaths: [String] = [],
        payloadTypes: [String] = [],
        parsedProfileCount: Int = 0,
        displayNamePresent: Bool? = nil,
        parseSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.examinedProfilePaths = examinedProfilePaths
        self.payloadTypes = payloadTypes
        self.parsedProfileCount = parsedProfileCount
        self.displayNamePresent = displayNamePresent
        self.parseSurfacePresent = parseSurfacePresent
        self.notes = notes
    }
}


// MARK: - Wave-11 2026 coverage multi-plane surfaces

/// Custom URL scheme / document-handler delivery posture (never registers schemes or handlers).
public struct URLSchemeHandlerState: Codable, Sendable, Equatable {
    /// LaunchServices / LS handlers database path hits.
    public var launchServicesPaths: [String]
    /// Sample app Info.plist / CFBundleURLTypes adjacent path hits.
    public var urlTypePlistPaths: [String]
    /// Document type / UTI handler adjacency path hits.
    public var documentHandlerPaths: [String]
    /// Dual-use openers (open, osascript, openurl helpers) path hits.
    public var openerBinaryPaths: [String]
    /// Whether a URL scheme / document handler surface was observed.
    public var handlerSurfacePresent: Bool?
    public var notes: [String]

    public init(
        launchServicesPaths: [String] = [],
        urlTypePlistPaths: [String] = [],
        documentHandlerPaths: [String] = [],
        openerBinaryPaths: [String] = [],
        handlerSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.launchServicesPaths = launchServicesPaths
        self.urlTypePlistPaths = urlTypePlistPaths
        self.documentHandlerPaths = documentHandlerPaths
        self.openerBinaryPaths = openerBinaryPaths
        self.handlerSurfacePresent = handlerSurfacePresent
        self.notes = notes
    }
}

/// Launchd disabled / override depth posture (never disables security jobs).
public struct LaunchdOverrideDepthState: Codable, Sendable, Equatable {
    /// disabled.plist / overrides.plist path hits.
    public var overridePlistPaths: [String]
    /// Security-product label hints observed as disabled (path/meta only).
    public var securityDisabledHints: [String]
    /// KeepAlive / ThrottleInterval adjacency notes as path hits.
    public var keepaliveAdjacentPaths: [String]
    /// Whether an override-depth surface was observed.
    public var overrideSurfacePresent: Bool?
    public var notes: [String]

    public init(
        overridePlistPaths: [String] = [],
        securityDisabledHints: [String] = [],
        keepaliveAdjacentPaths: [String] = [],
        overrideSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.overridePlistPaths = overridePlistPaths
        self.securityDisabledHints = securityDisabledHints
        self.keepaliveAdjacentPaths = keepaliveAdjacentPaths
        self.overrideSurfacePresent = overrideSurfacePresent
        self.notes = notes
    }
}

/// Browser extension dual-use persistence / collection plane (never dumps extension secrets).
public struct BrowserExtensionDualUseState: Codable, Sendable, Equatable {
    /// Chromium-class extension root path hits.
    public var chromiumExtensionPaths: [String]
    /// Safari App Extension / WebExtension path hits.
    public var safariExtensionPaths: [String]
    /// Preferences / Secure Preferences adjacency path hits.
    public var preferencePaths: [String]
    /// Whether a dual-use extension surface was observed.
    public var extensionSurfacePresent: Bool?
    public var notes: [String]

    public init(
        chromiumExtensionPaths: [String] = [],
        safariExtensionPaths: [String] = [],
        preferencePaths: [String] = [],
        extensionSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.chromiumExtensionPaths = chromiumExtensionPaths
        self.safariExtensionPaths = safariExtensionPaths
        self.preferencePaths = preferencePaths
        self.extensionSurfacePresent = extensionSurfacePresent
        self.notes = notes
    }
}

/// Shortcuts / App Intents automation lateral posture (never runs shortcuts or forges intents).
public struct ShortcutsAppIntentsState: Codable, Sendable, Equatable {
    /// Shortcuts.app / Workflows database path hits.
    public var shortcutsAppPaths: [String]
    /// App Intents / AppShortcuts support path hits.
    public var appIntentsPaths: [String]
    /// Automation / personal automation preference path hits.
    public var automationPrefPaths: [String]
    /// Whether a Shortcuts/App Intents surface was observed.
    public var automationSurfacePresent: Bool?
    public var notes: [String]

    public init(
        shortcutsAppPaths: [String] = [],
        appIntentsPaths: [String] = [],
        automationPrefPaths: [String] = [],
        automationSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.shortcutsAppPaths = shortcutsAppPaths
        self.appIntentsPaths = appIntentsPaths
        self.automationPrefPaths = automationPrefPaths
        self.automationSurfacePresent = automationSurfacePresent
        self.notes = notes
    }
}


// MARK: - Wave-12 2026 coverage multi-plane surfaces

/// Webloc / Internet Location file delivery (never crafts phishing webloc/inetloc payloads or rewrites Internet Location files).
public struct WeblocInetlocDeliveryState: Codable, Sendable, Equatable {
    public var weblocSamplePaths: [String]
    public var inetlocSamplePaths: [String]
    public var dropFolderHints: [String]
    public var deliverySurfacePresent: Bool?
    public var notes: [String]

    public init(
        weblocSamplePaths: [String] = [],
        inetlocSamplePaths: [String] = [],
        dropFolderHints: [String] = [],
        deliverySurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.weblocSamplePaths = weblocSamplePaths
        self.inetlocSamplePaths = inetlocSamplePaths
        self.dropFolderHints = dropFolderHints
        self.deliverySurfacePresent = deliverySurfacePresent
        self.notes = notes
    }
}


/// Mail rules / Apple Mail automation persistence (never reads Mail contents or modifies user Mail rules).
public struct MailRulesAutomationState: Codable, Sendable, Equatable {
    public var mailAppPaths: [String]
    public var rulesPlistPaths: [String]
    public var scriptingAdjacentPaths: [String]
    public var rulesSurfacePresent: Bool?
    public var notes: [String]

    public init(
        mailAppPaths: [String] = [],
        rulesPlistPaths: [String] = [],
        scriptingAdjacentPaths: [String] = [],
        rulesSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.mailAppPaths = mailAppPaths
        self.rulesPlistPaths = rulesPlistPaths
        self.scriptingAdjacentPaths = scriptingAdjacentPaths
        self.rulesSurfacePresent = rulesSurfacePresent
        self.notes = notes
    }
}


/// Unified log / logarchive observation depth (never dumps private unified-log message bodies or force-collects other users' logarchives).
public struct UnifiedLogObservationState: Codable, Sendable, Equatable {
    public var logToolPaths: [String]
    public var logarchiveHints: [String]
    public var privacyPrefPaths: [String]
    public var observationSurfacePresent: Bool?
    public var notes: [String]

    public init(
        logToolPaths: [String] = [],
        logarchiveHints: [String] = [],
        privacyPrefPaths: [String] = [],
        observationSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.logToolPaths = logToolPaths
        self.logarchiveHints = logarchiveHints
        self.privacyPrefPaths = privacyPrefPaths
        self.observationSurfacePresent = observationSurfacePresent
        self.notes = notes
    }
}


/// Dock persistent apps / recent items dual-use (never modifies Dock.plist or plants malicious Dock entries).
public struct DockPersistenceSurfaceState: Codable, Sendable, Equatable {
    public var dockPlistPaths: [String]
    public var recentItemsPaths: [String]
    public var dockDbHints: [String]
    public var dockSurfacePresent: Bool?
    public var notes: [String]

    public init(
        dockPlistPaths: [String] = [],
        recentItemsPaths: [String] = [],
        dockDbHints: [String] = [],
        dockSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.dockPlistPaths = dockPlistPaths
        self.recentItemsPaths = recentItemsPaths
        self.dockDbHints = dockDbHints
        self.dockSurfacePresent = dockSurfacePresent
        self.notes = notes
    }
}


/// Compiled AppleScript / OSA delivery residual (never compiles malicious .scpt payloads or executes third-party AppleScripts).
public struct OsascriptScptDeliveryState: Codable, Sendable, Equatable {
    public var osaToolPaths: [String]
    public var scriptEditorPaths: [String]
    public var scptDropHints: [String]
    public var scptSurfacePresent: Bool?
    public var notes: [String]

    public init(
        osaToolPaths: [String] = [],
        scriptEditorPaths: [String] = [],
        scptDropHints: [String] = [],
        scptSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.osaToolPaths = osaToolPaths
        self.scriptEditorPaths = scriptEditorPaths
        self.scptDropHints = scptDropHints
        self.scptSurfacePresent = scptSurfacePresent
        self.notes = notes
    }
}


/// Network share / SMB mount dual-use lateral (never mounts attacker shares or writes credentials to NetAuth).
public struct NetworkShareMountState: Codable, Sendable, Equatable {
    public var smbClientPaths: [String]
    public var netAuthPaths: [String]
    public var mountPointHints: [String]
    public var shareSurfacePresent: Bool?
    public var notes: [String]

    public init(
        smbClientPaths: [String] = [],
        netAuthPaths: [String] = [],
        mountPointHints: [String] = [],
        shareSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.smbClientPaths = smbClientPaths
        self.netAuthPaths = netAuthPaths
        self.mountPointHints = mountPointHints
        self.shareSurfacePresent = shareSurfacePresent
        self.notes = notes
    }
}


// MARK: - Wave-13 2026 coverage multi-plane surfaces


/// Calendar / Reminders automation lateral surface (never reads event contents or creates malicious calendar invites).
public struct CalendarRemindersAutomationState: Codable, Sendable, Equatable {
    public var calendarAppPaths: [String]
    public var remindersPaths: [String]
    public var eventKitPaths: [String]
    public var automationSurfacePresent: Bool?
    public var notes: [String]

    public init(
        calendarAppPaths: [String] = [],
        remindersPaths: [String] = [],
        eventKitPaths: [String] = [],
        automationSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.calendarAppPaths = calendarAppPaths
        self.remindersPaths = remindersPaths
        self.eventKitPaths = eventKitPaths
        self.automationSurfacePresent = automationSurfacePresent
        self.notes = notes
    }
}


/// Gatekeeper assessment / syspolicyd history depth (never clears Gatekeeper assessments or disables syspolicyd).
public struct GatekeeperAssessmentHistoryState: Codable, Sendable, Equatable {
    public var syspolicydPaths: [String]
    public var assessmentDbPaths: [String]
    public var spctlToolPaths: [String]
    public var assessmentSurfacePresent: Bool?
    public var notes: [String]

    public init(
        syspolicydPaths: [String] = [],
        assessmentDbPaths: [String] = [],
        spctlToolPaths: [String] = [],
        assessmentSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.syspolicydPaths = syspolicydPaths
        self.assessmentDbPaths = assessmentDbPaths
        self.spctlToolPaths = spctlToolPaths
        self.assessmentSurfacePresent = assessmentSurfacePresent
        self.notes = notes
    }
}


/// Homebrew / third-party package manager dual-use (never installs packages or modifies Homebrew formulae).
public struct HomebrewPackageDualUseState: Codable, Sendable, Equatable {
    public var brewBinaryPaths: [String]
    public var cellarPaths: [String]
    public var tapPaths: [String]
    public var packageSurfacePresent: Bool?
    public var notes: [String]

    public init(
        brewBinaryPaths: [String] = [],
        cellarPaths: [String] = [],
        tapPaths: [String] = [],
        packageSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.brewBinaryPaths = brewBinaryPaths
        self.cellarPaths = cellarPaths
        self.tapPaths = tapPaths
        self.packageSurfacePresent = packageSurfacePresent
        self.notes = notes
    }
}


/// CUPS / printer dual-use residual surface (never submits print jobs or reconfigures CUPS remotely).
public struct CupsPrintDualUseState: Codable, Sendable, Equatable {
    public var cupsDaemonPaths: [String]
    public var ppdConfigPaths: [String]
    public var printToolPaths: [String]
    public var printSurfacePresent: Bool?
    public var notes: [String]

    public init(
        cupsDaemonPaths: [String] = [],
        ppdConfigPaths: [String] = [],
        printToolPaths: [String] = [],
        printSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.cupsDaemonPaths = cupsDaemonPaths
        self.ppdConfigPaths = ppdConfigPaths
        self.printToolPaths = printToolPaths
        self.printSurfacePresent = printSurfacePresent
        self.notes = notes
    }
}


/// ScreenCapture / screenshot privacy dual-use depth (never captures screens or dumps Screen Recording TCC rows).
public struct ScreenCapturePrivacyDualUseState: Codable, Sendable, Equatable {
    public var screencaptureToolPaths: [String]
    public var screenCaptureKitPaths: [String]
    public var screenshotDropHints: [String]
    public var captureSurfacePresent: Bool?
    public var notes: [String]

    public init(
        screencaptureToolPaths: [String] = [],
        screenCaptureKitPaths: [String] = [],
        screenshotDropHints: [String] = [],
        captureSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.screencaptureToolPaths = screencaptureToolPaths
        self.screenCaptureKitPaths = screenCaptureKitPaths
        self.screenshotDropHints = screenshotDropHints
        self.captureSurfacePresent = captureSurfacePresent
        self.notes = notes
    }
}


// MARK: - Wave-14 2026 coverage multi-plane surfaces


/// Automator workflow delivery residual (never executes Automator workflows or plants malicious .workflow bundles).
public struct AutomatorWorkflowState: Codable, Sendable, Equatable {
    public var automatorAppPaths: [String]
    public var workflowSamplePaths: [String]
    public var actionLibraryPaths: [String]
    public var workflowSurfacePresent: Bool?
    public var notes: [String]
    public init(
        automatorAppPaths: [String] = [],
        workflowSamplePaths: [String] = [],
        actionLibraryPaths: [String] = [],
        workflowSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.automatorAppPaths = automatorAppPaths
        self.workflowSamplePaths = workflowSamplePaths
        self.actionLibraryPaths = actionLibraryPaths
        self.workflowSurfacePresent = workflowSurfacePresent
        self.notes = notes
    }
}


/// iCloud Drive / Mobile Documents path plane (never enumerates iCloud file contents or exfiltrates Mobile Documents).
public struct IcloudDrivePathState: Codable, Sendable, Equatable {
    public var mobileDocumentsPaths: [String]
    public var icloudDrivePaths: [String]
    public var cloudKitPaths: [String]
    public var icloudPathSurfacePresent: Bool?
    public var notes: [String]
    public init(
        mobileDocumentsPaths: [String] = [],
        icloudDrivePaths: [String] = [],
        cloudKitPaths: [String] = [],
        icloudPathSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.mobileDocumentsPaths = mobileDocumentsPaths
        self.icloudDrivePaths = icloudDrivePaths
        self.cloudKitPaths = cloudKitPaths
        self.icloudPathSurfacePresent = icloudPathSurfacePresent
        self.notes = notes
    }
}


/// Bluetooth / Continuity proximity residual depth (never enables Bluetooth pairing or spoofs Continuity identities).
public struct BluetoothContinuityDepthState: Codable, Sendable, Equatable {
    public var bluetoothDaemonPaths: [String]
    public var continuitySupportPaths: [String]
    public var btPreferencePaths: [String]
    public var btContinuitySurfacePresent: Bool?
    public var notes: [String]
    public init(
        bluetoothDaemonPaths: [String] = [],
        continuitySupportPaths: [String] = [],
        btPreferencePaths: [String] = [],
        btContinuitySurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.bluetoothDaemonPaths = bluetoothDaemonPaths
        self.continuitySupportPaths = continuitySupportPaths
        self.btPreferencePaths = btPreferencePaths
        self.btContinuitySurfacePresent = btContinuitySurfacePresent
        self.notes = notes
    }
}


/// Font validation / ATS dual-use surface (never installs malicious fonts or disables font validation).
public struct FontValidationDualuseState: Codable, Sendable, Equatable {
    public var fontToolPaths: [String]
    public var atsSupportPaths: [String]
    public var userFontPaths: [String]
    public var fontSurfacePresent: Bool?
    public var notes: [String]
    public init(
        fontToolPaths: [String] = [],
        atsSupportPaths: [String] = [],
        userFontPaths: [String] = [],
        fontSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.fontToolPaths = fontToolPaths
        self.atsSupportPaths = atsSupportPaths
        self.userFontPaths = userFontPaths
        self.fontSurfacePresent = fontSurfacePresent
        self.notes = notes
    }
}


/// QuickLook thumbnail cache residual depth (never dumps QuickLook thumbnail bitmap contents as secret material).
public struct QuicklookCacheDepthState: Codable, Sendable, Equatable {
    public var quicklookDaemonPaths: [String]
    public var thumbnailCachePaths: [String]
    public var qlmanagePaths: [String]
    public var quicklookSurfacePresent: Bool?
    public var notes: [String]
    public init(
        quicklookDaemonPaths: [String] = [],
        thumbnailCachePaths: [String] = [],
        qlmanagePaths: [String] = [],
        quicklookSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.quicklookDaemonPaths = quicklookDaemonPaths
        self.thumbnailCachePaths = thumbnailCachePaths
        self.qlmanagePaths = qlmanagePaths
        self.quicklookSurfacePresent = quicklookSurfacePresent
        self.notes = notes
    }
}


/// DNS resolver / mDNSResponder dual-use surface (never rewrites resolver config or poisons DNS caches).
public struct DnsResolverDualuseState: Codable, Sendable, Equatable {
    public var mdnsResponderPaths: [String]
    public var resolverConfigPaths: [String]
    public var dnsToolPaths: [String]
    public var dnsSurfacePresent: Bool?
    public var notes: [String]
    public init(
        mdnsResponderPaths: [String] = [],
        resolverConfigPaths: [String] = [],
        dnsToolPaths: [String] = [],
        dnsSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.mdnsResponderPaths = mdnsResponderPaths
        self.resolverConfigPaths = resolverConfigPaths
        self.dnsToolPaths = dnsToolPaths
        self.dnsSurfacePresent = dnsSurfacePresent
        self.notes = notes
    }
}


/// LaunchServices QuarantineEvents DB residual depth (never deletes QuarantineEvents rows or clears LS quarantine history).
public struct LsQuarantineDbDepthState: Codable, Sendable, Equatable {
    public var quarantineDbPaths: [String]
    public var lsSupportPaths: [String]
    public var quarantineToolHints: [String]
    public var quarantineDbSurfacePresent: Bool?
    public var notes: [String]
    public init(
        quarantineDbPaths: [String] = [],
        lsSupportPaths: [String] = [],
        quarantineToolHints: [String] = [],
        quarantineDbSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.quarantineDbPaths = quarantineDbPaths
        self.lsSupportPaths = lsSupportPaths
        self.quarantineToolHints = quarantineToolHints
        self.quarantineDbSurfacePresent = quarantineDbSurfacePresent
        self.notes = notes
    }
}


/// PAM authentication module residual surface (never installs PAM modules or modifies /etc/pam.d).
public struct PamAuthModuleState: Codable, Sendable, Equatable {
    public var pamConfigPaths: [String]
    public var pamModulePaths: [String]
    public var authdSupportPaths: [String]
    public var pamSurfacePresent: Bool?
    public var notes: [String]
    public init(
        pamConfigPaths: [String] = [],
        pamModulePaths: [String] = [],
        authdSupportPaths: [String] = [],
        pamSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.pamConfigPaths = pamConfigPaths
        self.pamModulePaths = pamModulePaths
        self.authdSupportPaths = authdSupportPaths
        self.pamSurfacePresent = pamSurfacePresent
        self.notes = notes
    }
}


/// Cron / at job dual-use residual depth (never installs cron or at jobs outside the lab root).
public struct CronAtJobDepthState: Codable, Sendable, Equatable {
    public var cronBinaryPaths: [String]
    public var crontabPaths: [String]
    public var atJobPaths: [String]
    public var cronAtSurfacePresent: Bool?
    public var notes: [String]
    public init(
        cronBinaryPaths: [String] = [],
        crontabPaths: [String] = [],
        atJobPaths: [String] = [],
        cronAtSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.cronBinaryPaths = cronBinaryPaths
        self.crontabPaths = crontabPaths
        self.atJobPaths = atJobPaths
        self.cronAtSurfacePresent = cronAtSurfacePresent
        self.notes = notes
    }
}


/// Notes.app metadata collection path plane (never reads Notes body contents or exports note secrets).
public struct NotesMetadataPlaneState: Codable, Sendable, Equatable {
    public var notesAppPaths: [String]
    public var notesStorePaths: [String]
    public var notesContainerPaths: [String]
    public var notesSurfacePresent: Bool?
    public var notes: [String]
    public init(
        notesAppPaths: [String] = [],
        notesStorePaths: [String] = [],
        notesContainerPaths: [String] = [],
        notesSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.notesAppPaths = notesAppPaths
        self.notesStorePaths = notesStorePaths
        self.notesContainerPaths = notesContainerPaths
        self.notesSurfacePresent = notesSurfacePresent
        self.notes = notes
    }
}


// MARK: - Wave-15 2026 coverage multi-plane surfaces


/// Photos.app library collection path plane (never reads photo contents or exports Photo Library media).
public struct PhotosLibraryPathState: Codable, Sendable, Equatable {
    public var photosAppPaths: [String]
    public var photosLibraryPaths: [String]
    public var photosSupportPaths: [String]
    public var photosSurfacePresent: Bool?
    public var notes: [String]
    public init(
        photosAppPaths: [String] = [],
        photosLibraryPaths: [String] = [],
        photosSupportPaths: [String] = [],
        photosSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.photosAppPaths = photosAppPaths
        self.photosLibraryPaths = photosLibraryPaths
        self.photosSupportPaths = photosSupportPaths
        self.photosSurfacePresent = photosSurfacePresent
        self.notes = notes
    }
}


/// VPN configuration dual-use residual surface (never installs VPN profiles or rewrites network extension VPN configs).
public struct VpnConfigDualuseState: Codable, Sendable, Equatable {
    public var vpnFrameworkPaths: [String]
    public var vpnPrefPaths: [String]
    public var vpnToolPaths: [String]
    public var vpnSurfacePresent: Bool?
    public var notes: [String]
    public init(
        vpnFrameworkPaths: [String] = [],
        vpnPrefPaths: [String] = [],
        vpnToolPaths: [String] = [],
        vpnSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.vpnFrameworkPaths = vpnFrameworkPaths
        self.vpnPrefPaths = vpnPrefPaths
        self.vpnToolPaths = vpnToolPaths
        self.vpnSurfacePresent = vpnSurfacePresent
        self.notes = notes
    }
}


/// App sandbox container residual depth (never breaks app sandbox or forges container entitlements).
public struct SandboxContainerDepthState: Codable, Sendable, Equatable {
    public var containerRootPaths: [String]
    public var sandboxProfilePaths: [String]
    public var seatbeltSupportPaths: [String]
    public var sandboxSurfacePresent: Bool?
    public var notes: [String]
    public init(
        containerRootPaths: [String] = [],
        sandboxProfilePaths: [String] = [],
        seatbeltSupportPaths: [String] = [],
        sandboxSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.containerRootPaths = containerRootPaths
        self.sandboxProfilePaths = sandboxProfilePaths
        self.seatbeltSupportPaths = seatbeltSupportPaths
        self.sandboxSurfacePresent = sandboxSurfacePresent
        self.notes = notes
    }
}


/// XPC Mach service residual depth (never registers XPC services or injects into Mach ports).
public struct XpcMachServiceDepthState: Codable, Sendable, Equatable {
    public var xpcBootstrapPaths: [String]
    public var machServicePlistPaths: [String]
    public var xpcToolPaths: [String]
    public var xpcMachSurfacePresent: Bool?
    public var notes: [String]
    public init(
        xpcBootstrapPaths: [String] = [],
        machServicePlistPaths: [String] = [],
        xpcToolPaths: [String] = [],
        xpcMachSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.xpcBootstrapPaths = xpcBootstrapPaths
        self.machServicePlistPaths = machServicePlistPaths
        self.xpcToolPaths = xpcToolPaths
        self.xpcMachSurfacePresent = xpcMachSurfacePresent
        self.notes = notes
    }
}


/// Time Machine local snapshot residual depth (never mounts snapshots for data theft or deletes backup catalogs).
public struct TmLocalSnapshotDepthState: Codable, Sendable, Equatable {
    public var tmUtilPaths: [String]
    public var snapshotStorePaths: [String]
    public var tmPrefPaths: [String]
    public var tmSnapshotSurfacePresent: Bool?
    public var notes: [String]
    public init(
        tmUtilPaths: [String] = [],
        snapshotStorePaths: [String] = [],
        tmPrefPaths: [String] = [],
        tmSnapshotSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.tmUtilPaths = tmUtilPaths
        self.snapshotStorePaths = snapshotStorePaths
        self.tmPrefPaths = tmPrefPaths
        self.tmSnapshotSurfacePresent = tmSnapshotSurfacePresent
        self.notes = notes
    }
}


/// Emond legacy rules residual depth (never installs emond rules or enables the legacy event monitor daemon).
public struct EmondLegacyDepthState: Codable, Sendable, Equatable {
    public var emondBinaryPaths: [String]
    public var emondRulePaths: [String]
    public var emondSupportPaths: [String]
    public var emondSurfacePresent: Bool?
    public var notes: [String]
    public init(
        emondBinaryPaths: [String] = [],
        emondRulePaths: [String] = [],
        emondSupportPaths: [String] = [],
        emondSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.emondBinaryPaths = emondBinaryPaths
        self.emondRulePaths = emondRulePaths
        self.emondSupportPaths = emondSupportPaths
        self.emondSurfacePresent = emondSurfacePresent
        self.notes = notes
    }
}


/// Screen Sharing / ARD residual depth (never enables Screen Sharing or ARD, never connects to remote desktops).
public struct ScreenSharingArdDepthState: Codable, Sendable, Equatable {
    public var screenSharingAppPaths: [String]
    public var ardAgentPaths: [String]
    public var remoteMgmtPrefPaths: [String]
    public var ardSurfacePresent: Bool?
    public var notes: [String]
    public init(
        screenSharingAppPaths: [String] = [],
        ardAgentPaths: [String] = [],
        remoteMgmtPrefPaths: [String] = [],
        ardSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.screenSharingAppPaths = screenSharingAppPaths
        self.ardAgentPaths = ardAgentPaths
        self.remoteMgmtPrefPaths = remoteMgmtPrefPaths
        self.ardSurfacePresent = ardSurfacePresent
        self.notes = notes
    }
}


/// Keychain ACL path residual surface (never dumps keychain items, passwords, or private keys).
public struct KeychainAclPathState: Codable, Sendable, Equatable {
    public var keychainDbPaths: [String]
    public var securityToolPaths: [String]
    public var keychainSupportPaths: [String]
    public var keychainAclSurfacePresent: Bool?
    public var notes: [String]
    public init(
        keychainDbPaths: [String] = [],
        securityToolPaths: [String] = [],
        keychainSupportPaths: [String] = [],
        keychainAclSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.keychainDbPaths = keychainDbPaths
        self.securityToolPaths = securityToolPaths
        self.keychainSupportPaths = keychainSupportPaths
        self.keychainAclSurfacePresent = keychainAclSurfacePresent
        self.notes = notes
    }
}


/// Python runtime dual-use residual surface (never executes third-party Python payloads or drops malicious site-packages).
public struct PythonRuntimeDualuseState: Codable, Sendable, Equatable {
    public var pythonBinaryPaths: [String]
    public var sitePackagePaths: [String]
    public var pythonFrameworkPaths: [String]
    public var pythonSurfacePresent: Bool?
    public var notes: [String]
    public init(
        pythonBinaryPaths: [String] = [],
        sitePackagePaths: [String] = [],
        pythonFrameworkPaths: [String] = [],
        pythonSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.pythonBinaryPaths = pythonBinaryPaths
        self.sitePackagePaths = sitePackagePaths
        self.pythonFrameworkPaths = pythonFrameworkPaths
        self.pythonSurfacePresent = pythonSurfacePresent
        self.notes = notes
    }
}


/// Shell plugin manager dual-use residual (never installs oh-my-zsh plugins or rewrites shell init for persistence).
public struct ShellPluginManagerState: Codable, Sendable, Equatable {
    public var omzPaths: [String]
    public var pluginDirPaths: [String]
    public var shellInitPaths: [String]
    public var shellPluginSurfacePresent: Bool?
    public var notes: [String]
    public init(
        omzPaths: [String] = [],
        pluginDirPaths: [String] = [],
        shellInitPaths: [String] = [],
        shellPluginSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.omzPaths = omzPaths
        self.pluginDirPaths = pluginDirPaths
        self.shellInitPaths = shellInitPaths
        self.shellPluginSurfacePresent = shellPluginSurfacePresent
        self.notes = notes
    }
}


// MARK: - Wave-16 2026 coverage multi-plane surfaces (25 themes / 50 half-pairs)


/// AirPlay receiver dual-use residual (never enables AirPlay Receiver or spoofs AirPlay targets).
public struct AirplayReceiverSurfaceState: Codable, Sendable, Equatable {
    public var airplayDaemonPaths: [String]
    public var airplayPrefPaths: [String]
    public var airplayHelperPaths: [String]
    public var airplaySurfacePresent: Bool?
    public var notes: [String]
    public init(
        airplayDaemonPaths: [String] = [],
        airplayPrefPaths: [String] = [],
        airplayHelperPaths: [String] = [],
        airplaySurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.airplayDaemonPaths = airplayDaemonPaths
        self.airplayPrefPaths = airplayPrefPaths
        self.airplayHelperPaths = airplayHelperPaths
        self.airplaySurfacePresent = airplaySurfacePresent
        self.notes = notes
    }
}


/// Handoff / Universal Clipboard residual depth (never reads Universal Clipboard contents or forges Handoff activity).
public struct HandoffClipboardDepthState: Codable, Sendable, Equatable {
    public var handoffFrameworkPaths: [String]
    public var clipboardPathHits: [String]
    public var sharingdPaths: [String]
    public var handoffSurfacePresent: Bool?
    public var notes: [String]
    public init(
        handoffFrameworkPaths: [String] = [],
        clipboardPathHits: [String] = [],
        sharingdPaths: [String] = [],
        handoffSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.handoffFrameworkPaths = handoffFrameworkPaths
        self.clipboardPathHits = clipboardPathHits
        self.sharingdPaths = sharingdPaths
        self.handoffSurfacePresent = handoffSurfacePresent
        self.notes = notes
    }
}


/// iMessage / Messages path collection plane (never reads Messages database contents or exports chat transcripts).
public struct ImessagePathPlaneState: Codable, Sendable, Equatable {
    public var messagesAppPaths: [String]
    public var messagesDbPaths: [String]
    public var messagesPrefPaths: [String]
    public var imessageSurfacePresent: Bool?
    public var notes: [String]
    public init(
        messagesAppPaths: [String] = [],
        messagesDbPaths: [String] = [],
        messagesPrefPaths: [String] = [],
        imessageSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.messagesAppPaths = messagesAppPaths
        self.messagesDbPaths = messagesDbPaths
        self.messagesPrefPaths = messagesPrefPaths
        self.imessageSurfacePresent = imessageSurfacePresent
        self.notes = notes
    }
}


/// FaceTime / camera pipeline dual-use surface (never activates camera/mic or dumps FaceTime call history contents).
public struct FacetimeCameraSurfaceState: Codable, Sendable, Equatable {
    public var facetimeAppPaths: [String]
    public var avConferencePaths: [String]
    public var facetimePrefPaths: [String]
    public var facetimeSurfacePresent: Bool?
    public var notes: [String]
    public init(
        facetimeAppPaths: [String] = [],
        avConferencePaths: [String] = [],
        facetimePrefPaths: [String] = [],
        facetimeSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.facetimeAppPaths = facetimeAppPaths
        self.avConferencePaths = avConferencePaths
        self.facetimePrefPaths = facetimePrefPaths
        self.facetimeSurfacePresent = facetimeSurfacePresent
        self.notes = notes
    }
}


/// Finder Sync extension dual-use surface (never installs Finder Sync extensions or rewrites Finder preferences for abuse).
public struct FinderSyncExtensionState: Codable, Sendable, Equatable {
    public var finderSyncFrameworkPaths: [String]
    public var appScriptPaths: [String]
    public var finderPrefPaths: [String]
    public var finderSyncSurfacePresent: Bool?
    public var notes: [String]
    public init(
        finderSyncFrameworkPaths: [String] = [],
        appScriptPaths: [String] = [],
        finderPrefPaths: [String] = [],
        finderSyncSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.finderSyncFrameworkPaths = finderSyncFrameworkPaths
        self.appScriptPaths = appScriptPaths
        self.finderPrefPaths = finderPrefPaths
        self.finderSyncSurfacePresent = finderSyncSurfacePresent
        self.notes = notes
    }
}


/// File Provider domain residual surface (never registers malicious File Provider domains or exfiltrates provider caches).
public struct FileproviderDomainState: Codable, Sendable, Equatable {
    public var fileProviderFrameworkPaths: [String]
    public var cloudStoragePaths: [String]
    public var fileProviderLaunchPaths: [String]
    public var fileProviderSurfacePresent: Bool?
    public var notes: [String]
    public init(
        fileProviderFrameworkPaths: [String] = [],
        cloudStoragePaths: [String] = [],
        fileProviderLaunchPaths: [String] = [],
        fileProviderSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.fileProviderFrameworkPaths = fileProviderFrameworkPaths
        self.cloudStoragePaths = cloudStoragePaths
        self.fileProviderLaunchPaths = fileProviderLaunchPaths
        self.fileProviderSurfacePresent = fileProviderSurfacePresent
        self.notes = notes
    }
}


/// Notification Center residual depth (never dumps notification body contents or forges notification payloads).
public struct NotificationCenterDepthState: Codable, Sendable, Equatable {
    public var notificationFrameworkPaths: [String]
    public var notificationStorePaths: [String]
    public var notificationPrefPaths: [String]
    public var notificationSurfacePresent: Bool?
    public var notes: [String]
    public init(
        notificationFrameworkPaths: [String] = [],
        notificationStorePaths: [String] = [],
        notificationPrefPaths: [String] = [],
        notificationSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.notificationFrameworkPaths = notificationFrameworkPaths
        self.notificationStorePaths = notificationStorePaths
        self.notificationPrefPaths = notificationPrefPaths
        self.notificationSurfacePresent = notificationSurfacePresent
        self.notes = notes
    }
}


/// Siri / Suggestions data-access residual (never dumps Siri transcripts or Suggestions databases contents).
public struct SiriSuggestionsPlaneState: Codable, Sendable, Equatable {
    public var siriFrameworkPaths: [String]
    public var suggestionsStorePaths: [String]
    public var siriPrefPaths: [String]
    public var siriSurfacePresent: Bool?
    public var notes: [String]
    public init(
        siriFrameworkPaths: [String] = [],
        suggestionsStorePaths: [String] = [],
        siriPrefPaths: [String] = [],
        siriSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.siriFrameworkPaths = siriFrameworkPaths
        self.suggestionsStorePaths = suggestionsStorePaths
        self.siriPrefPaths = siriPrefPaths
        self.siriSurfacePresent = siriSurfacePresent
        self.notes = notes
    }
}


/// Spotlight importer residual depth (never installs malicious Spotlight importers or dumps mdworker index contents).
public struct SpotlightImporterDepthState: Codable, Sendable, Equatable {
    public var metadataToolPaths: [String]
    public var spotlightImporterPaths: [String]
    public var mdsLaunchPaths: [String]
    public var spotlightImporterSurfacePresent: Bool?
    public var notes: [String]
    public init(
        metadataToolPaths: [String] = [],
        spotlightImporterPaths: [String] = [],
        mdsLaunchPaths: [String] = [],
        spotlightImporterSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.metadataToolPaths = metadataToolPaths
        self.spotlightImporterPaths = spotlightImporterPaths
        self.mdsLaunchPaths = mdsLaunchPaths
        self.spotlightImporterSurfacePresent = spotlightImporterSurfacePresent
        self.notes = notes
    }
}


/// Contacts database path residual plane (never exports contact cards or dumps AddressBook database contents).
public struct ContactsPathPlaneState: Codable, Sendable, Equatable {
    public var contactsAppPaths: [String]
    public var addressBookPaths: [String]
    public var contactsPrefPaths: [String]
    public var contactsSurfacePresent: Bool?
    public var notes: [String]
    public init(
        contactsAppPaths: [String] = [],
        addressBookPaths: [String] = [],
        contactsPrefPaths: [String] = [],
        contactsSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.contactsAppPaths = contactsAppPaths
        self.addressBookPaths = addressBookPaths
        self.contactsPrefPaths = contactsPrefPaths
        self.contactsSurfacePresent = contactsSurfacePresent
        self.notes = notes
    }
}


/// Calendar server / CalDAV residual surface (never reads calendar event bodies or credentials from CalDAV stores).
public struct CalendarServerPathState: Codable, Sendable, Equatable {
    public var caldavFrameworkPaths: [String]
    public var calendarsStorePaths: [String]
    public var calendarAgentPaths: [String]
    public var caldavSurfacePresent: Bool?
    public var notes: [String]
    public init(
        caldavFrameworkPaths: [String] = [],
        calendarsStorePaths: [String] = [],
        calendarAgentPaths: [String] = [],
        caldavSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.caldavFrameworkPaths = caldavFrameworkPaths
        self.calendarsStorePaths = calendarsStorePaths
        self.calendarAgentPaths = calendarAgentPaths
        self.caldavSurfacePresent = caldavSurfacePresent
        self.notes = notes
    }
}


/// Reminders cloud path residual plane (never reads reminder titles/bodies or exports Reminders databases).
public struct RemindersCloudPathState: Codable, Sendable, Equatable {
    public var remindersAppPaths: [String]
    public var remindersStorePaths: [String]
    public var remindersPrefPaths: [String]
    public var remindersCloudSurfacePresent: Bool?
    public var notes: [String]
    public init(
        remindersAppPaths: [String] = [],
        remindersStorePaths: [String] = [],
        remindersPrefPaths: [String] = [],
        remindersCloudSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.remindersAppPaths = remindersAppPaths
        self.remindersStorePaths = remindersStorePaths
        self.remindersPrefPaths = remindersPrefPaths
        self.remindersCloudSurfacePresent = remindersCloudSurfacePresent
        self.notes = notes
    }
}


/// Maps / location services residual plane (never dumps location history or spoofs CoreLocation positions).
public struct MapsLocationPathState: Codable, Sendable, Equatable {
    public var mapsAppPaths: [String]
    public var mapsCachePaths: [String]
    public var locationdPaths: [String]
    public var mapsLocationSurfacePresent: Bool?
    public var notes: [String]
    public init(
        mapsAppPaths: [String] = [],
        mapsCachePaths: [String] = [],
        locationdPaths: [String] = [],
        mapsLocationSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.mapsAppPaths = mapsAppPaths
        self.mapsCachePaths = mapsCachePaths
        self.locationdPaths = locationdPaths
        self.mapsLocationSurfacePresent = mapsLocationSurfacePresent
        self.notes = notes
    }
}


/// Weather / widget data residual plane (never dumps weather personalization data or widget timeline contents).
public struct WeatherWidgetPathState: Codable, Sendable, Equatable {
    public var weatherAppPaths: [String]
    public var weatherContainerPaths: [String]
    public var widgetServicePaths: [String]
    public var weatherSurfacePresent: Bool?
    public var notes: [String]
    public init(
        weatherAppPaths: [String] = [],
        weatherContainerPaths: [String] = [],
        widgetServicePaths: [String] = [],
        weatherSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.weatherAppPaths = weatherAppPaths
        self.weatherContainerPaths = weatherContainerPaths
        self.widgetServicePaths = widgetServicePaths
        self.weatherSurfacePresent = weatherSurfacePresent
        self.notes = notes
    }
}


/// Music / media library path residual (never exports Music library media or DRM material).
public struct MusicLibraryPathState: Codable, Sendable, Equatable {
    public var musicAppPaths: [String]
    public var musicLibraryPaths: [String]
    public var musicPrefPaths: [String]
    public var musicSurfacePresent: Bool?
    public var notes: [String]
    public init(
        musicAppPaths: [String] = [],
        musicLibraryPaths: [String] = [],
        musicPrefPaths: [String] = [],
        musicSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.musicAppPaths = musicAppPaths
        self.musicLibraryPaths = musicLibraryPaths
        self.musicPrefPaths = musicPrefPaths
        self.musicSurfacePresent = musicSurfacePresent
        self.notes = notes
    }
}


/// Books / EPUB path residual plane (never extracts EPUB contents or Books annotations as bulk export).
public struct BooksPathPlaneState: Codable, Sendable, Equatable {
    public var booksAppPaths: [String]
    public var booksContainerPaths: [String]
    public var booksPrefPaths: [String]
    public var booksSurfacePresent: Bool?
    public var notes: [String]
    public init(
        booksAppPaths: [String] = [],
        booksContainerPaths: [String] = [],
        booksPrefPaths: [String] = [],
        booksSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.booksAppPaths = booksAppPaths
        self.booksContainerPaths = booksContainerPaths
        self.booksPrefPaths = booksPrefPaths
        self.booksSurfacePresent = booksSurfacePresent
        self.notes = notes
    }
}


/// Podcasts library path residual (never dumps podcast episode files or account tokens).
public struct PodcastsPathPlaneState: Codable, Sendable, Equatable {
    public var podcastsAppPaths: [String]
    public var podcastsStorePaths: [String]
    public var podcastsPrefPaths: [String]
    public var podcastsSurfacePresent: Bool?
    public var notes: [String]
    public init(
        podcastsAppPaths: [String] = [],
        podcastsStorePaths: [String] = [],
        podcastsPrefPaths: [String] = [],
        podcastsSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.podcastsAppPaths = podcastsAppPaths
        self.podcastsStorePaths = podcastsStorePaths
        self.podcastsPrefPaths = podcastsPrefPaths
        self.podcastsSurfacePresent = podcastsSurfacePresent
        self.notes = notes
    }
}


/// TV.app residual path plane (never dumps TV.app media caches or account material).
public struct TvAppPathPlaneState: Codable, Sendable, Equatable {
    public var tvAppPaths: [String]
    public var tvContainerPaths: [String]
    public var tvPrefPaths: [String]
    public var tvSurfacePresent: Bool?
    public var notes: [String]
    public init(
        tvAppPaths: [String] = [],
        tvContainerPaths: [String] = [],
        tvPrefPaths: [String] = [],
        tvSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.tvAppPaths = tvAppPaths
        self.tvContainerPaths = tvContainerPaths
        self.tvPrefPaths = tvPrefPaths
        self.tvSurfacePresent = tvSurfacePresent
        self.notes = notes
    }
}


/// HomeKit residual path plane (never enumerates HomeKit accessory secrets or pairs devices).
public struct HomekitPathPlaneState: Codable, Sendable, Equatable {
    public var homeAppPaths: [String]
    public var homeKitStorePaths: [String]
    public var homedPaths: [String]
    public var homekitSurfacePresent: Bool?
    public var notes: [String]
    public init(
        homeAppPaths: [String] = [],
        homeKitStorePaths: [String] = [],
        homedPaths: [String] = [],
        homekitSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.homeAppPaths = homeAppPaths
        self.homeKitStorePaths = homeKitStorePaths
        self.homedPaths = homedPaths
        self.homekitSurfacePresent = homekitSurfacePresent
        self.notes = notes
    }
}


/// Health app residual path plane (never exports HealthKit samples or medical records).
public struct HealthPathPlaneState: Codable, Sendable, Equatable {
    public var healthAppPaths: [String]
    public var healthStorePaths: [String]
    public var healthdPaths: [String]
    public var healthSurfacePresent: Bool?
    public var notes: [String]
    public init(
        healthAppPaths: [String] = [],
        healthStorePaths: [String] = [],
        healthdPaths: [String] = [],
        healthSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.healthAppPaths = healthAppPaths
        self.healthStorePaths = healthStorePaths
        self.healthdPaths = healthdPaths
        self.healthSurfacePresent = healthSurfacePresent
        self.notes = notes
    }
}


/// Wallet / pass residual path plane (never dumps pass contents, payment tokens, or card data).
public struct WalletPassPathState: Codable, Sendable, Equatable {
    public var walletAppPaths: [String]
    public var passesStorePaths: [String]
    public var passdPaths: [String]
    public var walletSurfacePresent: Bool?
    public var notes: [String]
    public init(
        walletAppPaths: [String] = [],
        passesStorePaths: [String] = [],
        passdPaths: [String] = [],
        walletSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.walletAppPaths = walletAppPaths
        self.passesStorePaths = passesStorePaths
        self.passdPaths = passdPaths
        self.walletSurfacePresent = walletSurfacePresent
        self.notes = notes
    }
}


/// Find My residual path plane (never queries Find My device locations or dumps owner tokens).
public struct FindmyPathPlaneState: Codable, Sendable, Equatable {
    public var findMyAppPaths: [String]
    public var findMyCachePaths: [String]
    public var fmfdPaths: [String]
    public var findmySurfacePresent: Bool?
    public var notes: [String]
    public init(
        findMyAppPaths: [String] = [],
        findMyCachePaths: [String] = [],
        fmfdPaths: [String] = [],
        findmySurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.findMyAppPaths = findMyAppPaths
        self.findMyCachePaths = findMyCachePaths
        self.fmfdPaths = fmfdPaths
        self.findmySurfacePresent = findmySurfacePresent
        self.notes = notes
    }
}


/// Shortcuts iCloud sync residual depth (never executes Shortcuts or dumps iCloud-synced automation databases).
public struct ShortcutsIcloudSyncState: Codable, Sendable, Equatable {
    public var shortcutsAppPaths: [String]
    public var shortcutsDbPaths: [String]
    public var shortcutsPrefPaths: [String]
    public var shortcutsIcloudSurfacePresent: Bool?
    public var notes: [String]
    public init(
        shortcutsAppPaths: [String] = [],
        shortcutsDbPaths: [String] = [],
        shortcutsPrefPaths: [String] = [],
        shortcutsIcloudSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.shortcutsAppPaths = shortcutsAppPaths
        self.shortcutsDbPaths = shortcutsDbPaths
        self.shortcutsPrefPaths = shortcutsPrefPaths
        self.shortcutsIcloudSurfacePresent = shortcutsIcloudSurfacePresent
        self.notes = notes
    }
}


/// Device management profile residual depth (never installs configuration profiles or enrolls hosts in MDM).
public struct DevicemanagementProfileState: Codable, Sendable, Equatable {
    public var profilesToolPaths: [String]
    public var managedPrefPaths: [String]
    public var mdmClientPaths: [String]
    public var deviceMgmtSurfacePresent: Bool?
    public var notes: [String]
    public init(
        profilesToolPaths: [String] = [],
        managedPrefPaths: [String] = [],
        mdmClientPaths: [String] = [],
        deviceMgmtSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.profilesToolPaths = profilesToolPaths
        self.managedPrefPaths = managedPrefPaths
        self.mdmClientPaths = mdmClientPaths
        self.deviceMgmtSurfacePresent = deviceMgmtSurfacePresent
        self.notes = notes
    }
}


/// Software Update catalog residual surface (never points SUS catalogs at attacker mirrors or tampers with update plists).
public struct SoftwareupdateCatalogState: Codable, Sendable, Equatable {
    public var softwareUpdateToolPaths: [String]
    public var softwareUpdatePrefPaths: [String]
    public var softwareUpdateDaemonPaths: [String]
    public var softwareUpdateSurfacePresent: Bool?
    public var notes: [String]
    public init(
        softwareUpdateToolPaths: [String] = [],
        softwareUpdatePrefPaths: [String] = [],
        softwareUpdateDaemonPaths: [String] = [],
        softwareUpdateSurfacePresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.softwareUpdateToolPaths = softwareUpdateToolPaths
        self.softwareUpdatePrefPaths = softwareUpdatePrefPaths
        self.softwareUpdateDaemonPaths = softwareUpdateDaemonPaths
        self.softwareUpdateSurfacePresent = softwareUpdateSurfacePresent
        self.notes = notes
    }
}

/// Credential path presence only - never secret material.
public struct CredPathHit: Codable, Sendable, Equatable {
    public var kind: String
    public var path: String
    public var exists: Bool

    public init(kind: String, path: String, exists: Bool) {
        self.kind = kind
        self.path = path
        self.exists = exists
    }
}

/// LOOBin inventory hit.
public struct LOOBinHit: Codable, Sendable, Equatable {
    public var name: String
    public var path: String
    public var present: Bool
    public var tactics: [String]

    public init(name: String, path: String, present: Bool, tactics: [String] = []) {
        self.name = name
        self.path = path
        self.present = present
        self.tactics = tactics
    }
}

/// Running application summary (NSWorkspace-level).
public struct RunningAppInfo: Codable, Sendable, Equatable {
    public var name: String
    public var bundleIdentifier: String?
    public var path: String?

    public init(name: String, bundleIdentifier: String? = nil, path: String? = nil) {
        self.name = name
        self.bundleIdentifier = bundleIdentifier
        self.path = path
    }
}

/// MDM / management posture (path + profile-store heuristics; no payload secrets).
public struct MDMState: Codable, Sendable, Equatable {
    public var enrolled: Bool?
    public var vendorHints: [String]
    /// Top-level filenames under `/Library/Managed Preferences/` (presence only).
    public var managedPreferenceNames: [String]
    /// Whether a configuration-profile store directory was readable.
    public var profileStoreReadable: Bool?
    /// Count of mobileconfig-like / profile files when the store is listable.
    public var profileFileCount: Int?
    /// Presence of PPPC / TCC configuration-profile policy plist (path only).
    public var pppcPolicyPresent: Bool?
    public var notes: [String]

    public init(
        enrolled: Bool? = nil,
        vendorHints: [String] = [],
        managedPreferenceNames: [String] = [],
        profileStoreReadable: Bool? = nil,
        profileFileCount: Int? = nil,
        pppcPolicyPresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.enrolled = enrolled
        self.vendorHints = vendorHints
        self.managedPreferenceNames = managedPreferenceNames
        self.profileStoreReadable = profileStoreReadable
        self.profileFileCount = profileFileCount
        self.pppcPolicyPresent = pppcPolicyPresent
        self.notes = notes
    }
}

/// Identity posture (AD bind / Platform SSO) via filesystem heuristics.
public struct IdentityState: Codable, Sendable, Equatable {
    public var adBound: Bool?
    public var platformSSO: Bool?
    /// Kerberos config present (`edu.mit.Kerberos` prefs and/or `/etc/krb5.conf`).
    public var kerberosConfigPresent: Bool?
    /// Open Directory / DirectoryService config paths observed.
    public var odConfigPaths: [String]
    /// Platform SSO / AppSSO support paths observed.
    public var ssoPaths: [String]
    public var notes: [String]

    public init(
        adBound: Bool? = nil,
        platformSSO: Bool? = nil,
        kerberosConfigPresent: Bool? = nil,
        odConfigPaths: [String] = [],
        ssoPaths: [String] = [],
        notes: [String] = []
    ) {
        self.adBound = adBound
        self.platformSSO = platformSSO
        self.kerberosConfigPresent = kerberosConfigPresent
        self.odConfigPaths = odConfigPaths
        self.ssoPaths = ssoPaths
        self.notes = notes
    }
}

/// Ranked LOOBin plan entry for assess discovery/persist/execute planning.
public struct LOLPlanEntry: Codable, Sendable, Equatable {
    public var name: String
    public var path: String
    public var goal: String
    /// 0–100; higher = noisier / more OPSEC risk.
    public var noiseScore: Int
    public var tccImpact: [String]
    public var rankReason: String

    public init(
        name: String,
        path: String,
        goal: String,
        noiseScore: Int,
        tccImpact: [String] = [],
        rankReason: String = ""
    ) {
        self.name = name
        self.path = path
        self.goal = goal
        self.noiseScore = noiseScore
        self.tccImpact = tccImpact
        self.rankReason = rankReason
    }
}

/// Protections snapshot (SIP / Gatekeeper / FileVault - may be partial).
public struct ProtectionsState: Codable, Sendable, Equatable {
    public var sipEnabled: Bool?
    public var gatekeeperEnabled: Bool?
    public var fileVaultOn: Bool?
    public var notes: [String]

    public init(
        sipEnabled: Bool? = nil,
        gatekeeperEnabled: Bool? = nil,
        fileVaultOn: Bool? = nil,
        notes: [String] = []
    ) {
        self.sipEnabled = sipEnabled
        self.gatekeeperEnabled = gatekeeperEnabled
        self.fileVaultOn = fileVaultOn
        self.notes = notes
    }
}

/// Local sharing / remote access posture (path heuristics only, no port scan).
public struct NetworkState: Codable, Sendable, Equatable {
    /// Conservative "likely enabled" signals (nil = unknown).
    public var remoteLoginSSH: Bool?
    public var screenSharingARD: Bool?
    public var fileSharingSMB: Bool?
    /// Path inventory (presence ≠ enabled).
    public var remoteLoginPlistPresent: Bool?
    public var screenSharingPlistPresent: Bool?
    public var fileSharingPlistPresent: Bool?
    public var remoteManagementPrefsPresent: Bool?
    public var sshdConfigPresent: Bool?
    public var notes: [String]

    public init(
        remoteLoginSSH: Bool? = nil,
        screenSharingARD: Bool? = nil,
        fileSharingSMB: Bool? = nil,
        remoteLoginPlistPresent: Bool? = nil,
        screenSharingPlistPresent: Bool? = nil,
        fileSharingPlistPresent: Bool? = nil,
        remoteManagementPrefsPresent: Bool? = nil,
        sshdConfigPresent: Bool? = nil,
        notes: [String] = []
    ) {
        self.remoteLoginSSH = remoteLoginSSH
        self.screenSharingARD = screenSharingARD
        self.fileSharingSMB = fileSharingSMB
        self.remoteLoginPlistPresent = remoteLoginPlistPresent
        self.screenSharingPlistPresent = screenSharingPlistPresent
        self.fileSharingPlistPresent = fileSharingPlistPresent
        self.remoteManagementPrefsPresent = remoteManagementPrefsPresent
        self.sshdConfigPresent = sshdConfigPresent
        self.notes = notes
    }
}

/// Versioned host snapshot produced by collectors.
public struct CollectedState: Codable, Sendable, Equatable {
    public var schemaVersion: String
    public var collectedAt: Date
    public var host: HostState?
    public var securityProducts: [SecurityProductHit]
    public var launchAgents: [LaunchAgentEntry]
    public var systemLaunchAgents: [LaunchAgentEntry]
    public var launchDaemons: [LaunchAgentEntry]
    public var btmStorePresent: Bool?
    public var loginItemPaths: [String]
    public var loginItems: LoginItemsState?
    public var browserMeta: [BrowserMetaEntry]
    public var codesignSamples: [CodesignSample]
    public var dylibRiskHits: [DylibRiskHit]
    public var injectabilityHits: [InjectabilityHit]
    public var systemExtensionPaths: [String]
    public var privilegedHelperTools: [String]
    public var tcc: TCCState?
    public var credPaths: [CredPathHit]
    public var loobins: [LOOBinHit]
    /// Ranked LOOBin plans (discovery / persist / execute) from LOLPlanner.
    public var lolPlans: [LOLPlanEntry]
    public var runningApps: [RunningAppInfo]
    public var mdm: MDMState?
    public var identity: IdentityState?
    public var protections: ProtectionsState?
    public var network: NetworkState?
    /// Endpoint Security / EDR sensor posture.
    public var esf: ESFPostureState?
    /// OS patch-debt / CVE suggester context.
    public var patchDebt: PatchDebtState?
    /// Launch-constraint injectability truth.
    public var launchConstraints: LaunchConstraintState?
    /// NetworkExtension / VPN / content-filter posture.
    public var networkExtension: NetworkExtensionState?
    /// Authorization rights / auth.db / PackageKit surface.
    public var authRights: AuthRightsState?
    /// Developer toolchain dual-use surface.
    public var developerToolchain: DeveloperToolchainState?
    /// Time Machine / local snapshot data-access surface.
    public var timeMachine: TimeMachineState?
    /// User-writable mobileconfig / profile sideload risk.
    public var configProfileSideload: ConfigProfileSideloadState?
    /// App sandbox / entitlement thick-client surface.
    public var appSandboxEntitlements: AppSandboxEntitlementState?
    /// Notarization / stapling trust depth.
    public var notarizationStapling: NotarizationStaplingState?
    /// Virtualization / container dual-use surface.
    public var virtualizationContainers: VirtualizationContainerState?
    /// Continuity / AirDrop proximity posture.
    public var continuityAirDrop: ContinuityAirDropState?
    /// FileVault / recovery escrow posture.
    public var fileVaultEscrow: FileVaultEscrowState?
    /// ClickFix / paste-and-run Terminal delivery posture.
    public var clickFixTerminalDelivery: ClickFixTerminalDeliveryState?
    /// Remote Apple Events / EPPC lateral posture.
    public var remoteAppleEvents: RemoteAppleEventsState?
    /// Spotlight / mdworker / on-device AI-cache data-access.
    public var spotlightAICache: SpotlightAICacheState?
    /// Security-product management-plane unload class.
    public var securityMgmtPlane: SecurityMgmtPlaneState?
    /// Third-party TCC inheritance / embedded interpreter.
    public var thirdPartyTCCInheritance: ThirdPartyTCCInheritanceState?
    /// SSH-agent / key path lateral depth.
    public var sshAgentKeyPath: SSHAgentKeyPathState?
    /// PackageKit installer design-based persistence.
    public var packageKitInstallerDesign: PackageKitInstallerDesignState?
    /// Archive / quarantine third-party extractor.
    public var archiveQuarantineExtractor: ArchiveQuarantineExtractorState?
    /// Info-stealer multi-app collection path plane.
    public var infoStealerPathPlane: InfoStealerPathPlaneState?
    /// TCC / ESF visibility-depth posture.
    public var tccEsfVisibilityDepth: TCCESFVisibilityDepthState?
    /// MDM profile shallow parse depth.
    public var mdmProfileParseDepth: MDMProfileParseDepthState?
    /// Custom URL scheme / document-handler surface.
    public var urlSchemeHandler: URLSchemeHandlerState?
    /// Launchd disabled / override depth.
    public var launchdOverrideDepth: LaunchdOverrideDepthState?
    /// Browser extension dual-use plane.
    public var browserExtensionDualUse: BrowserExtensionDualUseState?
    /// Shortcuts / App Intents automation lateral.
    public var shortcutsAppIntents: ShortcutsAppIntentsState?
    /// Webloc / Internet Location file delivery.
    public var weblocInetlocDelivery: WeblocInetlocDeliveryState?
    /// Mail rules / Apple Mail automation persistence.
    public var mailRulesAutomation: MailRulesAutomationState?
    /// Unified log / logarchive observation depth.
    public var unifiedLogObservation: UnifiedLogObservationState?
    /// Dock persistent apps / recent items dual-use.
    public var dockPersistenceSurface: DockPersistenceSurfaceState?
    /// Compiled AppleScript / OSA delivery residual.
    public var osascriptScptDelivery: OsascriptScptDeliveryState?
    /// Network share / SMB mount dual-use lateral.
    public var networkShareMount: NetworkShareMountState?
    /// Calendar / Reminders automation lateral surface.
    public var calendarRemindersAutomation: CalendarRemindersAutomationState?
    /// Gatekeeper assessment / syspolicyd history depth.
    public var gatekeeperAssessmentHistory: GatekeeperAssessmentHistoryState?
    /// Homebrew / third-party package manager dual-use.
    public var homebrewPackageDualUse: HomebrewPackageDualUseState?
    /// CUPS / printer dual-use residual surface.
    public var cupsPrintDualUse: CupsPrintDualUseState?
    /// ScreenCapture / screenshot privacy dual-use depth.
    public var screenCapturePrivacyDualUse: ScreenCapturePrivacyDualUseState?
    /// Automator workflow delivery residual.
    public var automatorWorkflow: AutomatorWorkflowState?
    /// iCloud Drive / Mobile Documents path plane.
    public var icloudDrivePath: IcloudDrivePathState?
    /// Bluetooth / Continuity proximity residual depth.
    public var bluetoothContinuityDepth: BluetoothContinuityDepthState?
    /// Font validation / ATS dual-use surface.
    public var fontValidationDualuse: FontValidationDualuseState?
    /// QuickLook thumbnail cache residual depth.
    public var quicklookCacheDepth: QuicklookCacheDepthState?
    /// DNS resolver / mDNSResponder dual-use surface.
    public var dnsResolverDualuse: DnsResolverDualuseState?
    /// LaunchServices QuarantineEvents DB residual depth.
    public var lsQuarantineDbDepth: LsQuarantineDbDepthState?
    /// PAM authentication module residual surface.
    public var pamAuthModule: PamAuthModuleState?
    /// Cron / at job dual-use residual depth.
    public var cronAtJobDepth: CronAtJobDepthState?
    /// Notes.app metadata collection path plane.
    public var notesMetadataPlane: NotesMetadataPlaneState?
    /// Photos.app library collection path plane.
    public var photosLibraryPath: PhotosLibraryPathState?
    /// VPN configuration dual-use residual surface.
    public var vpnConfigDualuse: VpnConfigDualuseState?
    /// App sandbox container residual depth.
    public var sandboxContainerDepth: SandboxContainerDepthState?
    /// XPC Mach service residual depth.
    public var xpcMachServiceDepth: XpcMachServiceDepthState?
    /// Time Machine local snapshot residual depth.
    public var tmLocalSnapshotDepth: TmLocalSnapshotDepthState?
    /// Emond legacy rules residual depth.
    public var emondLegacyDepth: EmondLegacyDepthState?
    /// Screen Sharing / ARD residual depth.
    public var screenSharingArdDepth: ScreenSharingArdDepthState?
    /// Keychain ACL path residual surface.
    public var keychainAclPath: KeychainAclPathState?
    /// Python runtime dual-use residual surface.
    public var pythonRuntimeDualuse: PythonRuntimeDualuseState?
    /// Shell plugin manager dual-use residual.
    public var shellPluginManager: ShellPluginManagerState?
    /// AirPlay receiver dual-use residual.
    public var airplayReceiverSurface: AirplayReceiverSurfaceState?
    /// Handoff / Universal Clipboard residual depth.
    public var handoffClipboardDepth: HandoffClipboardDepthState?
    /// iMessage / Messages path collection plane.
    public var imessagePathPlane: ImessagePathPlaneState?
    /// FaceTime / camera pipeline dual-use surface.
    public var facetimeCameraSurface: FacetimeCameraSurfaceState?
    /// Finder Sync extension dual-use surface.
    public var finderSyncExtension: FinderSyncExtensionState?
    /// File Provider domain residual surface.
    public var fileproviderDomain: FileproviderDomainState?
    /// Notification Center residual depth.
    public var notificationCenterDepth: NotificationCenterDepthState?
    /// Siri / Suggestions data-access residual.
    public var siriSuggestionsPlane: SiriSuggestionsPlaneState?
    /// Spotlight importer residual depth.
    public var spotlightImporterDepth: SpotlightImporterDepthState?
    /// Contacts database path residual plane.
    public var contactsPathPlane: ContactsPathPlaneState?
    /// Calendar server / CalDAV residual surface.
    public var calendarServerPath: CalendarServerPathState?
    /// Reminders cloud path residual plane.
    public var remindersCloudPath: RemindersCloudPathState?
    /// Maps / location services residual plane.
    public var mapsLocationPath: MapsLocationPathState?
    /// Weather / widget data residual plane.
    public var weatherWidgetPath: WeatherWidgetPathState?
    /// Music / media library path residual.
    public var musicLibraryPath: MusicLibraryPathState?
    /// Books / EPUB path residual plane.
    public var booksPathPlane: BooksPathPlaneState?
    /// Podcasts library path residual.
    public var podcastsPathPlane: PodcastsPathPlaneState?
    /// TV.app residual path plane.
    public var tvAppPathPlane: TvAppPathPlaneState?
    /// HomeKit residual path plane.
    public var homekitPathPlane: HomekitPathPlaneState?
    /// Health app residual path plane.
    public var healthPathPlane: HealthPathPlaneState?
    /// Wallet / pass residual path plane.
    public var walletPassPath: WalletPassPathState?
    /// Find My residual path plane.
    public var findmyPathPlane: FindmyPathPlaneState?
    /// Shortcuts iCloud sync residual depth.
    public var shortcutsIcloudSync: ShortcutsIcloudSyncState?
    /// Device management profile residual depth.
    public var devicemanagementProfile: DevicemanagementProfileState?
    /// Software Update catalog residual surface.
    public var softwareupdateCatalog: SoftwareupdateCatalogState?
    public var collectorNotes: [String: String]
    public var deniedCollectors: [String]

    public init(
        schemaVersion: String = RootstockCore.schemaVersion,
        collectedAt: Date = Date(),
        host: HostState? = nil,
        securityProducts: [SecurityProductHit] = [],
        launchAgents: [LaunchAgentEntry] = [],
        systemLaunchAgents: [LaunchAgentEntry] = [],
        launchDaemons: [LaunchAgentEntry] = [],
        btmStorePresent: Bool? = nil,
        loginItemPaths: [String] = [],
        loginItems: LoginItemsState? = nil,
        browserMeta: [BrowserMetaEntry] = [],
        codesignSamples: [CodesignSample] = [],
        dylibRiskHits: [DylibRiskHit] = [],
        injectabilityHits: [InjectabilityHit] = [],
        systemExtensionPaths: [String] = [],
        privilegedHelperTools: [String] = [],
        tcc: TCCState? = nil,
        credPaths: [CredPathHit] = [],
        loobins: [LOOBinHit] = [],
        lolPlans: [LOLPlanEntry] = [],
        runningApps: [RunningAppInfo] = [],
        mdm: MDMState? = nil,
        identity: IdentityState? = nil,
        protections: ProtectionsState? = nil,
        network: NetworkState? = nil,
        esf: ESFPostureState? = nil,
        patchDebt: PatchDebtState? = nil,
        launchConstraints: LaunchConstraintState? = nil,
        networkExtension: NetworkExtensionState? = nil,
        authRights: AuthRightsState? = nil,
        developerToolchain: DeveloperToolchainState? = nil,
        timeMachine: TimeMachineState? = nil,
        configProfileSideload: ConfigProfileSideloadState? = nil,
        appSandboxEntitlements: AppSandboxEntitlementState? = nil,
        notarizationStapling: NotarizationStaplingState? = nil,
        virtualizationContainers: VirtualizationContainerState? = nil,
        continuityAirDrop: ContinuityAirDropState? = nil,
        fileVaultEscrow: FileVaultEscrowState? = nil,
        clickFixTerminalDelivery: ClickFixTerminalDeliveryState? = nil,
        remoteAppleEvents: RemoteAppleEventsState? = nil,
        spotlightAICache: SpotlightAICacheState? = nil,
        securityMgmtPlane: SecurityMgmtPlaneState? = nil,
        thirdPartyTCCInheritance: ThirdPartyTCCInheritanceState? = nil,
        sshAgentKeyPath: SSHAgentKeyPathState? = nil,
        packageKitInstallerDesign: PackageKitInstallerDesignState? = nil,
        archiveQuarantineExtractor: ArchiveQuarantineExtractorState? = nil,
        infoStealerPathPlane: InfoStealerPathPlaneState? = nil,
        tccEsfVisibilityDepth: TCCESFVisibilityDepthState? = nil,
        mdmProfileParseDepth: MDMProfileParseDepthState? = nil,
        urlSchemeHandler: URLSchemeHandlerState? = nil,
        launchdOverrideDepth: LaunchdOverrideDepthState? = nil,
        browserExtensionDualUse: BrowserExtensionDualUseState? = nil,
        shortcutsAppIntents: ShortcutsAppIntentsState? = nil,
        weblocInetlocDelivery: WeblocInetlocDeliveryState? = nil,
        mailRulesAutomation: MailRulesAutomationState? = nil,
        unifiedLogObservation: UnifiedLogObservationState? = nil,
        dockPersistenceSurface: DockPersistenceSurfaceState? = nil,
        osascriptScptDelivery: OsascriptScptDeliveryState? = nil,
        networkShareMount: NetworkShareMountState? = nil,
        calendarRemindersAutomation: CalendarRemindersAutomationState? = nil,
        gatekeeperAssessmentHistory: GatekeeperAssessmentHistoryState? = nil,
        homebrewPackageDualUse: HomebrewPackageDualUseState? = nil,
        cupsPrintDualUse: CupsPrintDualUseState? = nil,
        screenCapturePrivacyDualUse: ScreenCapturePrivacyDualUseState? = nil,
        automatorWorkflow: AutomatorWorkflowState? = nil,
        icloudDrivePath: IcloudDrivePathState? = nil,
        bluetoothContinuityDepth: BluetoothContinuityDepthState? = nil,
        fontValidationDualuse: FontValidationDualuseState? = nil,
        quicklookCacheDepth: QuicklookCacheDepthState? = nil,
        dnsResolverDualuse: DnsResolverDualuseState? = nil,
        lsQuarantineDbDepth: LsQuarantineDbDepthState? = nil,
        pamAuthModule: PamAuthModuleState? = nil,
        cronAtJobDepth: CronAtJobDepthState? = nil,
        notesMetadataPlane: NotesMetadataPlaneState? = nil,
        photosLibraryPath: PhotosLibraryPathState? = nil,
        vpnConfigDualuse: VpnConfigDualuseState? = nil,
        sandboxContainerDepth: SandboxContainerDepthState? = nil,
        xpcMachServiceDepth: XpcMachServiceDepthState? = nil,
        tmLocalSnapshotDepth: TmLocalSnapshotDepthState? = nil,
        emondLegacyDepth: EmondLegacyDepthState? = nil,
        screenSharingArdDepth: ScreenSharingArdDepthState? = nil,
        keychainAclPath: KeychainAclPathState? = nil,
        pythonRuntimeDualuse: PythonRuntimeDualuseState? = nil,
        shellPluginManager: ShellPluginManagerState? = nil,
        airplayReceiverSurface: AirplayReceiverSurfaceState? = nil,
        handoffClipboardDepth: HandoffClipboardDepthState? = nil,
        imessagePathPlane: ImessagePathPlaneState? = nil,
        facetimeCameraSurface: FacetimeCameraSurfaceState? = nil,
        finderSyncExtension: FinderSyncExtensionState? = nil,
        fileproviderDomain: FileproviderDomainState? = nil,
        notificationCenterDepth: NotificationCenterDepthState? = nil,
        siriSuggestionsPlane: SiriSuggestionsPlaneState? = nil,
        spotlightImporterDepth: SpotlightImporterDepthState? = nil,
        contactsPathPlane: ContactsPathPlaneState? = nil,
        calendarServerPath: CalendarServerPathState? = nil,
        remindersCloudPath: RemindersCloudPathState? = nil,
        mapsLocationPath: MapsLocationPathState? = nil,
        weatherWidgetPath: WeatherWidgetPathState? = nil,
        musicLibraryPath: MusicLibraryPathState? = nil,
        booksPathPlane: BooksPathPlaneState? = nil,
        podcastsPathPlane: PodcastsPathPlaneState? = nil,
        tvAppPathPlane: TvAppPathPlaneState? = nil,
        homekitPathPlane: HomekitPathPlaneState? = nil,
        healthPathPlane: HealthPathPlaneState? = nil,
        walletPassPath: WalletPassPathState? = nil,
        findmyPathPlane: FindmyPathPlaneState? = nil,
        shortcutsIcloudSync: ShortcutsIcloudSyncState? = nil,
        devicemanagementProfile: DevicemanagementProfileState? = nil,
        softwareupdateCatalog: SoftwareupdateCatalogState? = nil,
        collectorNotes: [String: String] = [:],
        deniedCollectors: [String] = []
    ) {
        self.schemaVersion = schemaVersion
        self.collectedAt = collectedAt
        self.host = host
        self.securityProducts = securityProducts
        self.launchAgents = launchAgents
        self.systemLaunchAgents = systemLaunchAgents
        self.launchDaemons = launchDaemons
        self.btmStorePresent = btmStorePresent
        self.loginItemPaths = loginItemPaths
        self.loginItems = loginItems
        self.browserMeta = browserMeta
        self.codesignSamples = codesignSamples
        self.dylibRiskHits = dylibRiskHits
        self.injectabilityHits = injectabilityHits
        self.systemExtensionPaths = systemExtensionPaths
        self.privilegedHelperTools = privilegedHelperTools
        self.tcc = tcc
        self.credPaths = credPaths
        self.loobins = loobins
        self.lolPlans = lolPlans
        self.runningApps = runningApps
        self.mdm = mdm
        self.identity = identity
        self.protections = protections
        self.network = network
        self.esf = esf
        self.patchDebt = patchDebt
        self.launchConstraints = launchConstraints
        self.networkExtension = networkExtension
        self.authRights = authRights
        self.developerToolchain = developerToolchain
        self.timeMachine = timeMachine
        self.configProfileSideload = configProfileSideload
        self.appSandboxEntitlements = appSandboxEntitlements
        self.notarizationStapling = notarizationStapling
        self.virtualizationContainers = virtualizationContainers
        self.continuityAirDrop = continuityAirDrop
        self.fileVaultEscrow = fileVaultEscrow
        self.clickFixTerminalDelivery = clickFixTerminalDelivery
        self.remoteAppleEvents = remoteAppleEvents
        self.spotlightAICache = spotlightAICache
        self.securityMgmtPlane = securityMgmtPlane
        self.thirdPartyTCCInheritance = thirdPartyTCCInheritance
        self.sshAgentKeyPath = sshAgentKeyPath
        self.packageKitInstallerDesign = packageKitInstallerDesign
        self.archiveQuarantineExtractor = archiveQuarantineExtractor
        self.infoStealerPathPlane = infoStealerPathPlane
        self.tccEsfVisibilityDepth = tccEsfVisibilityDepth
        self.mdmProfileParseDepth = mdmProfileParseDepth
        self.urlSchemeHandler = urlSchemeHandler
        self.launchdOverrideDepth = launchdOverrideDepth
        self.browserExtensionDualUse = browserExtensionDualUse
        self.shortcutsAppIntents = shortcutsAppIntents
        self.weblocInetlocDelivery = weblocInetlocDelivery
        self.mailRulesAutomation = mailRulesAutomation
        self.unifiedLogObservation = unifiedLogObservation
        self.dockPersistenceSurface = dockPersistenceSurface
        self.osascriptScptDelivery = osascriptScptDelivery
        self.networkShareMount = networkShareMount
        self.calendarRemindersAutomation = calendarRemindersAutomation
        self.gatekeeperAssessmentHistory = gatekeeperAssessmentHistory
        self.homebrewPackageDualUse = homebrewPackageDualUse
        self.cupsPrintDualUse = cupsPrintDualUse
        self.screenCapturePrivacyDualUse = screenCapturePrivacyDualUse
        self.automatorWorkflow = automatorWorkflow
        self.icloudDrivePath = icloudDrivePath
        self.bluetoothContinuityDepth = bluetoothContinuityDepth
        self.fontValidationDualuse = fontValidationDualuse
        self.quicklookCacheDepth = quicklookCacheDepth
        self.dnsResolverDualuse = dnsResolverDualuse
        self.lsQuarantineDbDepth = lsQuarantineDbDepth
        self.pamAuthModule = pamAuthModule
        self.cronAtJobDepth = cronAtJobDepth
        self.notesMetadataPlane = notesMetadataPlane
        self.photosLibraryPath = photosLibraryPath
        self.vpnConfigDualuse = vpnConfigDualuse
        self.sandboxContainerDepth = sandboxContainerDepth
        self.xpcMachServiceDepth = xpcMachServiceDepth
        self.tmLocalSnapshotDepth = tmLocalSnapshotDepth
        self.emondLegacyDepth = emondLegacyDepth
        self.screenSharingArdDepth = screenSharingArdDepth
        self.keychainAclPath = keychainAclPath
        self.pythonRuntimeDualuse = pythonRuntimeDualuse
        self.shellPluginManager = shellPluginManager
        self.airplayReceiverSurface = airplayReceiverSurface
        self.handoffClipboardDepth = handoffClipboardDepth
        self.imessagePathPlane = imessagePathPlane
        self.facetimeCameraSurface = facetimeCameraSurface
        self.finderSyncExtension = finderSyncExtension
        self.fileproviderDomain = fileproviderDomain
        self.notificationCenterDepth = notificationCenterDepth
        self.siriSuggestionsPlane = siriSuggestionsPlane
        self.spotlightImporterDepth = spotlightImporterDepth
        self.contactsPathPlane = contactsPathPlane
        self.calendarServerPath = calendarServerPath
        self.remindersCloudPath = remindersCloudPath
        self.mapsLocationPath = mapsLocationPath
        self.weatherWidgetPath = weatherWidgetPath
        self.musicLibraryPath = musicLibraryPath
        self.booksPathPlane = booksPathPlane
        self.podcastsPathPlane = podcastsPathPlane
        self.tvAppPathPlane = tvAppPathPlane
        self.homekitPathPlane = homekitPathPlane
        self.healthPathPlane = healthPathPlane
        self.walletPassPath = walletPassPath
        self.findmyPathPlane = findmyPathPlane
        self.shortcutsIcloudSync = shortcutsIcloudSync
        self.devicemanagementProfile = devicemanagementProfile
        self.softwareupdateCatalog = softwareupdateCatalog
        self.collectorNotes = collectorNotes
        self.deniedCollectors = deniedCollectors
    }

    /// Merge non-nil sections from another state (later wins for scalars).
    public mutating func merge(_ other: CollectedState) {
        if let host = other.host { self.host = host }
        if !other.securityProducts.isEmpty { self.securityProducts = other.securityProducts }
        if !other.launchAgents.isEmpty { self.launchAgents = other.launchAgents }
        if !other.systemLaunchAgents.isEmpty { self.systemLaunchAgents = other.systemLaunchAgents }
        if !other.launchDaemons.isEmpty { self.launchDaemons = other.launchDaemons }
        if let btm = other.btmStorePresent { self.btmStorePresent = btm }
        if !other.loginItemPaths.isEmpty { self.loginItemPaths = other.loginItemPaths }
        if let loginItems = other.loginItems { self.loginItems = loginItems }
        if !other.browserMeta.isEmpty { self.browserMeta = other.browserMeta }
        if !other.codesignSamples.isEmpty { self.codesignSamples = other.codesignSamples }
        if !other.dylibRiskHits.isEmpty { self.dylibRiskHits = other.dylibRiskHits }
        if !other.injectabilityHits.isEmpty { self.injectabilityHits = other.injectabilityHits }
        if !other.systemExtensionPaths.isEmpty { self.systemExtensionPaths = other.systemExtensionPaths }
        if !other.privilegedHelperTools.isEmpty { self.privilegedHelperTools = other.privilegedHelperTools }
        if let tcc = other.tcc {
            if var existing = self.tcc {
                if tcc.fullDiskAccessLikely != nil {
                    existing.fullDiskAccessLikely = tcc.fullDiskAccessLikely
                }
                if tcc.probeMethod != "stub" { existing.probeMethod = tcc.probeMethod }
                existing.notes.append(contentsOf: tcc.notes)
                let mergedSignals = Array(Set(existing.domainSignals + tcc.domainSignals)).sorted()
                existing.domainSignals = mergedSignals
                self.tcc = existing
            } else {
                self.tcc = tcc
            }
        }
        if !other.credPaths.isEmpty { self.credPaths = other.credPaths }
        if !other.loobins.isEmpty { self.loobins = other.loobins }
        if !other.lolPlans.isEmpty { self.lolPlans = other.lolPlans }
        if !other.runningApps.isEmpty { self.runningApps = other.runningApps }
        if let mdm = other.mdm { self.mdm = mdm }
        if let identity = other.identity { self.identity = identity }
        if let protections = other.protections { self.protections = protections }
        if let network = other.network { self.network = network }
        if let esf = other.esf { self.esf = esf }
        if let patchDebt = other.patchDebt { self.patchDebt = patchDebt }
        if let launchConstraints = other.launchConstraints {
            self.launchConstraints = launchConstraints
        }
        if let networkExtension = other.networkExtension {
            self.networkExtension = networkExtension
        }
        if let authRights = other.authRights { self.authRights = authRights }
        if let developerToolchain = other.developerToolchain {
            self.developerToolchain = developerToolchain
        }
        if let timeMachine = other.timeMachine { self.timeMachine = timeMachine }
        if let configProfileSideload = other.configProfileSideload {
            self.configProfileSideload = configProfileSideload
        }
        if let appSandboxEntitlements = other.appSandboxEntitlements {
            self.appSandboxEntitlements = appSandboxEntitlements
        }
        if let notarizationStapling = other.notarizationStapling {
            self.notarizationStapling = notarizationStapling
        }
        if let virtualizationContainers = other.virtualizationContainers {
            self.virtualizationContainers = virtualizationContainers
        }
        if let continuityAirDrop = other.continuityAirDrop {
            self.continuityAirDrop = continuityAirDrop
        }
        if let fileVaultEscrow = other.fileVaultEscrow {
            self.fileVaultEscrow = fileVaultEscrow
        }
        if let clickFixTerminalDelivery = other.clickFixTerminalDelivery {
            self.clickFixTerminalDelivery = clickFixTerminalDelivery
        }
        if let remoteAppleEvents = other.remoteAppleEvents {
            self.remoteAppleEvents = remoteAppleEvents
        }
        if let spotlightAICache = other.spotlightAICache {
            self.spotlightAICache = spotlightAICache
        }
        if let securityMgmtPlane = other.securityMgmtPlane {
            self.securityMgmtPlane = securityMgmtPlane
        }
        if let thirdPartyTCCInheritance = other.thirdPartyTCCInheritance {
            self.thirdPartyTCCInheritance = thirdPartyTCCInheritance
        }
        if let sshAgentKeyPath = other.sshAgentKeyPath {
            self.sshAgentKeyPath = sshAgentKeyPath
        }
        if let packageKitInstallerDesign = other.packageKitInstallerDesign {
            self.packageKitInstallerDesign = packageKitInstallerDesign
        }
        if let archiveQuarantineExtractor = other.archiveQuarantineExtractor {
            self.archiveQuarantineExtractor = archiveQuarantineExtractor
        }
        if let infoStealerPathPlane = other.infoStealerPathPlane {
            self.infoStealerPathPlane = infoStealerPathPlane
        }
        if let tccEsfVisibilityDepth = other.tccEsfVisibilityDepth {
            self.tccEsfVisibilityDepth = tccEsfVisibilityDepth
        }
        if let mdmProfileParseDepth = other.mdmProfileParseDepth {
            self.mdmProfileParseDepth = mdmProfileParseDepth
        }
        if let urlSchemeHandler = other.urlSchemeHandler {
            self.urlSchemeHandler = urlSchemeHandler
        }
        if let launchdOverrideDepth = other.launchdOverrideDepth {
            self.launchdOverrideDepth = launchdOverrideDepth
        }
        if let browserExtensionDualUse = other.browserExtensionDualUse {
            self.browserExtensionDualUse = browserExtensionDualUse
        }
        if let shortcutsAppIntents = other.shortcutsAppIntents {
            self.shortcutsAppIntents = shortcutsAppIntents
        }
        if let weblocInetlocDelivery = other.weblocInetlocDelivery {
            self.weblocInetlocDelivery = weblocInetlocDelivery
        }
        if let mailRulesAutomation = other.mailRulesAutomation {
            self.mailRulesAutomation = mailRulesAutomation
        }
        if let unifiedLogObservation = other.unifiedLogObservation {
            self.unifiedLogObservation = unifiedLogObservation
        }
        if let dockPersistenceSurface = other.dockPersistenceSurface {
            self.dockPersistenceSurface = dockPersistenceSurface
        }
        if let osascriptScptDelivery = other.osascriptScptDelivery {
            self.osascriptScptDelivery = osascriptScptDelivery
        }
        if let networkShareMount = other.networkShareMount {
            self.networkShareMount = networkShareMount
        }
        if let calendarRemindersAutomation = other.calendarRemindersAutomation {
            self.calendarRemindersAutomation = calendarRemindersAutomation
        }
        if let gatekeeperAssessmentHistory = other.gatekeeperAssessmentHistory {
            self.gatekeeperAssessmentHistory = gatekeeperAssessmentHistory
        }
        if let homebrewPackageDualUse = other.homebrewPackageDualUse {
            self.homebrewPackageDualUse = homebrewPackageDualUse
        }
        if let cupsPrintDualUse = other.cupsPrintDualUse {
            self.cupsPrintDualUse = cupsPrintDualUse
        }
        if let screenCapturePrivacyDualUse = other.screenCapturePrivacyDualUse {
            self.screenCapturePrivacyDualUse = screenCapturePrivacyDualUse
        }
        if let automatorWorkflow = other.automatorWorkflow {
            self.automatorWorkflow = automatorWorkflow
        }
        if let icloudDrivePath = other.icloudDrivePath {
            self.icloudDrivePath = icloudDrivePath
        }
        if let bluetoothContinuityDepth = other.bluetoothContinuityDepth {
            self.bluetoothContinuityDepth = bluetoothContinuityDepth
        }
        if let fontValidationDualuse = other.fontValidationDualuse {
            self.fontValidationDualuse = fontValidationDualuse
        }
        if let quicklookCacheDepth = other.quicklookCacheDepth {
            self.quicklookCacheDepth = quicklookCacheDepth
        }
        if let dnsResolverDualuse = other.dnsResolverDualuse {
            self.dnsResolverDualuse = dnsResolverDualuse
        }
        if let lsQuarantineDbDepth = other.lsQuarantineDbDepth {
            self.lsQuarantineDbDepth = lsQuarantineDbDepth
        }
        if let pamAuthModule = other.pamAuthModule {
            self.pamAuthModule = pamAuthModule
        }
        if let cronAtJobDepth = other.cronAtJobDepth {
            self.cronAtJobDepth = cronAtJobDepth
        }
        if let notesMetadataPlane = other.notesMetadataPlane {
            self.notesMetadataPlane = notesMetadataPlane
        }
        if let photosLibraryPath = other.photosLibraryPath {
            self.photosLibraryPath = photosLibraryPath
        }
        if let vpnConfigDualuse = other.vpnConfigDualuse {
            self.vpnConfigDualuse = vpnConfigDualuse
        }
        if let sandboxContainerDepth = other.sandboxContainerDepth {
            self.sandboxContainerDepth = sandboxContainerDepth
        }
        if let xpcMachServiceDepth = other.xpcMachServiceDepth {
            self.xpcMachServiceDepth = xpcMachServiceDepth
        }
        if let tmLocalSnapshotDepth = other.tmLocalSnapshotDepth {
            self.tmLocalSnapshotDepth = tmLocalSnapshotDepth
        }
        if let emondLegacyDepth = other.emondLegacyDepth {
            self.emondLegacyDepth = emondLegacyDepth
        }
        if let screenSharingArdDepth = other.screenSharingArdDepth {
            self.screenSharingArdDepth = screenSharingArdDepth
        }
        if let keychainAclPath = other.keychainAclPath {
            self.keychainAclPath = keychainAclPath
        }
        if let pythonRuntimeDualuse = other.pythonRuntimeDualuse {
            self.pythonRuntimeDualuse = pythonRuntimeDualuse
        }
        if let shellPluginManager = other.shellPluginManager {
            self.shellPluginManager = shellPluginManager
        }
        if let airplayReceiverSurface = other.airplayReceiverSurface {
            self.airplayReceiverSurface = airplayReceiverSurface
        }
        if let handoffClipboardDepth = other.handoffClipboardDepth {
            self.handoffClipboardDepth = handoffClipboardDepth
        }
        if let imessagePathPlane = other.imessagePathPlane {
            self.imessagePathPlane = imessagePathPlane
        }
        if let facetimeCameraSurface = other.facetimeCameraSurface {
            self.facetimeCameraSurface = facetimeCameraSurface
        }
        if let finderSyncExtension = other.finderSyncExtension {
            self.finderSyncExtension = finderSyncExtension
        }
        if let fileproviderDomain = other.fileproviderDomain {
            self.fileproviderDomain = fileproviderDomain
        }
        if let notificationCenterDepth = other.notificationCenterDepth {
            self.notificationCenterDepth = notificationCenterDepth
        }
        if let siriSuggestionsPlane = other.siriSuggestionsPlane {
            self.siriSuggestionsPlane = siriSuggestionsPlane
        }
        if let spotlightImporterDepth = other.spotlightImporterDepth {
            self.spotlightImporterDepth = spotlightImporterDepth
        }
        if let contactsPathPlane = other.contactsPathPlane {
            self.contactsPathPlane = contactsPathPlane
        }
        if let calendarServerPath = other.calendarServerPath {
            self.calendarServerPath = calendarServerPath
        }
        if let remindersCloudPath = other.remindersCloudPath {
            self.remindersCloudPath = remindersCloudPath
        }
        if let mapsLocationPath = other.mapsLocationPath {
            self.mapsLocationPath = mapsLocationPath
        }
        if let weatherWidgetPath = other.weatherWidgetPath {
            self.weatherWidgetPath = weatherWidgetPath
        }
        if let musicLibraryPath = other.musicLibraryPath {
            self.musicLibraryPath = musicLibraryPath
        }
        if let booksPathPlane = other.booksPathPlane {
            self.booksPathPlane = booksPathPlane
        }
        if let podcastsPathPlane = other.podcastsPathPlane {
            self.podcastsPathPlane = podcastsPathPlane
        }
        if let tvAppPathPlane = other.tvAppPathPlane {
            self.tvAppPathPlane = tvAppPathPlane
        }
        if let homekitPathPlane = other.homekitPathPlane {
            self.homekitPathPlane = homekitPathPlane
        }
        if let healthPathPlane = other.healthPathPlane {
            self.healthPathPlane = healthPathPlane
        }
        if let walletPassPath = other.walletPassPath {
            self.walletPassPath = walletPassPath
        }
        if let findmyPathPlane = other.findmyPathPlane {
            self.findmyPathPlane = findmyPathPlane
        }
        if let shortcutsIcloudSync = other.shortcutsIcloudSync {
            self.shortcutsIcloudSync = shortcutsIcloudSync
        }
        if let devicemanagementProfile = other.devicemanagementProfile {
            self.devicemanagementProfile = devicemanagementProfile
        }
        if let softwareupdateCatalog = other.softwareupdateCatalog {
            self.softwareupdateCatalog = softwareupdateCatalog
        }
        for (k, v) in other.collectorNotes { self.collectorNotes[k] = v }
        self.deniedCollectors.append(contentsOf: other.deniedCollectors)
    }
}
