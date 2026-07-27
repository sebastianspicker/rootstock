import Foundation
import RootstockBlueCore
import RootstockBlueCase

/// Executes collection packs against a host path or fixture tree, writing into a case.
/// Preflight is reported honestly; for offline fixture trees, use `skipStrictPreflight: true`.
public struct CollectRunner: Sendable {
    public var skipStrictPreflight: Bool

    public init(skipStrictPreflight: Bool = false) {
        self.skipStrictPreflight = skipStrictPreflight
    }

    public struct Result: Sendable {
        public var packName: String
        public var filesCopied: Int
        public var eventsWritten: Int
        public var preflight: PreflightReport
    }

    public func run(
        pack: CollectionPack,
        sourceRoot: URL,
        into package: CasePackage,
        actor: String = NSUserName()
    ) throws -> Result {
        let preflight = Preflight.check(for: pack, offlineFixtureMode: skipStrictPreflight)
        if !skipStrictPreflight {
            try Preflight.enforce(preflight)
        }

        var filesCopied = 0
        var events: [EventEnvelope] = []
        let fm = FileManager.default

        for artifact in pack.artifacts {
            let mapped = Self.artifactPaths(for: artifact)
            for rel in mapped {
                let src = sourceRoot.appendingPathComponent(rel)
                guard fm.fileExists(atPath: src.path) else { continue }
                let destName = "\(pack.name)/\(rel)"
                _ = try package.copyArtifact(from: src, relativeName: destName)
                filesCopied += 1
                events.append(
                    EventEnvelope(
                        source: .collect,
                        sourcePlugin: "collect.\(pack.name)",
                        eventType: "collect.artifact",
                        entityRefs: [.file(path: destName)],
                        fields: [
                            "collect.pack": pack.name,
                            "collect.artifact": artifact,
                            "collect.source_path": src.path,
                            "collect.relative": rel,
                            FieldTaxonomy.filePath: destName,
                            FieldTaxonomy.eventType: "collect.artifact",
                        ],
                        rawRef: src.path,
                        confidence: 1.0
                    )
                )
            }
        }

        // Always emit a pack summary event so the case has non-empty collect evidence.
        events.append(
            EventEnvelope(
                source: .collect,
                sourcePlugin: "collect.\(pack.name)",
                eventType: "collect.summary",
                entityRefs: [],
                fields: [
                    "collect.pack": pack.name,
                    "collect.files_copied": String(filesCopied),
                    "collect.artifact_count": String(pack.artifacts.count),
                    FieldTaxonomy.eventType: "collect.summary",
                ],
                confidence: 1.0
            )
        )

        let sink = CaseEventSink(package: package, actor: actor)
        for event in events {
            try sink.append(event)
        }
        try sink.noteCustody(
            action: "collect",
            detail: "pack=\(pack.name) files=\(filesCopied) events=\(events.count) root=\(sourceRoot.path)"
        )

        return Result(
            packName: pack.name,
            filesCopied: filesCopied,
            eventsWritten: events.count,
            preflight: preflight
        )
    }

    /// Map logical artifact names to relative paths under a macOS-like tree.
    public static func artifactPaths(for name: String) -> [String] {
        switch name.lowercased() {
        case "tcc":
            return ["Library/Application Support/com.apple.TCC/TCC.db"]
        case "quarantine":
            return ["Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"]
        case "autostart", "launchagents":
            return ["Library/LaunchAgents", "Library/LaunchDaemons"]
        case "btm":
            return [
                "private/var/db/com.apple.backgroundtaskmanagement",
                "var/db/com.apple.backgroundtaskmanagement",
            ]
        case "wifi":
            return [
                "Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist",
                "Library/Preferences/com.apple.wifi.known-networks.plist",
                "Library/Preferences/wifi_known_networks.json",
            ]
        case "configprofiles":
            return [
                "Library/ConfigurationProfiles",
                "Library/Managed Preferences",
            ]
        case "ssh":
            return ["Users", "etc/ssh"]
        case "security_posture":
            return ["Library/Preferences/security_posture.json"]
        case "alf", "firewall":
            return ["Library/Preferences/com.apple.alf.plist"]
        case "dock":
            return ["Users"]
        case "users", "basicinfo":
            return ["var/db/dslocal/nodes/Default/users"]
        case "unifiedlog_export", "asl", "installhistory":
            return ["Library/Logs"]
        case "xprotect":
            return ["Library/Logs/DiagnosticReports"]
        case "safari":
            return [
                "Users/alice/Library/Safari",
                "Users",
            ]
        case "chromium", "chrome":
            return [
                "Users/alice/Library/Application Support/Google/Chrome",
                "Users",
            ]
        case "knowledgec", "pol":
            return [
                "Users/alice/Library/Application Support/Knowledge",
                "Users",
            ]
        case "recentitems", "mru":
            return [
                "Users/alice/Library/Application Support/com.apple.sharedfilelist",
                "Users",
            ]
        case "firefox", "cookies":
            return ["Users"]
        case "loginitems", "login_items":
            return [
                "Users/alice/Library/Application Support/com.apple.sharedfilelist",
                "Users",
            ]
        case "crons", "cron":
            return [
                "etc/crontab",
                "etc/cron.d",
                "etc/periodic",
                "var/at/tabs",
                "private/var/at/tabs",
                "Library/Preferences/cron_jobs.json",
            ]
        case "biome", "pol_biome":
            return [
                "Users/alice/Library/Biome",
                "Users",
            ]
        case "systemextensions", "sysext":
            return [
                "Library/SystemExtensions",
                "Library/Preferences/system_extensions.json",
            ]
        case "utmpx", "sessions", "wtmp":
            return [
                "private/var/run/utmpx.jsonl",
                "var/run/utmpx.jsonl",
                "var/run/utmpx.json",
                "var/log/wtmp.jsonl",
                "Library/Logs/utmpx_export.jsonl",
                "Library/Logs/wtmp_export.jsonl",
            ]
        case "browser_extensions", "extensions":
            return [
                "Users/alice/Library/Application Support/Google/Chrome/Default/extensions.json",
                "Users/alice/Library/Application Support/Google/Chrome",
                "Users",
            ]
        case "gatekeeper", "gk":
            return [
                "Library/Logs/Gatekeeper",
                "Library/Preferences/com.apple.security.gk.json",
                "Library/Preferences/gatekeeper_assessments.json",
            ]
        case "netlocation", "network_locations", "network-context":
            return [
                "Library/Preferences/SystemConfiguration/network_locations.json",
                "Library/Preferences/SystemConfiguration/preferences.plist",
                "Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist",
            ]
        case "shell_profiles", "shellprofiles", "shellrc":
            return [
                "Users",
                "etc/profile",
                "etc/zprofile",
                "etc/zshrc",
                "etc/bashrc",
                "private/etc/profile",
            ]
        case "emond":
            return [
                "etc/emond.d",
                "private/etc/emond.d",
                "Library/Preferences/emond_rules.json",
            ]
        case "sudoers":
            return [
                "etc/sudoers",
                "etc/sudoers.d",
                "private/etc/sudoers",
                "private/etc/sudoers.d",
            ]
        case "launchd_overrides", "launchdoverrides", "disabled_plist":
            return [
                "var/db/com.apple.xpc.launchd",
                "private/var/db/com.apple.xpc.launchd",
                "Library/Preferences/launchd_disabled.json",
            ]
        case "privhelpers", "privileged_helpers", "privilegedhelpers":
            return [
                "Library/PrivilegedHelperTools",
                "Library/Preferences/privileged_helpers.json",
                "Library/LaunchDaemons",
            ]
        case "folder_actions", "folderactions", "folder_action":
            return [
                "Users",
                "Library/Scripts",
                "Library/Preferences/folder_actions.json",
            ]
        case "login_hooks", "loginhooks", "loginwindow_hooks":
            return [
                "Library/Preferences/com.apple.loginwindow.plist",
                "Library/Preferences/login_hooks.json",
                "var/root/Library/Preferences/com.apple.loginwindow.plist",
                "etc/kcpassword",
            ]
        case "software_update", "softwareupdate":
            return [
                "Library/Preferences/com.apple.SoftwareUpdate.plist",
            ]
        case "file_sharing", "smb":
            return [
                "Library/Preferences/SystemConfiguration/com.apple.smb.server.plist",
                "Library/Preferences/com.apple.AppleFileServer.plist",
            ]
        case "auth_plugins", "authplugins", "authorization_plugins":
            return [
                "Library/Security/SecurityAgentPlugins",
                "Library/Preferences/auth_plugins.json",
                "Library/Security/auth_plugins.json",
            ]
        case "netusage", "net_usage", "network_usage":
            return [
                "Library/Preferences/netusage.json",
                "Library/Preferences/com.apple.networkextension.plist",
                "Library/Preferences/com.apple.networkusage.plist",
            ]
        case "usb_history", "usbhistory", "usb":
            return [
                "Library/Preferences/usb_history.json",
                "Library/Preferences/com.apple.usb.plist",
                "Library/Logs/usb_history.jsonl",
            ]
        case "keychain_meta", "keychainmeta", "keychain_metadata":
            return [
                "Library/Preferences/keychain_metadata.json",
                "Users",
                "Library/Keychains/keychain_metadata.json",
            ]
        case "codesign", "codesign_inventory":
            return [
                "Library/Preferences/codesign_inventory.json",
                "Library/PrivilegedHelperTools",
                "Library/LaunchDaemons",
            ]
        case "ard", "remote_management", "remote_desktop":
            return [
                "Library/Preferences/com.apple.RemoteManagement.plist",
                "Library/Preferences/com.apple.RemoteDesktop.plist",
                "Library/Preferences/ard_inventory.json",
            ]
        // Wave-6 forensics / PoL / cloud
        case "spotlight", "spotlight_inventory":
            return [
                "Library/Preferences/spotlight_inventory.json",
                "Library/Preferences/spotlight_export.json",
                "Library/Logs/spotlight_export.jsonl",
                "Users",
            ]
        case "trash", "trash_inventory":
            return [
                "Library/Preferences/trash_inventory.json",
                "Library/Logs/trash_export.jsonl",
                "Users",
            ]
        case "doc_revisions", "docrevisions", "document_revisions":
            return [
                "Library/Preferences/doc_revisions.json",
                "Library/Preferences/document_revisions.json",
                ".DocumentRevisions-V100",
                "Users",
            ]
        case "saved_state", "savedstate", "saved_application_state":
            return [
                "Library/Preferences/saved_state.json",
                "Library/Preferences/saved_application_state.json",
                "Users",
            ]
        case "notifications", "notification_center":
            return [
                "Library/Preferences/notification_center.json",
                "Library/Preferences/notifications.json",
                "Library/Logs/notification_center.jsonl",
                "Users",
            ]
        case "quicklook", "quicklook_cache":
            return [
                "Library/Preferences/quicklook_cache.json",
                "Library/Logs/quicklook_cache.jsonl",
                "Users",
            ]
        case "screentime", "screen_time", "screentime_markers":
            return [
                "Library/Preferences/screentime_markers.json",
                "Library/Preferences/screentime.json",
                "Library/Preferences/screen_time.json",
                "Users",
            ]
        case "icloud", "icloud_account", "icloud_sync":
            return [
                "Library/Preferences/icloud_account.json",
                "Library/Preferences/icloud_sync.json",
                "Users",
            ]
        case "forensics_browser":
            return [
                "Users/alice/Library/Safari",
                "Users/alice/Library/Application Support/Google/Chrome",
                "Users/alice/Library/Application Support/Firefox",
            ]
        case "forensics_pol":
            return [
                "Users/alice/Library/Application Support/Knowledge",
                "Users/alice/Library/Application Support/com.apple.sharedfilelist",
                "Users/alice/Library/Biome",
                "Library/Preferences/screentime_markers.json",
            ]
        default:
            return [name]
        }
    }
}
