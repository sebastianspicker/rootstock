import Foundation
import RootstockBlueCore
import RootstockBlueCase

/// KnockKnock-class unified persistence inventory across autostart, BTM, cron,
/// login items, shell profiles, emond, privileged helpers, folder actions,
/// login hooks, authorization plugins, saved-state surface, and optional SSH keys.
public enum PersistenceInventory {
    /// Inventory surface sources merged into a single event list.
    public enum SourceTag: String, Sendable {
        case autostart
        case btm
        case cron
        case loginItem = "login_item"
        case ssh
        case shellProfile = "shell_profile"
        case emond
        case privilegedHelper = "privileged_helper"
        case folderAction = "folder_action"
        case loginHook = "login_hook"
        case authorizationPlugin = "authorization_plugin"
        case savedState = "saved_state"
    }

    /// Run Autostart + BTM + Cron + LoginItems + ShellProfiles + Emond
    /// + PrivHelpers + FolderActions + LoginHooks + AuthPlugins + SavedState
    /// (+ optional SSH authorized_keys) and tag for unified inventory.
    public static func enumerate(source: ImageSource, includeSSH: Bool = true) throws -> [EventEnvelope] {
        var parsers: [any ArtifactParser] = [
            AutostartParser(),
            BTMParser(),
            CronParser(),
            LoginItemsParser(),
            ShellProfilesParser(),
            EmondParser(),
            PrivHelpersParser(),
            FolderActionsParser(),
            LoginHooksParser(),
            AuthPluginsParser(),
            SavedStateParser(),
        ]
        if includeSSH {
            parsers.append(SSHArtifactsParser())
        }

        var events: [EventEnvelope] = []
        for parser in parsers {
            let parsed = try parser.parse(source: source)
            for var event in parsed {
                // SSH: only keep authorized_keys as remote-access persistence surface
                if parser.manifest.id == "SSH" {
                    guard event.eventType == "auth.ssh_authorized_key" else { continue }
                    event.fields["inventory.source"] = SourceTag.ssh.rawValue
                    event.fields["inventory.unified"] = "true"
                    event.fields["inventory.parser"] = parser.manifest.id
                    event.fields["inventory.surface"] = "remote_access"
                    event.fields["inventory.event_type"] = "access.persistence"
                    event.fields["inventory.kind"] = "ssh_authorized_key"
                    if event.fields["auth.event_type"] == nil {
                        event.fields["auth.event_type"] = event.eventType
                    }
                    event.eventType = "access.persistence"
                    event.fields[FieldTaxonomy.eventType] = "access.persistence"
                    events.append(event)
                    continue
                }

                // SavedState: only risky / non-Apple restore states as inventory surface
                if parser.manifest.id == "SAVEDSTATE" {
                    let tags = (event.fields["savedstate.risk_tags"] ?? "").lowercased()
                    let bid = (event.fields["savedstate.bundle_id"] ?? "").lowercased()
                    let interesting = !tags.isEmpty
                        || bid.contains("evil")
                        || bid.contains("implant")
                        || !(bid.hasPrefix("com.apple.") || bid.isEmpty)
                    guard interesting else { continue }
                    event.fields["inventory.source"] = SourceTag.savedState.rawValue
                    event.fields["inventory.unified"] = "true"
                    event.fields["inventory.parser"] = parser.manifest.id
                    event.fields["inventory.kind"] = "saved_state"
                    event.fields["inventory.event_type"] = "inventory.persistence"
                    if event.fields["persistence.kind"] == nil {
                        event.fields["persistence.kind"] = "saved_state"
                    }
                    events.append(event)
                    continue
                }

                let tag = sourceTag(for: parser.manifest.id, event: event)
                event.fields["inventory.source"] = tag.rawValue
                event.fields["inventory.unified"] = "true"
                event.fields["inventory.parser"] = parser.manifest.id
                if event.fields["inventory.event_type"] == nil {
                    event.fields["inventory.event_type"] = "inventory.persistence"
                }
                if event.fields["inventory.kind"] == nil {
                    event.fields["inventory.kind"] = event.fields["persistence.kind"]
                        ?? event.fields["btm.type_label"]
                        ?? tag.rawValue
                }
                events.append(event)
            }
        }
        return events
    }

    /// Summarize inventory events by kind / source tag counts.
    public static func summarize(_ events: [EventEnvelope]) -> [String: Int] {
        var counts: [String: Int] = [:]
        for event in events {
            let kind = event.fields["inventory.kind"]
                ?? event.fields["persistence.kind"]
                ?? event.fields["inventory.source"]
                ?? event.eventType
            counts[kind, default: 0] += 1
            if let src = event.fields["inventory.source"] {
                counts["source:\(src)", default: 0] += 1
            }
        }
        counts["total"] = events.count
        return counts
    }

    /// Write inventory events into a case package.
    @discardableResult
    public static func writeToCase(
        _ events: [EventEnvelope],
        package: CasePackage,
        actor: String = NSUserName()
    ) throws -> Int {
        for event in events {
            try package.appendEventJSONL(event, stream: "es")
            try package.insertTimelineEvent(event)
        }
        try package.appendCustody(
            CustodyEvent(
                actor: actor,
                action: "persistence_inventory",
                detail: "Persistence inventory wrote \(events.count) events sources=autostart,btm,cron,login_item,shell_profile,emond,privileged_helper,folder_action,login_hook,authorization_plugin,saved_state,ssh"
            )
        )
        try package.updateHashes()
        return events.count
    }

    // MARK: - Private

    private static func sourceTag(for parserID: String, event: EventEnvelope) -> SourceTag {
        switch parserID {
        case "AUTOSTART":
            return .autostart
        case "BTM":
            return .btm
        case "CRON":
            return .cron
        case "LOGINITEMS":
            return .loginItem
        case "SSH":
            return .ssh
        case "SHELLPROFILES":
            return .shellProfile
        case "EMOND":
            return .emond
        case "PRIVHELPERS":
            return .privilegedHelper
        case "FOLDERACTIONS":
            return .folderAction
        case "LOGINHOOKS":
            return .loginHook
        case "AUTHPLUGINS":
            return .authorizationPlugin
        case "SAVEDSTATE":
            return .savedState
        default:
            if event.eventType.contains("btm") { return .btm }
            if event.fields["persistence.kind"] == "cron"
                || event.fields["persistence.kind"] == "at"
                || event.fields["persistence.kind"] == "periodic" {
                return .cron
            }
            if event.fields["persistence.kind"] == "login_item" { return .loginItem }
            if event.fields["persistence.kind"] == "shell_profile" { return .shellProfile }
            if event.fields["persistence.kind"] == "emond" { return .emond }
            if event.fields["persistence.kind"] == "privileged_helper" { return .privilegedHelper }
            if event.fields["persistence.kind"] == "folder_action" { return .folderAction }
            if event.fields["persistence.kind"] == "login_hook"
                || event.fields["persistence.kind"] == "logout_hook" {
                return .loginHook
            }
            if event.fields["persistence.kind"] == "authorization_plugin"
                || event.fields["persistence.kind"] == "auth_plugin" {
                return .authorizationPlugin
            }
            return .autostart
        }
    }
}
