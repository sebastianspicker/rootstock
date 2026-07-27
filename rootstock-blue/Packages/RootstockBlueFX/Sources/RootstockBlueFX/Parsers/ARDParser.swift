import Foundation
import RootstockBlueCore

/// Apple Remote Desktop / Remote Management posture from prefs + inventory.
///
/// Parses `com.apple.RemoteManagement.plist` (including `ARD_AllLocalUsers`),
/// JSON inventories, and VNC allow flags for remote-access IR posture.
/// Complements IRPosture offline remote-access signals with richer ARD fields.
public struct ARDParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "ARD",
        tier: .tier1,
        description: "Apple Remote Desktop / Remote Management posture and allow lists"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        // JSON inventory (fixture-friendly)
        for rel in [
            "Library/Preferences/ard_inventory.json",
            "Library/Preferences/com.apple.RemoteManagement.json",
        ] {
            if let url = root.firstExisting([rel]),
               let json = ArtifactIO.jsonObject(contentsOf: url),
               seen.insert(url) {
                events.append(contentsOf: parseJSONInventory(json, rawRef: ArtifactRoot.pathKey(url)))
            }
        }

        // Classic RemoteManagement plist
        for rel in [
            "Library/Preferences/com.apple.RemoteManagement.plist",
            "Library/Preferences/com.apple.RemoteDesktop.plist",
            "var/db/RemoteManagement.launchd",
        ] {
            guard let url = root.firstExisting([rel]) else { continue }
            let key = ArtifactRoot.pathKey(url)
            guard seen.insert(url) else { continue }
            if rel.hasSuffix(".plist") {
                events.append(contentsOf: parseRemoteManagementPlist(at: url))
            } else {
                // Marker file presence → enabled-ish
                events.append(
                    makeEvent(
                        enabled: true,
                        allLocalUsers: nil,
                        allowVNC: nil,
                        users: [],
                        rawRef: key,
                        sourceNote: "marker"
                    )
                )
            }
        }

        // Discover alternate inventory names
        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "ard_inventory.json"
                || name == "com.apple.RemoteManagement.json"
                || name == "com.apple.RemoteManagement.plist"
        }) {
            let key = ArtifactRoot.pathKey(url)
            guard seen.insert(url) else { continue }
            if url.pathExtension == "plist" {
                events.append(contentsOf: parseRemoteManagementPlist(at: url))
            } else if let json = ArtifactIO.jsonObject(contentsOf: url) {
                events.append(contentsOf: parseJSONInventory(json, rawRef: key))
            }
        }

        return events
    }

    private func parseJSONInventory(_ json: Any, rawRef: String) -> [EventEnvelope] {
        // Single posture object or list of configs
        if let dict = json as? [String: Any] {
            // Nested configs array
            if let configs = dict["configs"] as? [[String: Any]] {
                return configs.compactMap { dictEvent($0, rawRef: rawRef) }
            }
            if let items = dict["items"] as? [[String: Any]] {
                return items.compactMap { dictEvent($0, rawRef: rawRef) }
            }
            if let ard = dict["ard"] as? [String: Any] {
                return [dictEvent(ard, rawRef: rawRef)].compactMap { $0 }
            }
            if let event = dictEvent(dict, rawRef: rawRef) {
                return [event]
            }
        }
        if let arr = json as? [[String: Any]] {
            return arr.compactMap { dictEvent($0, rawRef: rawRef) }
        }
        return []
    }

    private func dictEvent(_ dict: [String: Any], rawRef: String) -> EventEnvelope? {
        let enabled = boolish(dict["enabled"])
            ?? boolish(dict["ard.enabled"])
            ?? boolish(dict["RemoteManagementEnabled"])
            ?? boolish(dict["ScreenSharingEnabled"])
        let allLocal = boolish(dict["all_local_users"])
            ?? boolish(dict["ARD_AllLocalUsers"])
            ?? boolish(dict["ard.all_local_users"])
        let allowVNC = boolish(dict["allow_vnc"])
            ?? boolish(dict["VNCEnabled"])
            ?? boolish(dict["ard.allow_vnc"])
            ?? boolish(dict["AllowVNC"])
        let users = stringArray(dict["users"])
            + stringArray(dict["ARD_Users"])
            + stringArray(dict["allow_list"])
            + stringArray(dict["allowlist"])

        // Require at least one ARD-related signal
        guard enabled != nil || allLocal != nil || allowVNC != nil || !users.isEmpty
            || dict["ARD_AllLocalUsers"] != nil
            || stringish(dict["remote.service"])?.lowercased() == "ard"
        else { return nil }

        return makeEvent(
            enabled: enabled ?? (allLocal == true ? true : nil) ?? true,
            allLocalUsers: allLocal,
            allowVNC: allowVNC,
            users: users,
            rawRef: rawRef,
            sourceNote: "inventory"
        )
    }

    private func parseRemoteManagementPlist(at url: URL) -> [EventEnvelope] {
        guard let dict = ArtifactIO.jsonOrPlistDict(contentsOf: url) else { return [] }

        let allLocal = boolish(dict["ARD_AllLocalUsers"])
        let screenSharing = boolish(dict["ScreenSharingEnabled"])
        let allowVNC = boolish(dict["VNCEnabled"]) ?? boolish(dict["LoadRemoteManagementMenuExtra"])
        let users = stringArray(dict["ARD_Users"]) + stringArray(dict["AllowList"])

        // ARD_AllLocalUsers true implies remote management effectively enabled for all users
        let enabled = screenSharing ?? allLocal ?? (allowVNC == true ? true : nil) ?? true

        return [
            makeEvent(
                enabled: enabled,
                allLocalUsers: allLocal,
                allowVNC: allowVNC ?? screenSharing,
                users: users,
                rawRef: ArtifactRoot.pathKey(url),
                sourceNote: "plist"
            ),
        ]
    }

    private func makeEvent(
        enabled: Bool?,
        allLocalUsers: Bool?,
        allowVNC: Bool?,
        users: [String],
        rawRef: String,
        sourceNote: String
    ) -> EventEnvelope {
        let isEnabled = enabled ?? false
        var fields: [String: String] = [
            "ard.enabled": isEnabled ? "true" : "false",
            FieldTaxonomy.remoteService: "ard",
            FieldTaxonomy.remoteEnabled: isEnabled ? "true" : "false",
            "protection.name": "RemoteManagement",
            "protection.enabled": isEnabled ? "true" : "false",
            "ard.source": sourceNote,
            FieldTaxonomy.eventType: "remote.management",
        ]
        if let allLocalUsers {
            fields["ard.all_local_users"] = allLocalUsers ? "true" : "false"
        }
        if let allowVNC {
            fields["ard.allow_vnc"] = allowVNC ? "true" : "false"
        }
        if !users.isEmpty {
            fields["ard.users"] = users.joined(separator: ",")
        }

        // High-risk posture: all local users can take remote control
        if allLocalUsers == true {
            fields["ard.risk_tags"] = "all_local_users"
            fields["remote.risk_tags"] = "all_local_users"
        }

        // Dual event types for IR consumers: primary remote.management + posture alias field
        fields["ir.posture.remote_access"] = isEnabled ? "true" : "false"

        let entities: [EntityID] = [
            EntityID(kind: .host, value: "remote=ard"),
            EntityID(kind: .host, value: "ard|\(isEnabled)|\(allLocalUsers.map { $0 ? "all" : "restricted" } ?? "unknown")"),
            .file(path: rawRef),
        ]

        return EventEnvelope(
            eventTime: Date(timeIntervalSince1970: 0),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "ARD",
            eventType: "remote.management",
            entityRefs: entities,
            fields: fields,
            rawRef: rawRef,
            confidence: 0.94
        )
    }
}
