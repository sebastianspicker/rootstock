import Foundation
import RootstockBlueCore

/// Authorization plugins (`SecurityAgentPlugins`) - auth-path persistence.
///
/// Inventory of `/Library/Security/SecurityAgentPlugins/*` and JSON inventories.
/// ATT&CK T1556.001 (Modify Authentication Process: Domain Controller Authentication /
/// platform auth plugin loaders). On macOS these load into the auth stack and can
/// intercept credentials at interactive login.
///
/// Significant improvement over directory listing: normalized envelopes, risk tags
/// (unknown vendor, tmp path, unsigned), entity IDs, fixture CI.
/// Does not execute plugins or capture credentials.
public struct AuthPluginsParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "AUTHPLUGINS",
        tier: .tier1,
        description: "Authorization / SecurityAgent plugins (auth-path persistence)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()
        // Plugin name identity shared across JSON + directory so relative/absolute roots
        // and multi-source inventories do not double-count the same plugin.
        var seenNames = Set<String>()

        // JSON inventory preferred (fixture-friendly)
        for rel in [
            "Library/Preferences/auth_plugins.json",
            "Library/Security/authorization_plugins.json",
            "Library/Preferences/authorization_plugins.json",
        ] {
            if let url = root.firstExisting([rel]),
               let json = ArtifactIO.jsonObject(contentsOf: url),
               seen.insert(url) {
                let parsed = parseJSONInventory(json, rawRef: ArtifactRoot.pathKey(url))
                for e in parsed {
                    if let n = e.fields["auth.plugin_name"] {
                        seenNames.insert(n.lowercased())
                    }
                }
                events.append(contentsOf: parsed)
            }
        }

        // Enumerate SecurityAgentPlugins directory (bundles / markers)
        for url in root.enumerate(matching: { url in
            let path = url.path
            guard path.contains("/SecurityAgentPlugins/") else { return false }
            if url.hasDirectoryPath { return false }
            let name = url.lastPathComponent
            if name.hasPrefix(".") { return false }
            // Prefer Info.plist (bundle identity) or top-level marker files
            if name == "Info.plist" { return true }
            // Top-level file directly under SecurityAgentPlugins/<plugin>/
            let parent = url.deletingLastPathComponent()
            if parent.path.contains("/SecurityAgentPlugins/"),
               parent.deletingLastPathComponent().lastPathComponent == "SecurityAgentPlugins" {
                return true
            }
            return false
        }) {
            let key = ArtifactRoot.pathKey(url)

            // Resolve bundle / plugin directory identity
            var pluginPath = key
            var pluginName = url.lastPathComponent
            var bundleID = ""
            if pluginName == "Info.plist" {
                let parent = url.deletingLastPathComponent()
                if parent.lastPathComponent == "Contents" {
                    let bundle = parent.deletingLastPathComponent()
                    pluginPath = ArtifactRoot.pathKey(bundle)
                    pluginName = bundle.lastPathComponent
                } else {
                    pluginPath = ArtifactRoot.pathKey(parent)
                    pluginName = parent.lastPathComponent
                }
                if let dict = ArtifactIO.jsonOrPlistDict(contentsOf: url) {
                    bundleID = stringish(dict["CFBundleIdentifier"]) ?? stringish(dict["bundle_id"]) ?? ""
                }
            } else {
                // Marker / binary under plugin dir → attribute to parent plugin folder
                let parent = url.deletingLastPathComponent()
                if parent.deletingLastPathComponent().lastPathComponent == "SecurityAgentPlugins" {
                    pluginPath = ArtifactRoot.pathKey(parent)
                    pluginName = parent.lastPathComponent
                } else if pluginName.hasSuffix(".bundle") {
                    pluginName = String(pluginName.dropLast(".bundle".count))
                }
            }

            // Dedupe by plugin identity (JSON + multi-file bundles share one event)
            let nameKey = pluginName.lowercased()
            if seenNames.contains(nameKey) { continue }
            seenNames.insert(nameKey)
            _ = seen.insert(url)

            let emitPath: String
            if pluginPath.hasPrefix("/") {
                emitPath = pluginPath
            } else {
                emitPath = "/Library/Security/SecurityAgentPlugins/\(pluginName)"
            }

            events.append(
                makeEvent(
                    name: pluginName,
                    path: emitPath,
                    bundleID: bundleID.isEmpty ? pluginName : bundleID,
                    signed: nil,
                    vendor: "",
                    rawRef: key,
                    extraRisk: []
                )
            )
        }

        return events
    }

    private func parseJSONInventory(_ json: Any, rawRef: String) -> [EventEnvelope] {
        let items = ArtifactIO.dictionaryEntries(
            from: json,
            nestedKeys: ["plugins", "authorization_plugins", "auth_plugins"]
        )
        // dictionaryEntries returns [] when nested keys miss and nestedKeys non-empty;
        // fall back to single-dict inventory like the previous implementation.
        let resolved: [[String: Any]]
        if !items.isEmpty {
            resolved = items
        } else if let dict = json as? [String: Any] {
            resolved = [dict]
        } else {
            resolved = []
        }
        return resolved.compactMap { item -> EventEnvelope? in
            let name = stringish(item["plugin_name"])
                ?? stringish(item["name"])
                ?? stringish(item["label"])
                ?? stringish(item["bundle_id"])
                ?? ""
            let path = stringish(item["plugin_path"])
                ?? stringish(item["path"])
                ?? (name.isEmpty ? "" : "/Library/Security/SecurityAgentPlugins/\(name)")
            guard !name.isEmpty || !path.isEmpty else { return nil }
            let resolvedName = name.isEmpty ? URL(fileURLWithPath: path).lastPathComponent : name
            let bundleID = stringish(item["bundle_id"])
                ?? stringish(item["CFBundleIdentifier"])
                ?? resolvedName
            let signed = boolish(item["signed"])
            let vendor = stringish(item["vendor"]) ?? stringish(item["team_id"]) ?? ""

            var extraRisk: [String] = []
            if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
                extraRisk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            }

            return makeEvent(
                name: resolvedName,
                path: path.isEmpty ? "/Library/Security/SecurityAgentPlugins/\(resolvedName)" : path,
                bundleID: bundleID,
                signed: signed,
                vendor: vendor,
                rawRef: rawRef,
                extraRisk: extraRisk
            )
        }
    }

    private func makeEvent(
        name: String,
        path: String,
        bundleID: String,
        signed: Bool?,
        vendor: String,
        rawRef: String,
        extraRisk: [String]
    ) -> EventEnvelope {
        var risk = extraRisk
        let lowerName = name.lowercased()
        let lowerPath = path.lowercased()
        let lowerBundle = bundleID.lowercased()
        let lowerVendor = vendor.lowercased()

        if lowerPath.contains("/tmp/") || lowerPath.contains("/var/tmp/") || lowerPath.contains("/users/shared/") {
            if !risk.contains("tmp_path") { risk.append("tmp_path") }
        }
        if signed == false {
            if !risk.contains("unsigned") { risk.append("unsigned") }
        }
        let unknownVendorHints = lowerName.contains("evil")
            || lowerBundle.contains("evil")
            || lowerPath.contains("evil")
            || lowerVendor == "unknown"
            || lowerVendor.isEmpty && (lowerName.contains("evil") || lowerBundle.contains("evil"))
        if unknownVendorHints || lowerVendor == "unknown" || vendor.isEmpty && (lowerName.contains("evil") || lowerBundle.contains("com.evil")) {
            if !risk.contains("unknown_vendor") { risk.append("unknown_vendor") }
        }
        // Non-Apple vendor under SecurityAgentPlugins is inherently interesting when unsigned
        if signed == false || lowerName.contains("evil") || lowerBundle.contains("evil") {
            if !risk.contains("unknown_vendor") && vendor.lowercased() != "apple" {
                risk.append("unknown_vendor")
            }
        }

        var fields: [String: String] = [
            "persistence.kind": "authorization_plugin",
            "persistence.label": name,
            "persistence.path": path,
            "auth.plugin_name": name,
            "auth.plugin_path": path,
            "auth.plugin_bundle_id": bundleID,
            "auth.bundle_id": bundleID,
            "attack.technique": "T1556.001",
            FieldTaxonomy.filePath: path,
            FieldTaxonomy.eventType: "persistence.item",
        ]
        if let signed {
            fields["auth.plugin_signed"] = signed ? "true" : "false"
        }
        if !vendor.isEmpty {
            fields["auth.plugin_vendor"] = vendor
        }
        if !risk.isEmpty {
            fields["persistence.risk_tags"] = risk.joined(separator: ",")
            fields["auth.risk_tags"] = risk.joined(separator: ",")
        }

        let entities: [EntityID] = [
            EntityID(kind: .persistence, value: "authplugin|\(name)|\(path)"),
            EntityID(kind: .auth, value: "auth_plugin|\(bundleID)"),
            .file(path: path),
            .file(path: rawRef),
        ]

        return EventEnvelope(
            eventTime: Date(timeIntervalSince1970: 0),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "AUTHPLUGINS",
            eventType: "persistence.item",
            entityRefs: entities,
            fields: fields,
            rawRef: rawRef,
            confidence: 0.93
        )
    }
}
