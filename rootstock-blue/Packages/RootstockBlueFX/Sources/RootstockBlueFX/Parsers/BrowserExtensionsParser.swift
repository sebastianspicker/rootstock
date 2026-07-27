import Foundation
import RootstockBlueCore

/// Browser extensions for Chrome (and Chromium) and Safari.
///
/// Accepts per-extension `manifest.json` trees or fixture-friendly
/// `extensions.json` / `Extensions.json` inventories.
public struct BrowserExtensionsParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "BROWSER_EXTENSIONS",
        tier: .tier2,
        description: "Chrome and Safari browser extensions (manifest inventory)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        // Chrome / Chromium inventory JSON
        for found in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            let path = url.path
            if name == "extensions.json"
                && (path.contains("Chrome") || path.contains("Chromium") || path.contains("Edge") || path.contains("Brave")) {
                return true
            }
            // Per-extension manifest.json under Extensions/<id>/<version>/
            if name == "manifest.json" && path.contains("/Extensions/")
                && (path.contains("Chrome") || path.contains("Chromium") || path.contains("Google")) {
                return true
            }
            return false
        }) {
            if !seen.insert(found) { continue }
            if found.lastPathComponent == "extensions.json" {
                events.append(contentsOf: parseChromeInventory(at: found))
            } else {
                events.append(contentsOf: parseChromeManifest(at: found))
            }
        }

        // Safari Extensions.json / Extensions folder
        for found in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            let path = url.path
            if path.contains("/Safari/") {
                if name == "Extensions.json" || name == "extensions.json" {
                    return true
                }
                if name == "manifest.json" && path.contains("/Extensions/") {
                    return true
                }
            }
            return false
        }) {
            if !seen.insert(found) { continue }
            if found.lastPathComponent.lowercased().contains("extensions.json") {
                events.append(contentsOf: parseSafariInventory(at: found))
            } else {
                events.append(contentsOf: parseSafariManifest(at: found))
            }
        }

        // Explicit fixture paths
        for rel in [
            "Users/alice/Library/Application Support/Google/Chrome/Default/Extensions/extensions.json",
            "Users/alice/Library/Safari/Extensions/Extensions.json",
        ] {
            if let u = root.firstExisting([rel]) {
                if !seen.insert(u) { continue }
                if u.path.contains("Safari") {
                    events.append(contentsOf: parseSafariInventory(at: u))
                } else {
                    events.append(contentsOf: parseChromeInventory(at: u))
                }
            }
        }

        return events
    }

    // MARK: - Chrome

    private func parseChromeInventory(at url: URL) -> [EventEnvelope] {
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }

        let items: [[String: Any]]
        if let arr = obj as? [[String: Any]] {
            items = arr
        } else if let dict = obj as? [String: Any] {
            if let arr = dict["extensions"] as? [[String: Any]] {
                items = arr
            } else if let arr = dict["items"] as? [[String: Any]] {
                items = arr
            } else {
                // Map of id -> metadata
                var mapped: [[String: Any]] = []
                for (key, value) in dict {
                    if var entry = value as? [String: Any] {
                        if entry["id"] == nil { entry["id"] = key }
                        mapped.append(entry)
                    }
                }
                items = mapped
            }
        } else {
            return []
        }

        let user = inferUser(from: url)
        return items.compactMap { item in
            makeExtensionEvent(
                browser: "chrome",
                extID: stringValue(item["id"]) ?? stringValue(item["extension_id"]) ?? "",
                name: stringValue(item["name"]) ?? stringValue(item["short_name"]) ?? "",
                version: stringValue(item["version"]) ?? "",
                permissions: permissionsString(item["permissions"] ?? item["host_permissions"]),
                user: user,
                sourceURL: url,
                extra: item
            )
        }
    }

    private func parseChromeManifest(at url: URL) -> [EventEnvelope] {
        guard let obj = ArtifactIO.jsonDict(contentsOf: url) else { return [] }

        // Infer extension id from .../Extensions/<id>/<version>/manifest.json
        let parts = url.pathComponents
        var extID = ""
        if let idx = parts.lastIndex(of: "Extensions"), idx + 1 < parts.count {
            extID = parts[idx + 1]
        }

        let name = localizedName(obj["name"]) ?? stringValue(obj["name"]) ?? ""
        let version = stringValue(obj["version"]) ?? ""
        let perms = permissionsString(obj["permissions"])
        let user = inferUser(from: url)

        if let event = makeExtensionEvent(
            browser: "chrome",
            extID: extID,
            name: name,
            version: version,
            permissions: perms,
            user: user,
            sourceURL: url,
            extra: obj
        ) {
            return [event]
        }
        return []
    }

    // MARK: - Safari

    private func parseSafariInventory(at url: URL) -> [EventEnvelope] {
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }

        let items: [[String: Any]]
        if let arr = obj as? [[String: Any]] {
            items = arr
        } else if let dict = obj as? [String: Any] {
            if let arr = dict["extensions"] as? [[String: Any]] {
                items = arr
            } else if let arr = dict["Installed Extensions"] as? [[String: Any]] {
                items = arr
            } else {
                var mapped: [[String: Any]] = []
                for (key, value) in dict {
                    if var entry = value as? [String: Any] {
                        if entry["id"] == nil { entry["id"] = key }
                        mapped.append(entry)
                    }
                }
                items = mapped
            }
        } else {
            return []
        }

        let user = inferUser(from: url)
        return items.compactMap { item in
            makeExtensionEvent(
                browser: "safari",
                extID: stringValue(item["id"])
                    ?? stringValue(item["bundle_id"])
                    ?? stringValue(item["Bundle Identifier"])
                    ?? "",
                name: stringValue(item["name"]) ?? stringValue(item["Display Name"]) ?? "",
                version: stringValue(item["version"]) ?? stringValue(item["Version"]) ?? "",
                permissions: permissionsString(item["permissions"] ?? item["Permissions"]),
                user: user,
                sourceURL: url,
                extra: item
            )
        }
    }

    private func parseSafariManifest(at url: URL) -> [EventEnvelope] {
        guard let obj = ArtifactIO.jsonDict(contentsOf: url) else { return [] }
        let user = inferUser(from: url)
        if let event = makeExtensionEvent(
            browser: "safari",
            extID: stringValue(obj["bundle_id"]) ?? stringValue(obj["id"]) ?? url.deletingLastPathComponent().lastPathComponent,
            name: localizedName(obj["name"]) ?? stringValue(obj["name"]) ?? "",
            version: stringValue(obj["version"]) ?? "",
            permissions: permissionsString(obj["permissions"]),
            user: user,
            sourceURL: url,
            extra: obj
        ) {
            return [event]
        }
        return []
    }

    // MARK: - shared

    private func makeExtensionEvent(
        browser: String,
        extID: String,
        name: String,
        version: String,
        permissions: String,
        user: String?,
        sourceURL: URL,
        extra: [String: Any]
    ) -> EventEnvelope? {
        guard !extID.isEmpty || !name.isEmpty else { return nil }

        var fields: [String: String] = [
            "browser.name": browser,
            "extension.id": extID,
            "extension.name": name,
            "extension.version": version,
            "extension.permissions": permissions,
            FieldTaxonomy.eventType: "browser.extension",
            FieldTaxonomy.filePath: ArtifactRoot.pathKey(sourceURL),
        ]
        // Broad-permission heuristic for detections (all_urls / <all_urls> / *://*/*)
        let lowerPerms = permissions.lowercased()
        let broad = lowerPerms.contains("all_urls")
            || lowerPerms.contains("*://*/*")
            || lowerPerms.contains("<all_urls>")
            || lowerPerms.contains("://*/")
        fields["extension.broad_permissions"] = broad ? "true" : "false"
        if let user, !user.isEmpty {
            fields[FieldTaxonomy.userName] = user
        }
        if let desc = stringValue(extra["description"]) {
            fields["extension.description"] = desc
        }
        if let enabled = extra["enabled"] {
            fields["extension.enabled"] = boolString(enabled)
        }

        var entities: [EntityID] = [
            EntityID(kind: .host, value: "browser_extension|\(browser)|\(extID.isEmpty ? name : extID)"),
            .file(path: ArtifactRoot.pathKey(sourceURL)),
        ]
        if let user, !user.isEmpty {
            entities.append(.user(name: user))
        }

        return EventEnvelope(
            eventTime: fileMTime(sourceURL),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "BROWSER_EXTENSIONS",
            eventType: "browser.extension",
            entityRefs: entities,
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.95
        )
    }

    private func permissionsString(_ any: Any?) -> String {
        if let s = any as? String { return s }
        if let a = any as? [String] { return a.joined(separator: ",") }
        if let a = any as? [Any] {
            return a.compactMap { $0 as? String }.joined(separator: ",")
        }
        return ""
    }

    /// Chrome manifests often use `__MSG_extName__` - keep as-is unless a simple string.
    private func localizedName(_ any: Any?) -> String? {
        stringValue(any)
    }

    private func boolString(_ any: Any?) -> String {
        if let b = boolish(any) { return b ? "true" : "false" }
        return "false"
    }

    private func fileMTime(_ url: URL) -> Date {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs?[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)
    }
}
