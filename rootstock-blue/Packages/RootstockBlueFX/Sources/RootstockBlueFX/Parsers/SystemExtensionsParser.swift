import Foundation
import RootstockBlueCore

/// System Extensions inventory (Network Extension, Endpoint Security, DriverKit, etc.).
///
/// Fixture-friendly: `Library/SystemExtensions/extensions.json`.
public struct SystemExtensionsParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "SYSTEMEXTENSIONS",
        tier: .tier1,
        description: "Installed system extensions (bundle id, state, team id)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var urls: [URL] = []
        var seen = PathDeduper()

        for found in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            let path = url.path
            if name == "extensions.json" && (path.contains("SystemExtensions") || path.contains("SystemPolicy")) {
                return true
            }
            if path.contains("/SystemExtensions/") && (name.hasSuffix(".json") || name.hasSuffix(".plist")) {
                return true
            }
            if path.contains("SystemPolicyConfiguration") && (name.hasSuffix(".json") || name.hasSuffix(".plist")) {
                return true
            }
            return false
        }) {
            if !seen.insert(found) { continue }
            ArtifactRoot.appendUnique(&urls, found)
        }

        if let explicit = root.firstExisting([
            "Library/SystemExtensions/extensions.json",
            "private/var/db/SystemPolicyConfiguration/extensions.json",
        ]) {
            if seen.insert(explicit) {
                ArtifactRoot.appendUnique(&urls, explicit)
            }
        }

        var events: [EventEnvelope] = []
        for url in urls {
            events.append(contentsOf: parseExtensionsFile(at: url))
        }
        return events
    }

    private func parseExtensionsFile(at url: URL) -> [EventEnvelope] {
        guard let data = ArtifactIO.data(contentsOf: url) else { return [] }

        if let items = parseJSONItems(data) {
            return items.compactMap { makeEvent(item: $0, sourceURL: url) }
        }

        if let dict = ArtifactIO.plistDict(from: data),
           let items = extractItems(from: dict) {
            return items.compactMap { makeEvent(item: $0, sourceURL: url) }
        }

        return []
    }

    private func parseJSONItems(_ data: Data) -> [[String: Any]]? {
        guard let obj = ArtifactIO.jsonObject(from: data) else { return nil }
        return extractItems(from: obj)
    }

    private func extractItems(from obj: Any) -> [[String: Any]]? {
        if let arr = obj as? [[String: Any]] { return arr }
        if let arr = obj as? [Any] { return arr.compactMap { $0 as? [String: Any] } }
        if let dict = obj as? [String: Any] {
            if let items = dict["extensions"] as? [[String: Any]] { return items }
            if let items = dict["items"] as? [[String: Any]] { return items }
            if let items = dict["Extensions"] as? [[String: Any]] { return items }
        }
        return nil
    }

    private func makeEvent(item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let bundleID = stringValue(item["bundle_id"])
            ?? stringValue(item["bundleId"])
            ?? stringValue(item["CFBundleIdentifier"])
            ?? stringValue(item["identifier"])
            ?? ""
        let state = stringValue(item["state"])
            ?? stringValue(item["State"])
            ?? stringValue(item["status"])
            ?? ""
        let teamID = stringValue(item["team_id"])
            ?? stringValue(item["teamId"])
            ?? stringValue(item["TeamIdentifier"])
            ?? stringValue(item["team"])
            ?? ""
        let category = stringValue(item["category"])
            ?? stringValue(item["Category"])
            ?? stringValue(item["type"])
            ?? ""
        let path = stringValue(item["path"])
            ?? stringValue(item["URL"])
            ?? stringValue(item["url"])
            ?? ""

        guard !bundleID.isEmpty || !path.isEmpty else { return nil }

        // Prefer defense.system_extension for IR (ESF/NE/unknown third-party).
        // host.system_extension reserved for clearly Apple/driverkit inventory only.
        let lowerCat = category.lowercased()
        let lowerBundle = bundleID.lowercased()
        let isAppleDriver = lowerCat.contains("driverkit")
            || lowerBundle.hasPrefix("com.apple.")
        let eventType = isAppleDriver ? "host.system_extension" : "defense.system_extension"

        var fields: [String: String] = [
            "extension.bundle_id": bundleID,
            "extension.state": state,
            "extension.team_id": teamID,
            "extension.category": category,
            FieldTaxonomy.eventType: eventType,
            FieldTaxonomy.filePath: path.isEmpty ? ArtifactRoot.pathKey(sourceURL) : path,
        ]
        if !path.isEmpty {
            fields["extension.path"] = path
        }
        if let version = stringValue(item["version"]) ?? stringValue(item["CFBundleShortVersionString"]) {
            fields["extension.version"] = version
        }

        var entities: [EntityID] = [
            EntityID(kind: .host, value: "system_extension|\(bundleID.isEmpty ? path : bundleID)"),
            .file(path: ArtifactRoot.pathKey(sourceURL)),
        ]
        if !path.isEmpty {
            entities.append(.file(path: path))
        }
        if !teamID.isEmpty {
            entities.append(EntityID(kind: .host, value: "team|\(teamID)"))
        }

        return EventEnvelope(
            eventTime: fileMTime(sourceURL),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "SYSTEMEXTENSIONS",
            eventType: eventType,
            entityRefs: entities,
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.93
        )
    }

    private func fileMTime(_ url: URL) -> Date {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs?[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)
    }
}
