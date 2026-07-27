import Foundation
import RootstockBlueCore

/// Spotlight metadata inventory from collector/fixture JSON exports.
///
/// Surfaces indexed paths, content types, and display names for IR hunting
/// (sensitive filenames, suspicious downloads) - not a full mds store rewrite.
public struct SpotlightParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "SPOTLIGHT",
        tier: .tier2,
        description: "Spotlight metadata inventory (indexed paths / content types)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/spotlight_inventory.json",
            "Library/Logs/spotlight_export.jsonl",
            "Library/Preferences/spotlight_export.json",
        ] {
            if let url = root.firstExisting([rel]), seen.insert(url) {
                events.append(contentsOf: parseFile(at: url))
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "spotlight_inventory.json"
                || name == "spotlight_export.json"
                || name == "spotlight_export.jsonl"
        }) {
            if seen.insert(url) {
                events.append(contentsOf: parseFile(at: url))
            }
        }

        return events
    }

    private func parseFile(at url: URL) -> [EventEnvelope] {
        if url.pathExtension == "jsonl" || url.lastPathComponent.hasSuffix(".jsonl") {
            return ArtifactIO.jsonlDictionaries(contentsOf: url).compactMap { makeEvent(from: $0, sourceURL: url) }
        }
        return parseJSON(at: url)
    }

    private func parseJSON(at url: URL) -> [EventEnvelope] {
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }

        let entries = ArtifactIO.dictionaryEntries(
            from: obj,
            nestedKeys: ["items", "entries", "spotlight"],
            identityKeys: ["path", "display_name"]
        )
        return entries.compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let path = stringish(item["path"])
            ?? stringish(item["kMDItemPath"])
            ?? stringish(item["fs_path"])
            ?? ""
        let displayName = stringish(item["display_name"])
            ?? stringish(item["kMDItemDisplayName"])
            ?? stringish(item["kMDItemFSName"])
            ?? stringish(item["name"])
            ?? (path as NSString).lastPathComponent
        let contentType = stringish(item["content_type"])
            ?? stringish(item["kMDItemContentType"])
            ?? stringish(item["uti"])
            ?? ""

        guard !path.isEmpty || !displayName.isEmpty else { return nil }

        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        }
        let lowerPath = path.lowercased()
        let lowerName = displayName.lowercased()
        if lowerPath.contains("password") || lowerName.contains("password")
            || lowerPath.contains("secret") || lowerName.contains("credential")
            || lowerPath.contains("id_rsa") || lowerPath.contains(".pem") {
            if !risk.contains("sensitive_path") { risk.append("sensitive_path") }
            if !risk.contains("credential_filename") { risk.append("credential_filename") }
        }
        if lowerName.contains("evil") || lowerPath.contains("evil")
            || lowerPath.contains("/tmp/") || lowerName.contains("payload") {
            if !risk.contains("suspicious_name") { risk.append("suspicious_name") }
        }

        var fields: [String: String] = [
            "spotlight.path": path,
            "spotlight.display_name": displayName,
            "spotlight.content_type": contentType,
            FieldTaxonomy.eventType: "filesystem.spotlight",
        ]
        if !risk.isEmpty {
            fields["spotlight.risk_tags"] = risk.joined(separator: ",")
        }
        if let mtime = stringish(item["mtime"]) ?? stringish(item["kMDItemContentModificationDate"]) {
            fields["spotlight.mtime"] = mtime
        }
        if let user = inferUser(from: path.isEmpty ? sourceURL.path : path) {
            fields[FieldTaxonomy.userName] = user
        }

        var refs: [EntityID] = []
        if !path.isEmpty { refs.append(.file(path: path)) }
        refs.append(EntityID(kind: .host, value: "spotlight|\(displayName)"))

        return EventEnvelope(
            eventTime: parseDate(item["mtime"] ?? item["kMDItemContentModificationDate"]) ?? Date(timeIntervalSince1970: 0),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "SPOTLIGHT",
            eventType: "filesystem.spotlight",
            entityRefs: refs,
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.88
        )
    }
}
