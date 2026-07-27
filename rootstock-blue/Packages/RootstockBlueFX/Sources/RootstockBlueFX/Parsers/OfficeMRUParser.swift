import Foundation
import RootstockBlueCore

/// Office / collaboration Most Recently Used (MRU) inventory.
///
/// Covers Microsoft Office, Teams, Slack recent documents/channels markers,
/// deeper than generic Apple RecentDocuments for collab IR narrative.
public struct OfficeMRUParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "OFFICEMRU",
        tier: .tier2,
        description: "Office/Teams/Slack collaboration MRU with risk tags"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/office_mru.json",
            "Library/Preferences/collab_mru.json",
            "Library/Preferences/msoffice_recent.json",
            "Library/Logs/office_mru.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "office_mru.json"
                || name == "collab_mru.json"
                || name == "msoffice_recent.json"
                || name == "office_mru.jsonl"
                || name == "File MRU.json"
        }) {
            if seen.insert(url) {
                events.append(contentsOf: parseFile(at: url))
            }
        }

        return events
    }

    private func parseFile(at url: URL) -> [EventEnvelope] {
        if url.pathExtension == "jsonl" {
            return parseJSONL(at: url)
        }
        return ArtifactIO.jsonDictionaryEntries(
            contentsOf: url,
            nestedKeys: ["items", "recent", "documents"],
            identityKeys: ["path", "app"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url)
            .compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let app = stringish(item["app"])
            ?? stringish(item["application"])
            ?? stringish(item["bundle_id"])
            ?? "office"
        let path = stringish(item["path"])
            ?? stringish(item["url"])
            ?? stringish(item["file_path"])
            ?? ""
        let title = stringish(item["title"])
            ?? stringish(item["name"])
            ?? stringish(item["document"])
            ?? ""
        let channel = stringish(item["channel"])
            ?? stringish(item["workspace"])
            ?? ""

        guard !path.isEmpty || !title.isEmpty || !channel.isEmpty else { return nil }

        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        }
        let lowerPath = path.lowercased()
        let lowerTitle = title.lowercased()
        if lowerPath.contains("/tmp/") || lowerPath.contains("/var/folders/") {
            if !risk.contains("tmp_path") { risk.append("tmp_path") }
        }
        if lowerPath.contains("evil") || lowerTitle.contains("evil")
            || lowerPath.contains("payload") || lowerPath.contains("implant") {
            if !risk.contains("suspicious_path") { risk.append("suspicious_path") }
        }
        if lowerPath.contains("password") || lowerTitle.contains("password")
            || lowerPath.contains("secret") || lowerTitle.contains("credential")
            || lowerPath.contains(".ssh/") || lowerPath.hasSuffix(".pem") {
            if !risk.contains("sensitive_document") { risk.append("sensitive_document") }
        }
        if lowerPath.contains("sharepoint") || lowerPath.contains("onedrive")
            || path.lowercased().hasPrefix("https://") {
            if !risk.contains("cloud_document") { risk.append("cloud_document") }
        }

        let user = stringish(item["user"]) ?? inferUser(from: sourceURL.path) ?? ""

        var fields: [String: String] = [
            "office.app": app,
            "office.path": path,
            "office.title": String(title.prefix(200)),
            "office.channel": channel,
            FieldTaxonomy.eventType: "mru.office",
            FieldTaxonomy.filePath: path,
            FieldTaxonomy.userName: user,
        ]
        if let accessed = stringish(item["last_accessed"]) ?? stringish(item["timestamp"]) {
            fields["office.last_accessed"] = accessed
        }
        if !risk.isEmpty {
            fields["office.risk_tags"] = risk.joined(separator: ",")
        }

        var refs: [EntityID] = []
        if !path.isEmpty { refs.append(.file(path: path)) }
        refs.append(EntityID(kind: .host, value: "office|\(app)"))

        return EventEnvelope(
            eventTime: parseDate(item["last_accessed"] ?? item["timestamp"] ?? item["modified"])
                ?? Date(timeIntervalSince1970: 0),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "OFFICEMRU",
            eventType: "mru.office",
            entityRefs: refs,
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.9
        )
    }
}
