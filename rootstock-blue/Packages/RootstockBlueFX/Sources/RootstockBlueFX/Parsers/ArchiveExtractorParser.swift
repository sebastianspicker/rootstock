import Foundation
import RootstockBlueCore

/// Third-party archive extractor / quarantine non-inheritance surface (Wave-8 residual pair).
///
/// Inventories extractor apps and drop hints from offline markers.
/// Does not strip quarantine attributes or craft bypass archives.
public struct ArchiveExtractorParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "ARCHIVEEXTRACTOR",
        tier: .tier2,
        description: "Archive quarantine extractor surface (third-party vs stock)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/archive_extractors.json",
            "Library/Logs/archive_extractors.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "archive_extractors.json" || name == "archive_extractors.jsonl"
        }) {
            if seen.insert(url) {
                events.append(contentsOf: parseFile(at: url))
            }
        }

        return events
    }

    private func parseFile(at url: URL) -> [EventEnvelope] {
        if url.pathExtension == "jsonl" {
            return ArtifactIO.jsonlDictionaries(contentsOf: url)
                .compactMap { makeEvent(from: $0, sourceURL: url) }
        }
        return ArtifactIO.jsonDictionaryEntries(
            contentsOf: url,
            nestedKeys: ["extractors", "items", "entries"],
            identityKeys: ["extractor_name", "name", "extractor_path", "path"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        var name = stringish(item["extractor_name"])
            ?? stringish(item["name"])
            ?? stringish(item["app"])
            ?? ""
        let path = stringish(item["extractor_path"])
            ?? stringish(item["path"])
            ?? stringish(item["app_path"])
            ?? ""
        if name.isEmpty, !path.isEmpty {
            name = URL(fileURLWithPath: path).deletingPathExtension().lastPathComponent
        }
        let thirdParty = boolish(item["third_party"])
            ?? inferThirdParty(name: name, path: path)
        let dropHint = stringish(item["drop_hint"])
            ?? stringish(item["drop_path"])
            ?? stringish(item["downloads_hint"])
            ?? ""
        let user = stringish(item["user"]) ?? inferUser(from: sourceURL.path) ?? ""

        guard !name.isEmpty || !path.isEmpty else { return nil }
        if name.isEmpty { name = "unknown" }

        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        }
        if thirdParty {
            if !risk.contains("third_party_extractor") { risk.append("third_party_extractor") }
            if !risk.contains("quarantine_non_inherit") { risk.append("quarantine_non_inherit") }
        }

        var fields: [String: String] = [
            "archive.extractor_name": name,
            "archive.extractor_path": path,
            "archive.third_party": thirdParty ? "true" : "false",
            "archive.drop_hint": dropHint,
            FieldTaxonomy.eventType: "archive.extractor",
            FieldTaxonomy.userName: user,
        ]
        if !risk.isEmpty {
            fields["archive.risk_tags"] = risk.joined(separator: ",")
        }

        return EventEnvelope(
            eventTime: parseDate(item["timestamp"] ?? item["seen_at"]) ?? Date(),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "ARCHIVEEXTRACTOR",
            eventType: "archive.extractor",
            entityRefs: [
                EntityID(kind: .host, value: "archive|\(name.lowercased())|\(thirdParty)"),
            ],
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.9
        )
    }

    private func inferThirdParty(name: String, path: String) -> Bool {
        let p = path.lowercased()
        let n = name.lowercased()
        if p.contains("/system/library/") || p.hasPrefix("/usr/bin/") {
            return false
        }
        let third = ["keka", "the unarchiver", "betterzip", "archiver", "izip",
                     "stuffit", "winzip", "commander one", "path finder"]
        if third.contains(where: { n.contains($0) || p.contains($0.replacingOccurrences(of: " ", with: "")) }) {
            return true
        }
        // Applications/ outside stock Archive Utility → treat as third-party by default
        if p.contains("/applications/") && !p.contains("archive utility") {
            return true
        }
        return false
    }
}
