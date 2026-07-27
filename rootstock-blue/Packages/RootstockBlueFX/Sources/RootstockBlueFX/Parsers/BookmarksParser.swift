import Foundation
import RootstockBlueCore

/// Browser bookmarks inventory - URL/title/folder PoL for IR narrative.
///
/// Surfaces evil-domain and suspicious bookmarks as first-class case events
/// shared across Safari/Chromium/Firefox engines.
public struct BookmarksParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "BOOKMARKS",
        tier: .tier2,
        description: "Browser bookmarks inventory (URL/title/folder with risk tags)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/bookmarks_inventory.json",
            "Library/Preferences/browser_bookmarks.json",
            "Library/Logs/bookmarks_export.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "bookmarks_inventory.json"
                || name == "browser_bookmarks.json"
                || name == "bookmarks_export.jsonl"
                || name == "Bookmarks.json"
                || (name == "Bookmarks" && url.pathExtension.isEmpty)
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
            nestedKeys: ["bookmarks", "items", "roots"],
            identityKeys: ["url", "uri"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url)
            .compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let urlString = stringish(item["url"])
            ?? stringish(item["uri"])
            ?? stringish(item["href"])
            ?? ""
        let title = stringish(item["title"])
            ?? stringish(item["name"])
            ?? ""
        let folder = stringish(item["folder"])
            ?? stringish(item["parent"])
            ?? stringish(item["path"])
            ?? ""
        let engine = stringish(item["engine"])
            ?? stringish(item["browser"])
            ?? ""

        guard !urlString.isEmpty || !title.isEmpty else { return nil }

        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        }
        let lower = (urlString + " " + title).lowercased()
        if lower.contains("evil") || lower.contains("malware") || lower.contains("c2.") {
            if !risk.contains("evil_domain") { risk.append("evil_domain") }
        }
        if lower.contains("pastebin") || lower.contains("ngrok") || lower.contains("raw.githubusercontent") {
            if !risk.contains("suspicious_domain") { risk.append("suspicious_domain") }
        }
        if urlString.lowercased().hasPrefix("javascript:") || urlString.lowercased().hasPrefix("data:") {
            if !risk.contains("script_bookmark") { risk.append("script_bookmark") }
        }

        let user = stringish(item["user"]) ?? inferUser(from: sourceURL.path) ?? ""

        var fields: [String: String] = [
            "bookmark.url": urlString,
            "bookmark.title": String(title.prefix(200)),
            "bookmark.folder": folder,
            "bookmark.engine": engine,
            FieldTaxonomy.eventType: "browser.bookmark",
            FieldTaxonomy.browserName: engine,
            FieldTaxonomy.userName: user,
        ]
        if !risk.isEmpty {
            fields["bookmark.risk_tags"] = risk.joined(separator: ",")
        }

        return EventEnvelope(
            eventTime: parseDate(item["added"] ?? item["date_added"] ?? item["timestamp"])
                ?? Date(timeIntervalSince1970: 0),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "BOOKMARKS",
            eventType: "browser.bookmark",
            entityRefs: urlString.isEmpty
                ? [EntityID(kind: .host, value: "bookmark|\(title)")]
                : [EntityID(kind: .file, value: urlString)],
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.9
        )
    }
}
