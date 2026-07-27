import Foundation
import RootstockBlueCore

/// QuickLook thumbnail cache inventory - which files were previewed.
///
/// Sensitive paths in QL cache are high-ROI for IR (documents opened even if deleted).
public struct QuickLookParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "QUICKLOOK",
        tier: .tier2,
        description: "QuickLook thumbnail cache inventory (previewed paths)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/quicklook_cache.json",
            "Library/Preferences/quicklook_export.json",
            "Library/Logs/quicklook_cache.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "quicklook_cache.json"
                || name == "quicklook_export.json"
                || name == "quicklook_cache.jsonl"
        }) {
            if seen.insert(url) {
                events.append(contentsOf: parseFile(at: url))
            }
        }

        // Marker under com.apple.QuickLook.thumbnailcache
        for url in root.enumerate(matching: { url in
            url.path.contains("QuickLook")
                && (url.lastPathComponent.hasSuffix(".marker")
                    || url.lastPathComponent == "index.sqlite"
                    || url.lastPathComponent.hasSuffix(".sqlite.marker"))
        }) {
            let key = "ql-marker:" + ArtifactRoot.pathKey(url)
            if seen.insert(pathKey: key) {
                events.append(
                    EventEnvelope(
                        eventTime: Date(timeIntervalSince1970: 0),
                        collectedAt: Date(),
                        source: .parser,
                        sourcePlugin: "QUICKLOOK",
                        eventType: "filesystem.quicklook",
                        entityRefs: [.file(path: ArtifactRoot.pathKey(url))],
                        fields: [
                            "ql.cache_path": ArtifactRoot.pathKey(url),
                            "ql.marker": "true",
                            FieldTaxonomy.eventType: "filesystem.quicklook",
                        ],
                        rawRef: ArtifactRoot.pathKey(url),
                        confidence: 0.7
                    )
                )
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
            nestedKeys: ["thumbnails", "items", "cache"],
            identityKeys: ["path"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url)
            .compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let path = stringish(item["path"])
            ?? stringish(item["fs_path"])
            ?? stringish(item["file"])
            ?? ""
        let contentType = stringish(item["content_type"])
            ?? stringish(item["uti"])
            ?? ""
        guard !path.isEmpty else { return nil }

        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        }
        let lower = path.lowercased()
        if lower.contains("password") || lower.contains("secret")
            || lower.contains("credential") || lower.contains("id_rsa")
            || lower.contains(".pem") || lower.contains("ssn") {
            if !risk.contains("sensitive_path") { risk.append("sensitive_path") }
            if !risk.contains("credential_filename") { risk.append("credential_filename") }
        }
        if lower.contains("evil") || lower.contains("payload") || lower.contains("implant") {
            if !risk.contains("suspicious_name") { risk.append("suspicious_name") }
        }

        var fields: [String: String] = [
            "ql.path": path,
            "ql.content_type": contentType,
            FieldTaxonomy.eventType: "filesystem.quicklook",
        ]
        if let mtime = stringish(item["mtime"]) {
            fields["ql.mtime"] = mtime
        }
        if let hits = stringish(item["hit_count"]) ?? stringish(item["hits"]) {
            fields["ql.hit_count"] = hits
        }
        if !risk.isEmpty {
            fields["ql.risk_tags"] = risk.joined(separator: ",")
        }

        return EventEnvelope(
            eventTime: parseDate(item["mtime"]) ?? Date(timeIntervalSince1970: 0),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "QUICKLOOK",
            eventType: "filesystem.quicklook",
            entityRefs: [.file(path: path)],
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.88
        )
    }
}
