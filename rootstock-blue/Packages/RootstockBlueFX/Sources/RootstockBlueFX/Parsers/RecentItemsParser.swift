import Foundation
import RootstockBlueCore

/// Recent documents / MRU lists (plist or JSON) → timeline events with file entities.
public struct RecentItemsParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "RECENTITEMS",
        tier: .tier2,
        description: "Recent documents and MRU file lists"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []

        let candidates = root.enumerate(matching: {
            let name = $0.lastPathComponent
            return name == "RecentDocuments.plist"
                || name == "RecentDocuments.json"
                || name.hasPrefix("com.apple.LSSharedFileList.RecentDocuments")
                || (name.contains("Recent") && ($0.pathExtension == "plist" || $0.pathExtension == "json")
                    && $0.path.contains("sharedfilelist"))
        })
        // Prefer .plist over companion .json in the same directory (avoid double-count).
        var skipJSONDirs = Set<String>()
        for url in candidates where url.pathExtension == "plist" {
            skipJSONDirs.insert(ArtifactRoot.pathKey(url.deletingLastPathComponent()))
        }
        for url in candidates {
            if url.pathExtension == "json",
               skipJSONDirs.contains(ArtifactRoot.pathKey(url.deletingLastPathComponent())) {
                continue
            }
            if url.pathExtension == "json" {
                events.append(contentsOf: parseJSON(url))
            } else {
                events.append(contentsOf: parsePlist(url))
            }
        }
        return events
    }

    private func parsePlist(_ url: URL) -> [EventEnvelope] {
        guard let data = ArtifactIO.data(contentsOf: url) else { return [] }
        // Prefer dict; fall back to raw property list for array top-level fixtures.
        if let dict = ArtifactIO.plistDict(from: data) {
            return events(from: dict, sourceURL: url)
        }
        guard let obj = ArtifactIO.plistObject(from: data) else { return [] }
        return events(from: obj, sourceURL: url)
    }

    private func parseJSON(_ url: URL) -> [EventEnvelope] {
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }
        return events(from: obj, sourceURL: url)
    }

    private func events(from obj: Any, sourceURL: URL) -> [EventEnvelope] {
        let items = ArtifactIO.dictionaryEntries(
            from: obj,
            nestedKeys: ["items", "RecentDocuments"]
        )

        var out: [EventEnvelope] = []
        for (idx, item) in items.enumerated() {
            let name = stringValue(item["Name"]) ?? stringValue(item["name"]) ?? ""
            let fileURL = stringValue(item["URL"]) ?? stringValue(item["url"]) ?? ""
            guard !name.isEmpty || !fileURL.isEmpty else { continue }
            let path = fileURL.replacingOccurrences(of: "file://", with: "")
            var refs: [EntityID] = []
            if !path.isEmpty { refs.append(.file(path: path)) }
            out.append(
                EventEnvelope(
                    eventTime: Date(timeIntervalSince1970: 0),
                    collectedAt: Date(),
                    source: .parser,
                    sourcePlugin: "RECENTITEMS",
                    eventType: "mru.document",
                    entityRefs: refs,
                    fields: [
                        "mru.name": name,
                        "mru.url": fileURL,
                        "mru.path": path,
                        "mru.index": String(idx),
                        FieldTaxonomy.filePath: path,
                        FieldTaxonomy.eventType: "mru.document",
                        FieldTaxonomy.userName: inferUser(from: sourceURL) ?? "",
                    ],
                    rawRef: ArtifactRoot.pathKey(sourceURL),
                    confidence: 0.88
                )
            )
        }
        return out
    }
}
