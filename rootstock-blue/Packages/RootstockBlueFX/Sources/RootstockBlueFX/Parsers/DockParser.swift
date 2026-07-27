import Foundation
import RootstockBlueCore

/// Dock persistent/recent apps and folders from com.apple.dock.plist.
/// Emits dock.item / mru.app events with file entity refs for case timeline merge.
public struct DockParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "DOCK",
        tier: .tier2,
        description: "Dock persistent-apps, recent-apps, and folders"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        let plists = root.enumerate { url in
            url.lastPathComponent == "com.apple.dock.plist"
        }
        var events: [EventEnvelope] = []
        for url in plists {
            events.append(contentsOf: parseDock(at: url))
        }
        return events
    }

    private func parseDock(at url: URL) -> [EventEnvelope] {
        guard let dict = ArtifactIO.plistDict(contentsOf: url) else { return [] }

        let user = inferUser(from: url)
        var events: [EventEnvelope] = []
        events.append(contentsOf: tiles(
            dict["persistent-apps"] as? [Any] ?? [],
            kind: "persistent_app",
            eventType: "dock.item",
            sourceURL: url,
            user: user
        ))
        events.append(contentsOf: tiles(
            dict["recent-apps"] as? [Any] ?? [],
            kind: "recent_app",
            eventType: "mru.app",
            sourceURL: url,
            user: user
        ))
        events.append(contentsOf: tiles(
            dict["persistent-others"] as? [Any] ?? [],
            kind: "persistent_other",
            eventType: "dock.item",
            sourceURL: url,
            user: user
        ))
        return events
    }

    private func tiles(
        _ items: [Any],
        kind: String,
        eventType: String,
        sourceURL: URL,
        user: String?
    ) -> [EventEnvelope] {
        var out: [EventEnvelope] = []
        for (idx, item) in items.enumerated() {
            guard let tile = item as? [String: Any] else { continue }
            let data = tile["tile-data"] as? [String: Any] ?? tile
            let label = stringValue(data["file-label"])
                ?? stringValue(data["file-label"])
                ?? stringValue(data["bundle-identifier"])
                ?? ""
            let bundle = stringValue(data["bundle-identifier"]) ?? ""
            let path = extractPath(from: data)
            guard !label.isEmpty || !path.isEmpty || !bundle.isEmpty else { continue }

            var entities: [EntityID] = []
            if !path.isEmpty {
                entities.append(.file(path: path))
            }
            if let user, !user.isEmpty {
                entities.append(.user(name: user))
            }

            var fields: [String: String] = [
                "dock.kind": kind,
                "dock.label": label,
                "dock.bundle_id": bundle,
                "dock.path": path,
                "dock.index": String(idx),
                "dock.plist_path": ArtifactRoot.pathKey(sourceURL),
                FieldTaxonomy.filePath: path,
                FieldTaxonomy.eventType: eventType,
                FieldTaxonomy.userName: user ?? "",
            ]
            if !bundle.isEmpty {
                fields["app.bundle_id"] = bundle
            }

            out.append(
                EventEnvelope(
                    eventTime: Date(timeIntervalSince1970: 0),
                    collectedAt: Date(),
                    source: .parser,
                    sourcePlugin: "DOCK",
                    eventType: eventType,
                    entityRefs: entities,
                    fields: fields,
                    rawRef: ArtifactRoot.pathKey(sourceURL),
                    confidence: 0.9
                )
            )
        }
        return out
    }

    private func extractPath(from tileData: [String: Any]) -> String {
        if let fileData = tileData["file-data"] as? [String: Any] {
            if let s = stringValue(fileData["_CFURLString"]) {
                return normalizeFileURL(s)
            }
            if let s = stringValue(fileData["URL"]) {
                return normalizeFileURL(s)
            }
        }
        if let s = stringValue(tileData["file-path"]) {
            return normalizeFileURL(s)
        }
        if let s = stringValue(tileData["path"]) {
            return normalizeFileURL(s)
        }
        return ""
    }

    private func normalizeFileURL(_ s: String) -> String {
        var t = s
        if t.hasPrefix("file://") {
            t = String(t.dropFirst("file://".count))
            // Percent-decode lightly
            t = t.removingPercentEncoding ?? t
        }
        // Drop trailing slash for apps if desired - keep as-is for dirs
        return t
    }

}
