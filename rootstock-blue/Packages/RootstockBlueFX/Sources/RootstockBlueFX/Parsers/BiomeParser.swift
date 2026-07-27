import Foundation
import RootstockBlueCore

/// Apple Biome / pattern-of-life streams (fixture-friendly JSON/JSONL).
///
/// Real Biome stores are protobuf-heavy; collectors often export JSONL under
/// `Users/*/Library/Biome/streams/**`. This parser also accepts a simplified
/// `streams.json` inventory listing.
public struct BiomeParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "BIOME",
        tier: .tier2,
        description: "Biome / pattern-of-life stream events (app_launch, screen_time, media_playback)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var urls: [URL] = []
        var seen = PathDeduper()

        for found in root.enumerate(matching: { url in
            let path = url.path
            let name = url.lastPathComponent
            guard path.contains("/Biome") || path.contains("/Library/Biome") else { return false }
            if name == "streams.json" { return true }
            if name.hasSuffix(".jsonl") || name.hasSuffix(".json") { return true }
            return false
        }) {
            if !seen.insert(found) { continue }
            ArtifactRoot.appendUnique(&urls, found)
        }

        // Explicit firstExisting for well-known fixture layout.
        for rel in [
            "Users/alice/Library/Biome/streams.json",
            "Users/alice/Library/Biome/streams/app_launch.jsonl",
            "Users/alice/Library/Biome/streams/screen_time.jsonl",
            "Users/alice/Library/Biome/streams/media_playback.jsonl",
        ] {
            if let u = root.firstExisting([rel]) {
                if seen.insert(u) {
                    ArtifactRoot.appendUnique(&urls, u)
                }
            }
        }

        var events: [EventEnvelope] = []
        for url in urls {
            if url.lastPathComponent == "streams.json" {
                events.append(contentsOf: parseStreamsInventory(at: url))
            } else if url.pathExtension == "jsonl" || url.lastPathComponent.hasSuffix(".jsonl") {
                events.append(contentsOf: parseJSONL(at: url))
            } else if url.pathExtension == "json" {
                events.append(contentsOf: parseJSONArrayOrObject(at: url))
            }
        }
        return events
    }

    // MARK: - streams.json inventory

    private func parseStreamsInventory(at url: URL) -> [EventEnvelope] {
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }

        let items: [[String: Any]]
        if let arr = obj as? [[String: Any]] {
            items = arr
        } else if let dict = obj as? [String: Any] {
            if let arr = dict["streams"] as? [[String: Any]] {
                items = arr
            } else if let arr = dict["items"] as? [[String: Any]] {
                items = arr
            } else {
                items = []
            }
        } else {
            return []
        }

        let user = inferUser(from: url)
        return items.compactMap { item in
            makeEvent(
                stream: stringValue(item["stream"]) ?? stringValue(item["name"]) ?? stringValue(item["id"]) ?? "unknown",
                value: stringValue(item["value"])
                    ?? stringValue(item["app"])
                    ?? stringValue(item["bundle_id"])
                    ?? stringValue(item["title"])
                    ?? "",
                timestamp: parseDate(item["timestamp"] ?? item["time"] ?? item["start"]),
                user: user,
                sourceURL: url,
                extra: item
            )
        }
    }

    // MARK: - JSONL stream files

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        let user = inferUser(from: url)
        let streamHint = streamNameFromPath(url)
        var events: [EventEnvelope] = []

        for obj in ArtifactIO.jsonlDictionaries(contentsOf: url) {
            let stream = stringValue(obj["stream"])
                ?? stringValue(obj["stream_name"])
                ?? streamHint
            let value = stringValue(obj["value"])
                ?? stringValue(obj["app"])
                ?? stringValue(obj["bundle_id"])
                ?? stringValue(obj["title"])
                ?? stringValue(obj["media_title"])
                ?? ""
            guard !stream.isEmpty || !value.isEmpty else { continue }

            if let event = makeEvent(
                stream: stream.isEmpty ? "biome.unknown" : stream,
                value: value,
                timestamp: parseDate(obj["timestamp"] ?? obj["time"] ?? obj["start"] ?? obj["event_time"]),
                user: user,
                sourceURL: url,
                extra: obj
            ) {
                events.append(event)
            }
        }
        return events
    }

    // MARK: - JSON array of events (non-inventory)

    private func parseJSONArrayOrObject(at url: URL) -> [EventEnvelope] {
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }

        let entries: [[String: Any]]
        if let arr = obj as? [[String: Any]] {
            entries = arr
        } else if let dict = obj as? [String: Any] {
            if let arr = dict["events"] as? [[String: Any]] {
                entries = arr
            } else if let arr = dict["items"] as? [[String: Any]] {
                entries = arr
            } else if dict["stream"] != nil || dict["value"] != nil || dict["app"] != nil {
                entries = [dict]
            } else {
                return []
            }
        } else {
            return []
        }

        let user = inferUser(from: url)
        let streamHint = streamNameFromPath(url)
        return entries.compactMap { item in
            makeEvent(
                stream: stringValue(item["stream"]) ?? streamHint,
                value: stringValue(item["value"])
                    ?? stringValue(item["app"])
                    ?? stringValue(item["bundle_id"])
                    ?? "",
                timestamp: parseDate(item["timestamp"] ?? item["time"] ?? item["start"]),
                user: user,
                sourceURL: url,
                extra: item
            )
        }
    }

    // MARK: - event builder

    private func makeEvent(
        stream: String,
        value: String,
        timestamp: Date?,
        user: String?,
        sourceURL: URL,
        extra: [String: Any]
    ) -> EventEnvelope? {
        guard !stream.isEmpty || !value.isEmpty else { return nil }

        var eventType = "pol.biome.event"
        let lower = stream.lowercased()
        if lower.contains("app_launch") || lower.contains("app/launch") || lower.contains("applaunch") {
            eventType = "pol.biome.app_launch"
        } else if lower.contains("screen_time") || lower.contains("screentime") {
            eventType = "pol.biome.screen_time"
        } else if lower.contains("media") || lower.contains("playback") {
            eventType = "pol.biome.media_playback"
        }

        var fields: [String: String] = [
            "pol.stream": stream,
            "pol.value": value,
            "pol.source": "biome",
            FieldTaxonomy.eventType: eventType,
            FieldTaxonomy.filePath: ArtifactRoot.pathKey(sourceURL),
        ]
        if let user, !user.isEmpty {
            fields[FieldTaxonomy.userName] = user
        }
        if let duration = stringValue(extra["duration"]) ?? stringValue(extra["duration_seconds"]) {
            fields["pol.duration_seconds"] = duration
        }
        if let bundle = stringValue(extra["bundle_id"]) ?? stringValue(extra["bundleId"]) {
            fields["pol.bundle_id"] = bundle
        }

        var entities: [EntityID] = [
            EntityID(kind: .host, value: "biome|\(stream)"),
        ]
        if !value.isEmpty {
            entities.append(EntityID(kind: .persistence, value: "biome|\(value)"))
        }
        if let user, !user.isEmpty {
            entities.append(.user(name: user))
        }

        let mtime = fileMTime(sourceURL)
        return EventEnvelope(
            eventTime: timestamp ?? mtime,
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "BIOME",
            eventType: eventType,
            entityRefs: entities,
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.88
        )
    }

    // MARK: - helpers

    private func streamNameFromPath(_ url: URL) -> String {
        let name = url.deletingPathExtension().lastPathComponent
        if name == "streams" || name.isEmpty { return "biome.stream" }
        return name
    }

    private func fileMTime(_ url: URL) -> Date {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs?[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)
    }
}
