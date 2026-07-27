import Foundation
import RootstockBlueCore

/// Screen Time / Focus markers - app usage inventory and focus-mode posture.
///
/// Metadata only: app_id, category, usage_seconds, focus mode. Does not dump
/// private activity content or full knowledgeC-style message bodies.
public struct ScreenTimeParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "SCREENTIME",
        tier: .tier2,
        description: "Screen Time / Focus markers (app usage inventory, not private content)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/screentime_markers.json",
            "Library/Preferences/screentime.json",
            "Library/Preferences/screen_time.json",
            "Library/Logs/screentime_export.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "screentime_markers.json"
                || name == "screentime.json"
                || name == "screen_time.json"
                || name == "screentime_export.jsonl"
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
        // Multi-bucket JSON: apps + focus + items can coexist in one object.
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }

        var events: [EventEnvelope] = []
        if let dict = obj as? [String: Any] {
            if let apps = dict["apps"] as? [[String: Any]] {
                events.append(contentsOf: apps.compactMap { makeAppEvent(from: $0, sourceURL: url) })
            }
            if let focus = dict["focus"] as? [[String: Any]] {
                events.append(contentsOf: focus.compactMap { makeFocusEvent(from: $0, sourceURL: url) })
            }
            if let items = dict["items"] as? [[String: Any]] {
                events.append(contentsOf: items.compactMap { makeAppEvent(from: $0, sourceURL: url) })
            }
            // Single object
            if dict["app_id"] != nil {
                if let e = makeAppEvent(from: dict, sourceURL: url) {
                    events.append(e)
                }
            }
        } else if let arr = obj as? [[String: Any]] {
            events.append(contentsOf: arr.compactMap { makeAppEvent(from: $0, sourceURL: url) })
        }
        return events
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        for obj in ArtifactIO.jsonlDictionaries(contentsOf: url) {
            if obj["mode"] != nil || obj["focus_mode"] != nil, obj["app_id"] == nil {
                if let e = makeFocusEvent(from: obj, sourceURL: url) { events.append(e) }
            } else if let e = makeAppEvent(from: obj, sourceURL: url) {
                events.append(e)
            }
        }
        return events
    }

    private func makeAppEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let appID = stringish(item["app_id"])
            ?? stringish(item["bundle_id"])
            ?? stringish(item["identifier"])
            ?? ""
        guard !appID.isEmpty else { return nil }

        let bundlePath = stringish(item["bundle_path"])
            ?? stringish(item["path"])
            ?? ""
        let category = stringish(item["category"]) ?? ""
        let usage = stringish(item["usage_seconds"])
            ?? stringish(item["usage"])
            ?? ""
        let focusMode = stringish(item["focus_mode"]) ?? ""

        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        }
        let lowerApp = appID.lowercased()
        let lowerPath = bundlePath.lowercased()
        if lowerApp.contains("evil") || lowerApp.contains("implant") || lowerApp.contains("malware") {
            if !risk.contains("suspicious_app") { risk.append("suspicious_app") }
        }
        if lowerPath.contains("/tmp/") || lowerPath.hasPrefix("/var/tmp") {
            if !risk.contains("tmp_path") { risk.append("tmp_path") }
        }
        if let secs = Double(usage), secs >= 3600 {
            if !risk.contains("high_usage") { risk.append("high_usage") }
        }

        var fields: [String: String] = [
            "screentime.app_id": appID,
            "screentime.bundle_path": bundlePath,
            "screentime.category": category,
            "screentime.usage_seconds": usage,
            "screentime.focus_mode": focusMode,
            FieldTaxonomy.eventType: "pol.screentime",
        ]
        if let lastUsed = stringish(item["last_used"]) {
            fields["screentime.last_used"] = lastUsed
        }
        if !risk.isEmpty {
            fields["screentime.risk_tags"] = risk.joined(separator: ",")
        }

        return EventEnvelope(
            eventTime: parseDate(item["last_used"]) ?? Date(timeIntervalSince1970: 0),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "SCREENTIME",
            eventType: "pol.screentime",
            entityRefs: [EntityID(kind: .host, value: "screentime|\(appID)")],
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.86
        )
    }

    private func makeFocusEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let mode = stringish(item["mode"])
            ?? stringish(item["focus_mode"])
            ?? ""
        guard !mode.isEmpty else { return nil }
        let enabled = boolish(item["enabled"]) ?? true

        return EventEnvelope(
            eventTime: parseDate(item["last_changed"]) ?? Date(timeIntervalSince1970: 0),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "SCREENTIME",
            eventType: "pol.focus",
            entityRefs: [EntityID(kind: .host, value: "focus|\(mode)")],
            fields: [
                "screentime.focus_mode": mode,
                "screentime.focus_enabled": enabled ? "true" : "false",
                FieldTaxonomy.eventType: "pol.focus",
            ],
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.85
        )
    }
}
