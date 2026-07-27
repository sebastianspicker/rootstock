import Foundation
import RootstockBlueCore

/// Notification Center inventory - **metadata markers only**.
///
/// Emits app_id, category, title markers, and delivery times.
/// Does not export full notification body content into case JSONL by default
/// (privacy non-goal: no full message-body dumps).
public struct NotificationsParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "NOTIFICATIONS",
        tier: .tier2,
        description: "Notification Center metadata markers (no full body dumps)"
    )

    /// Body-like keys that must never be copied into envelopes.
    private static let forbiddenBodyKeys: Set<String> = [
        "body", "message", "subtitle", "userinfo", "user_info",
        "content", "text", "alert_body", "full_text", "notification_body",
    ]

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/notification_center.json",
            "Library/Preferences/notifications.json",
            "Library/Logs/notification_center.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "notification_center.json"
                || name == "notifications.json"
                || name == "notification_center.jsonl"
                || name == "db2-export.json"
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
            nestedKeys: ["notifications", "items", "entries"],
            identityKeys: ["app_id", "bundle_id"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url)
            .compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        // Defense-in-depth: drop forbidden body keys from consideration
        for key in item.keys {
            if Self.forbiddenBodyKeys.contains(key.lowercased()) {
                // intentionally ignored - never copied
                continue
            }
        }

        let appID = stringish(item["app_id"])
            ?? stringish(item["bundle_id"])
            ?? stringish(item["identifier"])
            ?? ""
        let category = stringish(item["category"])
            ?? stringish(item["thread"])
            ?? ""
        // Title marker only - short headline, not full body
        let titleMarker = stringish(item["title_marker"])
            ?? stringish(item["title"])
            ?? stringish(item["headline"])
            ?? ""
        // Cap title marker length to avoid accidental body dumps
        let cappedTitle = String(titleMarker.prefix(120))

        guard !appID.isEmpty || !cappedTitle.isEmpty else { return nil }

        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        }
        let lowerApp = appID.lowercased()
        if lowerApp.contains("evil") || lowerApp.contains("implant") || lowerApp.contains("malware") {
            if !risk.contains("suspicious_app") { risk.append("suspicious_app") }
        }
        let lowerTitle = cappedTitle.lowercased()
        if lowerTitle.contains("remote access") || lowerTitle.contains("password")
            || lowerTitle.contains("credential") || lowerTitle.contains("security") {
            if !risk.contains("security_sensitive") { risk.append("security_sensitive") }
        }

        let bodyExported = boolish(item["body_exported"]) == true
        // Product non-goal: never emit body text even if source JSON includes it
        var fields: [String: String] = [
            "notif.app_id": appID,
            "notif.category": category,
            "notif.title_marker": cappedTitle,
            "notif.body_exported": bodyExported ? "true" : "false",
            FieldTaxonomy.eventType: "notification.delivered",
        ]
        if let delivered = stringish(item["delivered_at"]) ?? stringish(item["timestamp"]) {
            fields["notif.delivered_at"] = delivered
        }
        if let hasBody = boolish(item["has_body"]) {
            fields["notif.has_body"] = hasBody ? "true" : "false"
        }
        if !risk.isEmpty {
            fields["notif.risk_tags"] = risk.joined(separator: ",")
        }

        // Explicitly ensure no body field slipped in
        fields.removeValue(forKey: "notif.body")
        fields.removeValue(forKey: "body")
        fields.removeValue(forKey: "message")

        return EventEnvelope(
            eventTime: parseDate(item["delivered_at"] ?? item["timestamp"]) ?? Date(timeIntervalSince1970: 0),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "NOTIFICATIONS",
            eventType: "notification.delivered",
            entityRefs: [EntityID(kind: .host, value: "notif|\(appID)")],
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.88
        )
    }
}
