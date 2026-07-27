import Foundation
import RootstockBlueCore

/// Compiled AppleScript / OSA delivery residual markers (Wave-12 red↔blue pair).
///
/// Honesty: never compiles malicious .scpt payloads or executes third-party AppleScripts.
public struct OsascriptScptDeliveryParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "OSASCRIPTSCPT",
        tier: .tier2,
        description: "OSA/scpt delivery surface markers"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/osascript_scpt_delivery.json",
            "Library/Logs/osascript_scpt_delivery.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "osascript_scpt_delivery.json" || name == "osascript_scpt_delivery.jsonl"
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
            nestedKeys: ["items", "entries", "surfaces", "paths"],
            identityKeys: ["path", "name", "label", "kind", "tile_path", "share_url"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let secretKeys = ["password", "cookie", "cookie_value", "secret", "token", "keychain_data"]
        for k in secretKeys { _ = item[k] }

        let path = stringish(item["path"])
            ?? stringish(item["tile_path"])
            ?? stringish(item["handler_path"])
            ?? stringish(item["tool_path"])
            ?? ""
        let name = stringish(item["name"])
            ?? stringish(item["rule_name"])
            ?? stringish(item["kind"])
            ?? stringish(item["label"])
            ?? ""
        guard !path.isEmpty || !name.isEmpty else { return nil }

        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.lowercased().contains("password_dump") }
        }
        if risk.isEmpty { risk.append("scpt_surface") }
        if !risk.contains("scpt_surface") { risk.append("scpt_surface") }

        let user = stringish(item["user"]) ?? inferUser(from: path) ?? inferUser(from: sourceURL.path) ?? ""
        var fields: [String: String] = [
            "osa.path": path,
            "osa.name": name,
            "osa.notes": stringish(item["notes"]) ?? "OSA/scpt delivery markers - never compiles malicious .scpt payloads or executes third-party AppleScripts",
            "osa.secrets_exported": "false",
            FieldTaxonomy.eventType: "osascript.scpt",
            FieldTaxonomy.userName: user,
        ]
        if let host = stringish(item["url_host"]) { fields["osa.url_host"] = host }
        if let share = stringish(item["share_url"]) { fields["osa.share_url"] = share }
        if let depth = stringish(item["depth"]) { fields["osa.depth"] = depth }
        if boolish(item["runs_script"]) == true { fields["osa.runs_script"] = "true" }
        if boolish(item["tool_present"]) == true { fields["osa.tool_present"] = "true" }
        if !risk.isEmpty { fields["osa.risk_tags"] = risk.joined(separator: ",") }

        return EventEnvelope(
            eventTime: parseDate(item["timestamp"] ?? item["seen_at"]) ?? Date(),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "OSASCRIPTSCPT",
            eventType: "osascript.scpt",
            entityRefs: [
                EntityID(kind: .host, value: "osa|\(name.isEmpty ? path : name)"),
            ],
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.88
        )
    }
}
