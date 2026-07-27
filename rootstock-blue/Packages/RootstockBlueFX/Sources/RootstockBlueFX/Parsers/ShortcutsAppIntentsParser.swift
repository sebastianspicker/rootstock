import Foundation
import RootstockBlueCore

/// Shortcuts / App Intents automation markers (Wave-11 red↔blue pair).
///
/// Inventories Shortcuts database / App Intents framework path markers for IR.
/// Honesty: never runs shortcuts or forges intents.
public struct ShortcutsAppIntentsParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "SHORTCUTSAPPINTENTS",
        tier: .tier2,
        description: "Shortcuts / App Intents automation lateral markers"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/shortcuts_app_intents.json",
            "Library/Logs/shortcuts_app_intents.jsonl",
            "Library/Shortcuts/shortcuts_inventory.json",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "shortcuts_app_intents.json"
                || name == "shortcuts_app_intents.jsonl"
                || name == "shortcuts_inventory.json"
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
            nestedKeys: ["items", "shortcuts", "entries", "automations"],
            identityKeys: ["shortcut_name", "path", "automation_path", "intent_path"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let path = stringish(item["path"])
            ?? stringish(item["automation_path"])
            ?? stringish(item["intent_path"])
            ?? stringish(item["shortcuts_path"])
            ?? ""
        let name = stringish(item["shortcut_name"])
            ?? stringish(item["name"])
            ?? ""
        guard !path.isEmpty || !name.isEmpty else { return nil }

        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        }
        if boolish(item["automation_surface"]) == true || !path.isEmpty {
            if !risk.contains("automation_surface") { risk.append("automation_surface") }
        }
        if boolish(item["runs_shell"]) == true || boolish(item["scripting"]) == true {
            if !risk.contains("scripting_action") { risk.append("scripting_action") }
        }
        if boolish(item["remote_adjacent"]) == true, !risk.contains("remote_adjacent") {
            risk.append("remote_adjacent")
        }

        let user = stringish(item["user"]) ?? inferUser(from: path) ?? inferUser(from: sourceURL.path) ?? ""
        var fields: [String: String] = [
            "shortcuts.path": path,
            "shortcuts.name": name,
            "shortcuts.notes": stringish(item["notes"])
                ?? "Shortcuts/App Intents path markers - never executes automations",
            FieldTaxonomy.eventType: "shortcuts.automation",
            FieldTaxonomy.userName: user,
        ]
        if !risk.isEmpty {
            fields["shortcuts.risk_tags"] = risk.joined(separator: ",")
        }

        return EventEnvelope(
            eventTime: parseDate(item["timestamp"] ?? item["seen_at"]) ?? Date(),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "SHORTCUTSAPPINTENTS",
            eventType: "shortcuts.automation",
            entityRefs: [
                EntityID(kind: .host, value: "shortcuts|\(name.isEmpty ? path : name)"),
            ],
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.88
        )
    }
}
