import Foundation
import RootstockBlueCore

/// Dock persistent apps / recent items dual-use markers (Wave-12 red↔blue pair).
///
/// Honesty: never modifies Dock.plist or plants malicious Dock entries.
public struct DockPersistenceSurfaceParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "DOCKPERSIST",
        tier: .tier2,
        description: "Dock persistence dual-use surface markers"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/dock_persistence_surface.json",
            "Library/Logs/dock_persistence_surface.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "dock_persistence_surface.json" || name == "dock_persistence_surface.jsonl"
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
        if risk.isEmpty { risk.append("dock_surface") }
        if !risk.contains("dock_surface") { risk.append("dock_surface") }

        let user = stringish(item["user"]) ?? inferUser(from: path) ?? inferUser(from: sourceURL.path) ?? ""
        var fields: [String: String] = [
            "dock.path": path,
            "dock.name": name,
            "dock.notes": stringish(item["notes"]) ?? "Dock persistence dual-use markers - never modifies Dock.plist or plants malicious Dock entries",
            "dock.secrets_exported": "false",
            FieldTaxonomy.eventType: "dock.persistence",
            FieldTaxonomy.userName: user,
        ]
        if let host = stringish(item["url_host"]) { fields["dock.url_host"] = host }
        if let share = stringish(item["share_url"]) { fields["dock.share_url"] = share }
        if let depth = stringish(item["depth"]) { fields["dock.depth"] = depth }
        if boolish(item["runs_script"]) == true { fields["dock.runs_script"] = "true" }
        if boolish(item["tool_present"]) == true { fields["dock.tool_present"] = "true" }
        if !risk.isEmpty { fields["dock.risk_tags"] = risk.joined(separator: ",") }

        return EventEnvelope(
            eventTime: parseDate(item["timestamp"] ?? item["seen_at"]) ?? Date(),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "DOCKPERSIST",
            eventType: "dock.persistence",
            entityRefs: [
                EntityID(kind: .host, value: "dock|\(name.isEmpty ? path : name)"),
            ],
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.88
        )
    }
}
