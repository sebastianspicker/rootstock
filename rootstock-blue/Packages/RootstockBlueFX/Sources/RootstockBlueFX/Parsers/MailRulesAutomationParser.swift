import Foundation
import RootstockBlueCore

/// Mail rules / Apple Mail automation persistence markers (Wave-12 red↔blue pair).
///
/// Honesty: never reads Mail contents or modifies user Mail rules.
public struct MailRulesAutomationParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "MAILRULESAUTO",
        tier: .tier2,
        description: "Mail rules automation surface markers"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/mail_rules_automation.json",
            "Library/Logs/mail_rules_automation.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "mail_rules_automation.json" || name == "mail_rules_automation.jsonl"
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
        if risk.isEmpty { risk.append("rules_surface") }
        if !risk.contains("rules_surface") { risk.append("rules_surface") }

        let user = stringish(item["user"]) ?? inferUser(from: path) ?? inferUser(from: sourceURL.path) ?? ""
        var fields: [String: String] = [
            "mail_rules.path": path,
            "mail_rules.name": name,
            "mail_rules.notes": stringish(item["notes"]) ?? "Mail rules automation markers - never reads Mail contents or modifies user Mail rules",
            "mail_rules.secrets_exported": "false",
            FieldTaxonomy.eventType: "mail.rules",
            FieldTaxonomy.userName: user,
        ]
        if let host = stringish(item["url_host"]) { fields["mail_rules.url_host"] = host }
        if let share = stringish(item["share_url"]) { fields["mail_rules.share_url"] = share }
        if let depth = stringish(item["depth"]) { fields["mail_rules.depth"] = depth }
        if boolish(item["runs_script"]) == true { fields["mail_rules.runs_script"] = "true" }
        if boolish(item["tool_present"]) == true { fields["mail_rules.tool_present"] = "true" }
        if !risk.isEmpty { fields["mail_rules.risk_tags"] = risk.joined(separator: ",") }

        return EventEnvelope(
            eventTime: parseDate(item["timestamp"] ?? item["seen_at"]) ?? Date(),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "MAILRULESAUTO",
            eventType: "mail.rules",
            entityRefs: [
                EntityID(kind: .host, value: "mail_rules|\(name.isEmpty ? path : name)"),
            ],
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.88
        )
    }
}
