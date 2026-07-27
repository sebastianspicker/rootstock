import Foundation
import RootstockBlueCore

/// URL scheme / document-handler surface markers (Wave-11 red↔blue pair).
///
/// Inventories LaunchServices / CFBundleURLTypes / opener path markers for IR.
/// Honesty: never registers schemes or rewrites handlers.
public struct URLSchemeHandlerParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "URLSCHEMEHANDLER",
        tier: .tier2,
        description: "URL scheme / document-handler delivery surface (path markers)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/url_scheme_handler.json",
            "Library/Logs/url_scheme_handler.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "url_scheme_handler.json" || name == "url_scheme_handler.jsonl"
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
            nestedKeys: ["items", "handlers", "entries", "surfaces"],
            identityKeys: ["handler_path", "scheme", "path", "launch_services_path"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let path = stringish(item["handler_path"])
            ?? stringish(item["path"])
            ?? stringish(item["launch_services_path"])
            ?? stringish(item["opener_path"])
            ?? ""
        let scheme = stringish(item["scheme"])
            ?? stringish(item["url_scheme"])
            ?? ""
        let kind = (stringish(item["handler_kind"])
            ?? stringish(item["kind"])
            ?? "launch_services").lowercased()
        guard !path.isEmpty || !scheme.isEmpty else { return nil }

        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        }
        if boolish(item["handler_surface"]) == true || !path.isEmpty {
            if !risk.contains("handler_surface") { risk.append("handler_surface") }
        }
        if boolish(item["third_party_handler"]) == true, !risk.contains("third_party_handler") {
            risk.append("third_party_handler")
        }
        if !scheme.isEmpty, !risk.contains("custom_scheme") {
            risk.append("custom_scheme")
        }

        let user = stringish(item["user"]) ?? inferUser(from: path) ?? inferUser(from: sourceURL.path) ?? ""
        var fields: [String: String] = [
            "url_scheme.handler_path": path,
            "url_scheme.scheme": scheme,
            "url_scheme.handler_kind": kind,
            "url_scheme.notes": stringish(item["notes"]) ?? "URL scheme handler path presence only",
            FieldTaxonomy.eventType: "url_scheme.handler",
            FieldTaxonomy.userName: user,
        ]
        if !risk.isEmpty {
            fields["url_scheme.risk_tags"] = risk.joined(separator: ",")
        }

        return EventEnvelope(
            eventTime: parseDate(item["timestamp"] ?? item["seen_at"]) ?? Date(),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "URLSCHEMEHANDLER",
            eventType: "url_scheme.handler",
            entityRefs: [
                EntityID(kind: .host, value: "url_scheme|\(scheme.isEmpty ? path : scheme)"),
            ],
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.88
        )
    }
}
