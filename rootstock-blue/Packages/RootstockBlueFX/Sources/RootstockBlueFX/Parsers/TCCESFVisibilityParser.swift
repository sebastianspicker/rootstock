import Foundation
import RootstockBlueCore

/// TCC / ESF **visibility depth** markers (Wave-8 residual red↔blue pair).
///
/// Labels operator visibility as strong / partial / thin from offline markers.
/// Never dumps TCC.db rows or live-subscribes Endpoint Security.
public struct TCCESFVisibilityParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "TCCESFVISIBILITY",
        tier: .tier2,
        description: "TCC/ESF visibility depth (strong|partial|thin)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/tcc_esf_visibility.json",
            "Library/Logs/tcc_esf_visibility.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "tcc_esf_visibility.json" || name == "tcc_esf_visibility.jsonl"
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
            nestedKeys: ["items", "entries", "visibility"],
            identityKeys: ["depth", "visibility_depth", "tcc_path_listable", "tool_present"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        var depth = (stringish(item["depth"])
            ?? stringish(item["visibility_depth"])
            ?? "").lowercased()
        let tccListable = boolish(item["tcc_path_listable"])
            ?? boolish(item["tcc_listable"])
            ?? boolish(item["tcc_readable"])
            ?? false
        let toolPresent = boolish(item["tool_present"])
            ?? stringish(item["tool_path"]).map { !$0.isEmpty }
            ?? false
        let toolPath = stringish(item["tool_path"])
            ?? stringish(item["visibility_tool"])
            ?? ""
        let user = stringish(item["user"]) ?? inferUser(from: sourceURL.path) ?? ""

        if depth.isEmpty {
            // Heuristic when depth omitted
            if tccListable && toolPresent {
                depth = "strong"
            } else if tccListable || toolPresent {
                depth = "partial"
            } else {
                depth = "thin"
            }
        }
        let allowed = ["strong", "partial", "thin"]
        if !allowed.contains(depth) {
            depth = "thin"
        }

        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        }
        if depth == "thin" {
            if !risk.contains("thin_visibility") { risk.append("thin_visibility") }
            if !risk.contains("sensor_gap_adjacent") { risk.append("sensor_gap_adjacent") }
        } else if depth == "partial" {
            if !risk.contains("partial_visibility") { risk.append("partial_visibility") }
        }

        var fields: [String: String] = [
            "visibility.depth": depth,
            "visibility.tcc_path_listable": tccListable ? "true" : "false",
            "visibility.tool_present": toolPresent ? "true" : "false",
            "visibility.tool_path": toolPath,
            FieldTaxonomy.eventType: "tcc_esf.visibility",
            FieldTaxonomy.userName: user,
        ]
        if !risk.isEmpty {
            fields["visibility.risk_tags"] = risk.joined(separator: ",")
        }

        return EventEnvelope(
            eventTime: parseDate(item["timestamp"] ?? item["assessed_at"]) ?? Date(),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "TCCESFVISIBILITY",
            eventType: "tcc_esf.visibility",
            entityRefs: [
                EntityID(kind: .host, value: "visibility|\(depth)|\(toolPresent)"),
            ],
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.9
        )
    }
}
