import Foundation
import RootstockBlueCore

/// Apple Notes **metadata markers** - titles/folders/mtime only.
///
/// Does not export full note body content (privacy non-goal, same class as
/// NOTIFICATIONS body export refusal).
public struct NotesParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "NOTES",
        tier: .tier2,
        description: "Apple Notes metadata markers (no full body dumps)"
    )

    private static let forbiddenBodyKeys: Set<String> = [
        "body", "content", "text", "note_body", "html", "attributed_body",
        "snippet_full", "plaintext", "full_text",
    ]

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/notes_metadata.json",
            "Library/Preferences/notes_export.json",
            "Library/Logs/notes_metadata.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "notes_metadata.json"
                || name == "notes_export.json"
                || name == "notes_metadata.jsonl"
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
            nestedKeys: ["notes", "items"],
            identityKeys: ["title", "title_marker"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url)
            .compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        // Never copy body keys
        for key in item.keys {
            if Self.forbiddenBodyKeys.contains(key.lowercased()) {
                continue
            }
        }

        let titleMarker = stringish(item["title_marker"])
            ?? stringish(item["title"])
            ?? stringish(item["name"])
            ?? ""
        let folder = stringish(item["folder"])
            ?? stringish(item["account"])
            ?? ""
        let cappedTitle = String(titleMarker.prefix(120))

        guard !cappedTitle.isEmpty || !folder.isEmpty else { return nil }

        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        }
        let lower = cappedTitle.lowercased()
        if lower.contains("password") || lower.contains("credential")
            || lower.contains("secret") || lower.contains("api key")
            || lower.contains("private key") || lower.contains("ssn")
            || lower.contains("wifi password") {
            if !risk.contains("sensitive_title") { risk.append("sensitive_title") }
        }
        if lower.contains("evil") || lower.contains("c2") || lower.contains("implant") {
            if !risk.contains("suspicious_title") { risk.append("suspicious_title") }
        }

        let user = stringish(item["user"]) ?? inferUser(from: sourceURL.path) ?? ""
        let bodyExported = boolish(item["body_exported"]) == true

        var fields: [String: String] = [
            "notes.title_marker": cappedTitle,
            "notes.folder": folder,
            "notes.body_exported": bodyExported ? "true" : "false",
            FieldTaxonomy.eventType: "notes.metadata",
            FieldTaxonomy.userName: user,
        ]
        if let modified = stringish(item["modified_at"]) ?? stringish(item["timestamp"]) {
            fields["notes.modified_at"] = modified
        }
        if let created = stringish(item["created_at"]) {
            fields["notes.created_at"] = created
        }
        if let noteID = stringish(item["note_id"]) ?? stringish(item["id"]) {
            fields["notes.note_id_marker"] = String(noteID.prefix(40))
        }
        if !risk.isEmpty {
            fields["notes.risk_tags"] = risk.joined(separator: ",")
        }

        fields.removeValue(forKey: "notes.body")
        fields.removeValue(forKey: "body")
        fields.removeValue(forKey: "content")

        return EventEnvelope(
            eventTime: parseDate(item["modified_at"] ?? item["timestamp"] ?? item["created_at"])
                ?? Date(timeIntervalSince1970: 0),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "NOTES",
            eventType: "notes.metadata",
            entityRefs: [
                EntityID(kind: .host, value: "notes|\(cappedTitle.prefix(40))"),
            ],
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.88
        )
    }
}
