import Foundation
import RootstockBlueCore

/// DocumentRevisions / Versions.framework markers from inventory JSON and store paths.
///
/// Surfaces prior document versions for recovery and sensitive-document IR context
/// without dumping full document bodies into the case by default.
public struct DocRevisionsParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "DOCREVISIONS",
        tier: .tier2,
        description: "DocumentRevisions / Versions inventory (path / version markers)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/doc_revisions.json",
            "Library/Preferences/document_revisions.json",
            "Library/Logs/doc_revisions.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "doc_revisions.json"
                || name == "document_revisions.json"
                || name == "doc_revisions.jsonl"
                || name == "revisions_export.json"
        }) {
            if seen.insert(url) {
                events.append(contentsOf: parseFile(at: url))
            }
        }

        // Marker files under .DocumentRevisions-V100 or DocumentRevisions
        for url in root.enumerate(matching: { url in
            let path = url.path
            return (path.contains("DocumentRevisions") || path.contains(".DocumentRevisions"))
                && (url.lastPathComponent == "db-info.txt"
                    || url.lastPathComponent.hasSuffix(".json")
                    || url.lastPathComponent.hasSuffix(".marker"))
        }) {
            let key = "docrev-marker:" + ArtifactRoot.pathKey(url)
            if seen.insert(pathKey: key) {
                events.append(
                    EventEnvelope(
                        eventTime: Date(timeIntervalSince1970: 0),
                        collectedAt: Date(),
                        source: .parser,
                        sourcePlugin: "DOCREVISIONS",
                        eventType: "filesystem.doc_revision",
                        entityRefs: [.file(path: ArtifactRoot.pathKey(url))],
                        fields: [
                            "docrev.store_path": ArtifactRoot.pathKey(url),
                            "docrev.marker": "true",
                            FieldTaxonomy.eventType: "filesystem.doc_revision",
                        ],
                        rawRef: ArtifactRoot.pathKey(url),
                        confidence: 0.7
                    )
                )
            }
        }

        return events
    }

    private func parseFile(at url: URL) -> [EventEnvelope] {
        if url.pathExtension == "jsonl" {
            return parseJSONL(at: url)
        }
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else {
            // Non-JSON export markers still get a presence event when path matches
            if url.path.contains("DocumentRevisions") || url.path.contains("doc_revision") {
                return [
                    EventEnvelope(
                        eventTime: Date(timeIntervalSince1970: 0),
                        collectedAt: Date(),
                        source: .parser,
                        sourcePlugin: "DOCREVISIONS",
                        eventType: "filesystem.doc_revision",
                        entityRefs: [.file(path: ArtifactRoot.pathKey(url))],
                        fields: [
                            "docrev.store_path": ArtifactRoot.pathKey(url),
                            "docrev.marker": "true",
                            FieldTaxonomy.eventType: "filesystem.doc_revision",
                        ],
                        rawRef: ArtifactRoot.pathKey(url),
                        confidence: 0.65
                    ),
                ]
            }
            return []
        }
        return ArtifactIO.dictionaryEntries(
            from: obj,
            nestedKeys: ["revisions", "items", "versions"],
            identityKeys: ["path"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url)
            .compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let path = stringish(item["path"])
            ?? stringish(item["document_path"])
            ?? stringish(item["file"])
            ?? ""
        let version = stringish(item["version"])
            ?? stringish(item["generation"])
            ?? stringish(item["rev"])
            ?? ""
        guard !path.isEmpty || !version.isEmpty else { return nil }

        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        }
        let lower = path.lowercased()
        if lower.contains("confidential") || lower.contains("secret")
            || lower.contains("password") || lower.contains("credential")
            || lower.contains("ssn") || lower.contains("payroll") {
            if !risk.contains("sensitive_document") { risk.append("sensitive_document") }
        }

        var fields: [String: String] = [
            "docrev.path": path,
            "docrev.version": version,
            FieldTaxonomy.eventType: "filesystem.doc_revision",
        ]
        if let mtime = stringish(item["mtime"]) ?? stringish(item["modified"]) {
            fields["docrev.mtime"] = mtime
        }
        if let gen = stringish(item["gen_store_id"]) ?? stringish(item["store_id"]) {
            fields["docrev.gen_store_id"] = gen
        }
        if !risk.isEmpty {
            fields["docrev.risk_tags"] = risk.joined(separator: ",")
        }

        return EventEnvelope(
            eventTime: parseDate(item["mtime"] ?? item["modified"]) ?? Date(timeIntervalSince1970: 0),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "DOCREVISIONS",
            eventType: "filesystem.doc_revision",
            entityRefs: path.isEmpty ? [] : [.file(path: path)],
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.87
        )
    }
}
