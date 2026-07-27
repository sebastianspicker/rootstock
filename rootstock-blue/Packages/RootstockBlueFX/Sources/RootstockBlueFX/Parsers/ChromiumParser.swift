import Foundation
import RootstockBlueCore

/// Chromium History (urls/visits/downloads) → entity-linked timeline events.
public struct ChromiumParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "CHROMIUM",
        tier: .tier2,
        description: "Chrome/Edge/Chromium history visits and downloads"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        // Chromium profiles store a file named "History" (no extension)
        let histories = root.enumerate(matching: { url in
            url.lastPathComponent == "History"
                && (url.path.contains("Chrome")
                    || url.path.contains("Chromium")
                    || url.path.contains("Edge")
                    || url.path.contains("Brave")
                    || url.path.contains("Google"))
        })
        for db in histories {
            events.append(contentsOf: try parseHistory(db))
        }
        return events
    }

    private func parseHistory(_ url: URL) throws -> [EventEnvelope] {
        let reader = try SQLiteReader(url: url)
        var events: [EventEnvelope] = []
        let engine = browserEngine(from: url.path)

        if try reader.tableExists("visits"), try reader.tableExists("urls") {
            let rows = try reader.query(
                """
                SELECT
                  CAST(v.id AS TEXT) AS visit_id,
                  CAST(v.visit_time AS TEXT) AS visit_time,
                  COALESCE(u.url, '') AS url,
                  COALESCE(u.title, '') AS title,
                  COALESCE(CAST(u.visit_count AS TEXT), '') AS visit_count
                FROM visits v
                LEFT JOIN urls u ON v.url = u.id;
                """
            )
            for row in rows {
                let urlString = row["url"] ?? ""
                let when = Epochs.dateFromChromeMicroseconds(row["visit_time"] ?? "")
                events.append(
                    EventEnvelope(
                        eventTime: when,
                        collectedAt: Date(),
                        source: .parser,
                        sourcePlugin: "CHROMIUM",
                        eventType: "browser.visit",
                        entityRefs: urlString.isEmpty ? [] : [EntityID(kind: .file, value: urlString)],
                        fields: [
                            "browser.engine": engine,
                            "browser.url": urlString,
                            "browser.title": row["title"] ?? "",
                            "browser.visit_count": row["visit_count"] ?? "",
                            "browser.visit_id": row["visit_id"] ?? "",
                            FieldTaxonomy.eventType: "browser.visit",
                            FieldTaxonomy.userName: inferUser(from: url) ?? "",
                        ],
                        rawRef: ArtifactRoot.pathKey(url),
                        confidence: 0.95
                    )
                )
            }
        }

        if try reader.tableExists("downloads") {
            let drows = try reader.query(
                """
                SELECT
                  CAST(id AS TEXT) AS id,
                  COALESCE(target_path, current_path, '') AS path,
                  COALESCE(tab_url, site_url, referrer, '') AS source_url,
                  COALESCE(CAST(start_time AS TEXT), '') AS start_time,
                  COALESCE(mime_type, '') AS mime_type,
                  COALESCE(CAST(received_bytes AS TEXT), '') AS received_bytes
                FROM downloads;
                """
            )
            for row in drows {
                let path = row["path"] ?? ""
                let sourceURL = row["source_url"] ?? ""
                let when = Epochs.dateFromChromeMicroseconds(row["start_time"] ?? "")
                var refs: [EntityID] = []
                if !path.isEmpty { refs.append(.file(path: path)) }
                if !sourceURL.isEmpty { refs.append(EntityID(kind: .file, value: sourceURL)) }
                events.append(
                    EventEnvelope(
                        eventTime: when,
                        collectedAt: Date(),
                        source: .parser,
                        sourcePlugin: "CHROMIUM",
                        eventType: "browser.download",
                        entityRefs: refs,
                        fields: [
                            "browser.engine": engine,
                            "browser.download_path": path,
                            "browser.download_url": sourceURL,
                            "browser.mime_type": row["mime_type"] ?? "",
                            "browser.received_bytes": row["received_bytes"] ?? "",
                            FieldTaxonomy.filePath: path,
                            FieldTaxonomy.eventType: "browser.download",
                            FieldTaxonomy.userName: inferUser(from: url) ?? "",
                        ],
                        rawRef: ArtifactRoot.pathKey(url),
                        confidence: 0.92
                    )
                )
            }
        }

        return events
    }

    private func browserEngine(from path: String) -> String {
        if path.contains("Edge") { return "edge" }
        if path.contains("Brave") { return "brave" }
        if path.contains("Chromium") { return "chromium" }
        return "chrome"
    }

}
