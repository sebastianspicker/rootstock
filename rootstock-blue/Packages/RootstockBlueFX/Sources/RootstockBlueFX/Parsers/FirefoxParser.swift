import Foundation
import RootstockBlueCore

/// Firefox browser history and downloads - parity with Safari/Chromium case events.
///
/// Prefers fixture-friendly `firefox_history.json` exports; also reads places.sqlite
/// when present (moz_places / moz_historyvisits / moz_annos download markers).
public struct FirefoxParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "FIREFOX",
        tier: .tier2,
        description: "Firefox places history visits and downloads"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        // JSON inventory exports (primary for fixtures / UAC-style dumps)
        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "firefox_history.json"
                || name == "firefox_export.json"
                || name == "places_export.json"
        }) {
            if seen.insert(url) {
                events.append(contentsOf: parseJSONExport(at: url))
            }
        }

        // places.sqlite when present
        for url in root.enumerate(matching: { url in
            url.lastPathComponent == "places.sqlite"
                && (url.path.contains("Firefox") || url.path.contains("firefox"))
        }) {
            if seen.insert(url) {
                if let rows = try? parsePlacesSQLite(url) {
                    events.append(contentsOf: rows)
                }
            }
        }

        return events
    }

    private func parseJSONExport(at url: URL) -> [EventEnvelope] {
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }

        var events: [EventEnvelope] = []
        let user = inferUser(from: url.path)

        if let dict = obj as? [String: Any] {
            if let visits = dict["visits"] as? [[String: Any]] {
                for v in visits {
                    if let e = makeVisit(from: v, sourceURL: url, user: user) {
                        events.append(e)
                    }
                }
            }
            if let downloads = dict["downloads"] as? [[String: Any]] {
                for d in downloads {
                    if let e = makeDownload(from: d, sourceURL: url, user: user) {
                        events.append(e)
                    }
                }
            }
            // Flat list
            if let items = dict["items"] as? [[String: Any]] {
                for item in items {
                    if item["path"] != nil || item["target_path"] != nil {
                        if let e = makeDownload(from: item, sourceURL: url, user: user) {
                            events.append(e)
                        }
                    } else if let e = makeVisit(from: item, sourceURL: url, user: user) {
                        events.append(e)
                    }
                }
            }
        } else if let arr = obj as? [[String: Any]] {
            for item in arr {
                if item["path"] != nil || item["target_path"] != nil {
                    if let e = makeDownload(from: item, sourceURL: url, user: user) {
                        events.append(e)
                    }
                } else if let e = makeVisit(from: item, sourceURL: url, user: user) {
                    events.append(e)
                }
            }
        }
        return events
    }

    private func parsePlacesSQLite(_ url: URL) throws -> [EventEnvelope] {
        let reader = try SQLiteReader(url: url)
        var events: [EventEnvelope] = []
        let user = inferUser(from: url.path)

        if try reader.tableExists("moz_places"), try reader.tableExists("moz_historyvisits") {
            let rows = try reader.query(
                """
                SELECT
                  COALESCE(p.url, '') AS url,
                  COALESCE(p.title, '') AS title,
                  COALESCE(CAST(p.visit_count AS TEXT), '') AS visit_count,
                  COALESCE(CAST(v.visit_date AS TEXT), '') AS visit_date
                FROM moz_historyvisits v
                LEFT JOIN moz_places p ON v.place_id = p.id
                LIMIT 5000;
                """
            )
            for row in rows {
                let when = Epochs.dateFromFirefoxMicroseconds(row["visit_date"] ?? "")
                    ?? Date(timeIntervalSince1970: 0)
                let urlString = row["url"] ?? ""
                events.append(
                    EventEnvelope(
                        eventTime: when,
                        collectedAt: Date(),
                        source: .parser,
                        sourcePlugin: "FIREFOX",
                        eventType: "browser.visit",
                        entityRefs: urlString.isEmpty ? [] : [EntityID(kind: .file, value: urlString)],
                        fields: [
                            "browser.engine": "firefox",
                            "browser.url": urlString,
                            "browser.title": row["title"] ?? "",
                            "browser.visit_count": row["visit_count"] ?? "",
                            FieldTaxonomy.eventType: "browser.visit",
                            FieldTaxonomy.userName: user ?? "",
                        ],
                        rawRef: ArtifactRoot.pathKey(url),
                        confidence: 0.95
                    )
                )
            }
        }

        // Download annotations when present
        if try reader.tableExists("moz_annos"), try reader.tableExists("moz_places") {
            let drows = try reader.query(
                """
                SELECT
                  COALESCE(p.url, '') AS url,
                  COALESCE(a.content, '') AS content,
                  COALESCE(CAST(a.dateAdded AS TEXT), '') AS date_added
                FROM moz_annos a
                LEFT JOIN moz_places p ON a.place_id = p.id
                WHERE a.content LIKE 'file://%' OR a.content LIKE '/%'
                LIMIT 2000;
                """
            )
            for row in drows {
                let path = (row["content"] ?? "").replacingOccurrences(of: "file://", with: "")
                let when = Epochs.dateFromFirefoxMicroseconds(row["date_added"] ?? "")
                    ?? Date(timeIntervalSince1970: 0)
                var refs: [EntityID] = []
                if !path.isEmpty { refs.append(.file(path: path)) }
                events.append(
                    EventEnvelope(
                        eventTime: when,
                        collectedAt: Date(),
                        source: .parser,
                        sourcePlugin: "FIREFOX",
                        eventType: "browser.download",
                        entityRefs: refs,
                        fields: [
                            "browser.engine": "firefox",
                            "browser.url": row["url"] ?? "",
                            "browser.download_path": path,
                            FieldTaxonomy.eventType: "browser.download",
                            FieldTaxonomy.userName: user ?? "",
                        ],
                        rawRef: ArtifactRoot.pathKey(url),
                        confidence: 0.9
                    )
                )
            }
        }

        return events
    }

    private func makeVisit(from item: [String: Any], sourceURL: URL, user: String?) -> EventEnvelope? {
        let urlString = stringish(item["url"]) ?? stringish(item["uri"]) ?? ""
        let title = stringish(item["title"]) ?? ""
        guard !urlString.isEmpty || !title.isEmpty else { return nil }

        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        }
        let lower = urlString.lowercased()
        if lower.contains("evil") || lower.contains("c2.") || lower.contains("malware") {
            if !risk.contains("evil_domain") { risk.append("evil_domain") }
        }

        var fields: [String: String] = [
            "browser.engine": "firefox",
            "browser.url": urlString,
            "browser.title": title,
            "browser.visit_count": stringish(item["visit_count"]) ?? "",
            FieldTaxonomy.eventType: "browser.visit",
            FieldTaxonomy.userName: user ?? "",
        ]
        if !risk.isEmpty {
            fields["browser.risk_tags"] = risk.joined(separator: ",")
        }

        return EventEnvelope(
            eventTime: parseDate(item["visit_time"] ?? item["timestamp"] ?? item["time"])
                ?? Date(timeIntervalSince1970: 0),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "FIREFOX",
            eventType: "browser.visit",
            entityRefs: urlString.isEmpty ? [] : [EntityID(kind: .file, value: urlString)],
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.92
        )
    }

    private func makeDownload(from item: [String: Any], sourceURL: URL, user: String?) -> EventEnvelope? {
        let path = stringish(item["path"])
            ?? stringish(item["target_path"])
            ?? stringish(item["download_path"])
            ?? ""
        let urlString = stringish(item["url"])
            ?? stringish(item["source_url"])
            ?? stringish(item["referrer"])
            ?? ""
        guard !path.isEmpty || !urlString.isEmpty else { return nil }

        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        }
        let lowerURL = urlString.lowercased()
        let lowerPath = path.lowercased()
        if lowerURL.contains("evil") || lowerPath.contains("evil") || lowerPath.contains("payload") {
            if !risk.contains("evil_domain") { risk.append("evil_domain") }
        }
        if lowerPath.hasSuffix(".sh") || lowerPath.hasSuffix(".py") || lowerPath.hasSuffix(".command")
            || (stringish(item["mime_type"]) ?? "").contains("x-sh") {
            if !risk.contains("script_download") { risk.append("script_download") }
        }
        if lowerPath.contains("/tmp/") {
            if !risk.contains("tmp_path") { risk.append("tmp_path") }
        }

        var fields: [String: String] = [
            "browser.engine": "firefox",
            "browser.url": urlString,
            "browser.download_path": path,
            "browser.mime_type": stringish(item["mime_type"]) ?? "",
            FieldTaxonomy.eventType: "browser.download",
            FieldTaxonomy.userName: user ?? "",
        ]
        if !risk.isEmpty {
            fields["browser.risk_tags"] = risk.joined(separator: ",")
        }

        var refs: [EntityID] = []
        if !path.isEmpty { refs.append(.file(path: path)) }
        if !urlString.isEmpty { refs.append(EntityID(kind: .file, value: urlString)) }

        return EventEnvelope(
            eventTime: parseDate(item["start_time"] ?? item["timestamp"] ?? item["time"])
                ?? Date(timeIntervalSince1970: 0),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "FIREFOX",
            eventType: "browser.download",
            entityRefs: refs,
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.92
        )
    }
}
