/// Offline forensic parser: QuarantineParser - fixture-backed IR events (no secret export).
import Foundation
import RootstockBlueCore

public struct QuarantineParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "QUARANTINE",
        tier: .tier1,
        description: "Parse LaunchServices QuarantineEvents database"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var dbs: [URL] = []

        for url in root.enumerate(matching: {
            $0.lastPathComponent == "com.apple.LaunchServices.QuarantineEventsV2"
                || $0.lastPathComponent.hasPrefix("com.apple.LaunchServices.QuarantineEvents")
        }) {
            ArtifactRoot.appendUnique(&dbs, url)
        }

        if let system = root.firstExisting([
            "Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2",
        ]) {
            ArtifactRoot.appendUnique(&dbs, system)
        }

        var events: [EventEnvelope] = []
        for db in dbs {
            events.append(contentsOf: try parseDB(db))
        }
        return events
    }

    private func parseDB(_ url: URL) throws -> [EventEnvelope] {
        let reader = try SQLiteReader(url: url)
        let table: String
        if try reader.tableExists("LSQuarantineEvent") {
            table = "LSQuarantineEvent"
        } else if try reader.tableExists("LSQuarantineEvents") {
            table = "LSQuarantineEvents"
        } else {
            return []
        }

        let rows = try reader.query(
            """
            SELECT
              COALESCE(LSQuarantineEventIdentifier, '') AS id,
              COALESCE(CAST(LSQuarantineTimeStamp AS TEXT), '') AS ts,
              COALESCE(LSQuarantineAgentBundleIdentifier, '') AS agent,
              COALESCE(LSQuarantineAgentName, '') AS agent_name,
              COALESCE(LSQuarantineDataURLString, '') AS data_url,
              COALESCE(LSQuarantineOriginURLString, '') AS origin_url,
              COALESCE(LSQuarantineSenderName, '') AS sender
            FROM \(table);
            """
        )

        return rows.map { row in
            let ts = Epochs.dateFromMacAbsolute(row["ts"] ?? "")
            let dataURL = row["data_url"] ?? ""
            let origin = row["origin_url"] ?? ""
            var entities: [EntityID] = []
            if !dataURL.isEmpty {
                entities.append(.file(path: dataURL))
            }
            return EventEnvelope(
                eventTime: ts,
                collectedAt: Date(),
                source: .parser,
                sourcePlugin: "QUARANTINE",
                eventType: "quarantine.event",
                entityRefs: entities,
                fields: [
                    "quarantine.id": row["id"] ?? "",
                    "quarantine.agent": row["agent"] ?? "",
                    "quarantine.agent_name": row["agent_name"] ?? "",
                    "quarantine.data_url": dataURL,
                    "quarantine.origin_url": origin,
                    "quarantine.sender": row["sender"] ?? "",
                    FieldTaxonomy.filePath: dataURL,
                    FieldTaxonomy.eventType: "quarantine.event",
                ],
                rawRef: ArtifactRoot.pathKey(url),
                confidence: 0.95
            )
        }
    }
}
