import Foundation
import RootstockBlueCase
import RootstockBlueCore
import RootstockMacFacts

/// Import a core Rootstock collector `scan.json` into a blue case as timeline events.
///
/// Family bridge (DD-011): optional, fail-closed on missing required meta.
/// Provenance: `sourcePlugin` values use `collector.*` prefix.
public enum ScanJSONImporter: Sendable {
    public struct Summary: Sendable, Equatable {
        public var tccEvents: Int
        public var launchItemEvents: Int
        public var metaNotes: Int

        public var totalEvents: Int { tccEvents + launchItemEvents + metaNotes }
    }

    /// Parse collector scan JSON data into `EventEnvelope`s (does not write the case).
    public static func events(from data: Data) throws -> (events: [EventEnvelope], summary: Summary) {
        let obj = try JSONSerialization.jsonObject(with: data)
        guard let root = obj as? [String: Any] else {
            throw RootstockBlueError.io("scan.json root must be an object")
        }
        guard let scanId = root["scan_id"] as? String, !scanId.isEmpty else {
            throw RootstockBlueError.io("scan.json missing scan_id")
        }
        let hostname = root["hostname"] as? String ?? ""
        let timestamp = root["timestamp"] as? String
        let collectedAt = parseISO8601(timestamp) ?? Date()

        var events: [EventEnvelope] = []
        var tccCount = 0
        var launchCount = 0

        // Host meta envelope
        events.append(
            EventEnvelope(
                eventTime: collectedAt,
                collectedAt: Date(),
                source: .parser,
                sourcePlugin: "collector.meta",
                eventType: "collector.scan_meta",
                entityRefs: [
                    EntityID(kind: .host, value: hostname.isEmpty ? scanId : hostname),
                ],
                fields: [
                    "collector.scan_id": scanId,
                    "collector.hostname": hostname,
                    "collector.macos_version": root["macos_version"] as? String ?? "",
                    "collector.version": root["collector_version"] as? String ?? "",
                    "family.source": "collector",
                    FieldTaxonomy.eventType: "collector.scan_meta",
                ],
                rawRef: "scan_id:\(scanId)",
                confidence: 1.0
            )
        )

        if let grants = root["tcc_grants"] as? [[String: Any]] {
            for grant in grants {
                let service = grant["service"] as? String ?? ""
                let client = grant["client"] as? String ?? ""
                let scope = grant["scope"] as? String ?? ""
                let authValue = grant["auth_value"].map { "\($0)" } ?? ""
                events.append(
                    EventEnvelope(
                        eventTime: collectedAt,
                        collectedAt: Date(),
                        source: .parser,
                        sourcePlugin: "collector.tcc",
                        eventType: "tcc.grant",
                        entityRefs: [
                            EntityID(kind: .tcc, value: "\(service)|\(client)"),
                        ],
                        fields: [
                            FieldTaxonomy.tccService: service,
                            "tcc.service_display": TCCServiceCatalog.displayName(for: service),
                            FieldTaxonomy.tccIdentity: client,
                            "tcc.scope": scope,
                            "tcc.auth_value": authValue,
                            "collector.scan_id": scanId,
                            "family.source": "collector",
                            FieldTaxonomy.eventType: "tcc.grant",
                        ],
                        rawRef: "scan_id:\(scanId)",
                        confidence: 0.9
                    )
                )
                tccCount += 1
            }
        }

        if let items = root["launch_items"] as? [[String: Any]] {
            for item in items {
                let label = item["label"] as? String ?? ""
                let path = item["path"] as? String ?? ""
                let program = item["program"] as? String ?? ""
                let type = item["type"] as? String ?? ""
                events.append(
                    EventEnvelope(
                        eventTime: collectedAt,
                        collectedAt: Date(),
                        source: .parser,
                        sourcePlugin: "collector.persistence",
                        eventType: "persistence.launch_item",
                        entityRefs: [
                            EntityID(kind: .process, value: label.isEmpty ? path : label),
                        ],
                        fields: [
                            "persist.label": label,
                            "persist.path": path,
                            "persist.program": program,
                            "persist.type": type,
                            "collector.scan_id": scanId,
                            "family.source": "collector",
                            FieldTaxonomy.eventType: "persistence.launch_item",
                        ],
                        rawRef: path.isEmpty ? "scan_id:\(scanId)" : path,
                        confidence: 0.9
                    )
                )
                launchCount += 1
            }
        }

        let summary = Summary(
            tccEvents: tccCount,
            launchItemEvents: launchCount,
            metaNotes: 1
        )
        return (events, summary)
    }

    /// Load scan.json from disk and append events into the case package.
    @discardableResult
    public static func importIntoCase(scanURL: URL, casePackage: CasePackage) throws -> Summary {
        let data = try Data(contentsOf: scanURL)
        let (events, summary) = try events(from: data)
        for event in events {
            try casePackage.appendEventJSONL(event, stream: "es")
            try casePackage.insertTimelineEvent(event)
        }
        try casePackage.appendCustody(
            CustodyEvent(
                actor: "rootstock-blue",
                action: "import.scan_json",
                detail: "Imported \(summary.totalEvents) events from \(scanURL.lastPathComponent)"
            )
        )
        try casePackage.updateHashes()
        return summary
    }

    private static func parseISO8601(_ value: String?) -> Date? {
        guard let value, !value.isEmpty else { return nil }
        let frac = ISO8601DateFormatter()
        frac.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = frac.date(from: value) { return d }
        let plain = ISO8601DateFormatter()
        plain.formatOptions = [.withInternetDateTime]
        return plain.date(from: value)
    }
}
