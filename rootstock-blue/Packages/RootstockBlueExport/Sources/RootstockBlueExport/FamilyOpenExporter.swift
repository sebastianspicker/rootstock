import Foundation
import RootstockBlueCase
import RootstockBlueCore

/// Optional DD-011 family open-export (schema v1) for Neo4j import from a case.
public enum FamilyOpenExporter: Sendable {
    public static let schemaVersion = 1
    public static let source = "rootstock-blue"

    public static let nodeTypes = ["Finding", "Host", "LaunchItem", "Protection"]
    public static let edgeVocabulary = ["HAS_FINDING", "HAS_LAUNCH_ITEM", "HAS_PROTECTION"]

    /// Build export from case timeline events (subset: host + protections + persistence + findings).
    public static func build(
        events: [EventEnvelope],
        caseName: String = "case",
        scopeName: String = "rootstock-blue-case",
        scanProfile: String = "offline-dfir",
        generatedAt: Date = Date()
    ) -> [String: Any] {
        let hostName = events
            .first(where: { $0.eventType == "ir.posture.host" })?
            .fields["host.hostname"]
            ?? caseName
        let hostId = "Host:\(sanitize(hostName))"
        var nodes: [[String: Any]] = [
            [
                "id": hostId,
                "type": "Host",
                "name": hostName,
                "hostname": hostName,
                "case_name": caseName,
            ],
        ]
        var edges: [[String: String]] = []
        var seen = Set<String>()

        for event in events {
            if event.eventType == "ir.posture.protection" {
                let name = event.fields["protection.name"] ?? "Protection"
                let id = "Protection:\(sanitize(name.lowercased()))"
                if seen.insert(id).inserted {
                    nodes.append(
                        [
                            "id": id,
                            "type": "Protection",
                            "name": name,
                            "enabled": event.fields["protection.enabled"] ?? "unknown",
                        ]
                    )
                    edges.append(["from": hostId, "to": id, "type": "HAS_PROTECTION"])
                }
            } else if event.eventType == "persistence.item"
                || event.sourcePlugin == "AUTOSTART"
            {
                let label = event.fields["persistence.label"]
                    ?? event.fields[FieldTaxonomy.persistenceLabel]
                    ?? event.rawRef
                    ?? UUID().uuidString
                let id = "LaunchItem:\(sanitize(label))"
                if seen.insert(id).inserted {
                    nodes.append(
                        [
                            "id": id,
                            "type": "LaunchItem",
                            "name": label,
                            "label": label,
                            "path": event.fields["persistence.path"]
                                ?? event.fields[FieldTaxonomy.persistencePath]
                                ?? "",
                            "program": event.fields["persistence.program"]
                                ?? event.fields[FieldTaxonomy.processPath]
                                ?? "",
                        ]
                    )
                    edges.append(["from": hostId, "to": id, "type": "HAS_LAUNCH_ITEM"])
                }
            } else if event.eventType == "finding.import"
                || event.eventType.hasPrefix("harden.")
                || event.fields["finding.id"] != nil
            {
                let fid = event.fields["finding.id"] ?? event.eventType
                let id = "Finding:\(sanitize(fid))"
                if seen.insert(id).inserted {
                    nodes.append(
                        [
                            "id": id,
                            "type": "Finding",
                            "name": event.fields["finding.title"] ?? fid,
                            "finding_id": fid,
                            "severity": event.fields["finding.severity"] ?? "info",
                            "category": event.fields["finding.category"] ?? "other",
                        ]
                    )
                    edges.append(["from": hostId, "to": id, "type": "HAS_FINDING"])
                }
            }
        }

        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return [
            "schema_version": schemaVersion,
            "source": source,
            "generated_at": formatter.string(from: generatedAt),
            "scope_name": scopeName,
            "scan_profile": scanProfile,
            "node_types": nodeTypes,
            "edge_types": Array(Set(edges.map { $0["type"]! })).sorted(),
            "edge_vocabulary": edgeVocabulary,
            "nodes": nodes,
            "edges": edges,
        ]
    }

    public static func writeJSON(
        events: [EventEnvelope],
        to url: URL,
        caseName: String = "case",
        scopeName: String = "rootstock-blue-case"
    ) throws {
        let dict = build(events: events, caseName: caseName, scopeName: scopeName)
        let data = try JSONSerialization.data(
            withJSONObject: dict,
            options: [.prettyPrinted, .sortedKeys]
        )
        try data.write(to: url, options: .atomic)
    }

    private static func sanitize(_ value: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "._-"))
        let scalars = value.unicodeScalars.map { allowed.contains($0) ? Character($0) : "_" }
        return String(scalars)
    }
}
