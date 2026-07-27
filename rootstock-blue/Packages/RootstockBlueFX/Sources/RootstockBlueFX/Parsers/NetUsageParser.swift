import Foundation
import RootstockBlueCore

/// Network usage / egress inventory from fixture JSON exports of netusage.sqlite
/// or collector-side network usage dumps.
///
/// Surfaces process-level bytes in/out and destination domains for IR hunting
/// (anomalous egress, high-volume C2-like transfers, suspicious process names).
/// Offline-only - does not open live SQLite or perform live traffic capture.
public struct NetUsageParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "NETUSAGE",
        tier: .tier2,
        description: "Process network usage (bytes in/out, domains) from netusage exports"
    )

    /// Bytes-out above this threshold is treated as high_volume (fixture-scale).
    private static let highVolumeThreshold: Int64 = 50_000_000

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/netusage.json",
            "Library/Preferences/com.apple.networkusage.json",
            "private/var/networkd/netusage.sqlite.json",
            "var/networkd/netusage.sqlite.json",
        ] {
            if let url = root.firstExisting([rel]),
               let json = ArtifactIO.jsonObject(contentsOf: url),
               seen.insert(url) {
                events.append(contentsOf: parseJSONInventory(json, rawRef: ArtifactRoot.pathKey(url)))
            }
        }

        // Also discover by name under the tree (alternate collector layouts)
        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            if name == "netusage.json" || name == "com.apple.networkusage.json" { return true }
            if name == "netusage.sqlite.json" { return true }
            return false
        }) {
            guard seen.insert(url) else { continue }
            if let json = ArtifactIO.jsonObject(contentsOf: url) {
                events.append(contentsOf: parseJSONInventory(json, rawRef: ArtifactRoot.pathKey(url)))
            }
        }

        return events
    }

    private func parseJSONInventory(_ json: Any, rawRef: String) -> [EventEnvelope] {
        let items = ArtifactIO.dictionaryEntries(
            from: json,
            nestedKeys: ["usage", "entries", "processes", "items"],
            identityKeys: ["process", "bytes_out", "domain"]
        )
        return items.compactMap { makeEvent(from: $0, rawRef: rawRef) }
    }

    private func makeEvent(from item: [String: Any], rawRef: String) -> EventEnvelope? {
        let process = stringish(item["process"])
            ?? stringish(item["process_name"])
            ?? stringish(item["proc"])
            ?? stringish(item["name"])
            ?? stringish(item["bundle_id"])
            ?? ""
        let domain = stringish(item["domain"])
            ?? stringish(item["host"])
            ?? stringish(item["destination"])
            ?? stringish(item["remote_host"])
            ?? ""
        let bytesIn = int64ish(item["bytes_in"])
            ?? int64ish(item["rx_bytes"])
            ?? int64ish(item["received"])
            ?? 0
        let bytesOut = int64ish(item["bytes_out"])
            ?? int64ish(item["tx_bytes"])
            ?? int64ish(item["sent"])
            ?? 0

        guard !process.isEmpty || !domain.isEmpty || bytesOut > 0 || bytesIn > 0 else { return nil }

        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        }

        let lowerProc = process.lowercased()
        let lowerDomain = domain.lowercased()

        if lowerProc.contains("evil") || lowerProc.contains("/tmp/") || lowerProc.contains("curl") {
            if !risk.contains("suspicious_process") { risk.append("suspicious_process") }
        }
        if bytesOut >= Self.highVolumeThreshold {
            if !risk.contains("high_volume") { risk.append("high_volume") }
        }
        // C2-ish domains (fixture + common patterns)
        if lowerDomain.contains("evil.example")
            || lowerDomain.contains("c2.")
            || lowerDomain.hasSuffix(".evil")
            || (lowerDomain.contains("evil") && lowerDomain.contains(".")) {
            if !risk.contains("anomalous_egress") { risk.append("anomalous_egress") }
        }
        // High egress from suspicious process is also anomalous
        if risk.contains("suspicious_process") && bytesOut > 1_000_000 {
            if !risk.contains("anomalous_egress") { risk.append("anomalous_egress") }
        }

        var fields: [String: String] = [
            "net.usage.process": process,
            "net.usage.bytes_in": String(bytesIn),
            "net.usage.bytes_out": String(bytesOut),
            "net.usage.domain": domain,
            FieldTaxonomy.eventType: "network.usage",
        ]
        if !process.isEmpty {
            fields[FieldTaxonomy.processPath] = process
        }
        if !domain.isEmpty {
            fields["net.domain"] = domain
        }
        if !risk.isEmpty {
            fields["net.risk_tags"] = risk.joined(separator: ",")
            fields["net.usage.risk_tags"] = risk.joined(separator: ",")
        }
        if let firstSeen = stringish(item["first_seen"]) ?? stringish(item["timestamp"]) {
            fields["net.usage.first_seen"] = firstSeen
        }

        var entities: [EntityID] = [
            EntityID(kind: .network, value: "netusage|\(process)|\(domain)|\(bytesOut)"),
        ]
        if !process.isEmpty {
            entities.append(EntityID(kind: .process, value: "path=\(process)"))
        }
        if !domain.isEmpty {
            entities.append(EntityID(kind: .network, value: "domain=\(domain)"))
        }

        let eventTime = parseDate(item["timestamp"] ?? item["last_seen"] ?? item["first_seen"])
            ?? Date(timeIntervalSince1970: 0)

        return EventEnvelope(
            eventTime: eventTime,
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "NETUSAGE",
            eventType: "network.usage",
            entityRefs: entities,
            fields: fields,
            rawRef: rawRef,
            confidence: 0.88
        )
    }

    private func int64ish(_ value: Any?) -> Int64? {
        if let n = value as? NSNumber { return n.int64Value }
        if let i = value as? Int64 { return i }
        if let i = value as? Int { return Int64(i) }
        if let s = value as? String, let i = Int64(s) { return i }
        return nil
    }
}
