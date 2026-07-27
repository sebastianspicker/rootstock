import Foundation
import RootstockBlueCore

/// Microsoft Remote Desktop (MSRDC) and related RDP client connection history.
///
/// Surfaces host, user, client app, and last-connected markers for lateral
/// movement / remote-access IR - not credential material from RDP sessions.
public struct MSRDCParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "MSRDC",
        tier: .tier2,
        description: "Remote desktop client connection history (MSRDC/RDP)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/msrdc_connections.json",
            "Library/Preferences/rdp_connections.json",
            "Library/Preferences/com.microsoft.rdc.macos.json",
            "Library/Logs/msrdc_connections.jsonl",
            "Library/Containers/com.microsoft.rdc.macos/Data/Library/Preferences/connections.json",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "msrdc_connections.json"
                || name == "rdp_connections.json"
                || name == "msrdc_connections.jsonl"
                || name == "com.microsoft.rdc.macos.json"
                || (name == "connections.json" && url.path.lowercased().contains("rdc"))
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
            nestedKeys: ["connections", "items", "hosts"],
            identityKeys: ["host", "hostname", "pc_name"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url)
            .compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let host = stringish(item["host"])
            ?? stringish(item["hostname"])
            ?? stringish(item["pc_name"])
            ?? stringish(item["server"])
            ?? ""
        let rdpUser = stringish(item["user"])
            ?? stringish(item["username"])
            ?? stringish(item["friendly_name"])
            ?? ""
        let client = stringish(item["client"])
            ?? stringish(item["app"])
            ?? "msrdc"
        let lastConnected = stringish(item["last_connected"])
            ?? stringish(item["timestamp"])
            ?? stringish(item["last_used"])
            ?? ""
        let port = stringish(item["port"]) ?? "3389"

        guard !host.isEmpty else { return nil }

        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        }
        // Any remote connection residue is operationally relevant
        if !risk.contains("remote_connection") { risk.append("remote_connection") }
        let lowerHost = host.lowercased()
        if lowerHost.contains("evil") || lowerHost.contains("c2")
            || lowerHost.contains("malware") || lowerHost.hasSuffix(".evil") {
            if !risk.contains("suspicious_host") { risk.append("suspicious_host") }
        }
        if lowerHost.hasPrefix("10.") || lowerHost.hasPrefix("192.168.")
            || lowerHost.hasPrefix("172.") {
            if !risk.contains("internal_host") { risk.append("internal_host") }
        } else if lowerHost.contains(".") && !lowerHost.hasSuffix(".local") {
            if !risk.contains("external_host") { risk.append("external_host") }
        }

        let localUser = stringish(item["local_user"]) ?? inferUser(from: sourceURL.path) ?? ""

        var fields: [String: String] = [
            "rdp.host": host,
            "rdp.user": rdpUser,
            "rdp.client": client,
            "rdp.port": port,
            "rdp.last_connected": lastConnected,
            FieldTaxonomy.eventType: "remote.rdp_connection",
            FieldTaxonomy.userName: localUser,
        ]
        if let gateway = stringish(item["gateway"]) {
            fields["rdp.gateway"] = gateway
        }
        if !risk.isEmpty {
            fields["rdp.risk_tags"] = risk.joined(separator: ",")
        }

        return EventEnvelope(
            eventTime: parseDate(item["last_connected"] ?? item["timestamp"] ?? item["last_used"])
                ?? Date(timeIntervalSince1970: 0),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "MSRDC",
            eventType: "remote.rdp_connection",
            entityRefs: [
                EntityID(kind: .network, value: "rdp|\(host)"),
            ],
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.9
        )
    }
}
