import Foundation
import RootstockBlueCore

/// Preferred / known Wi-Fi networks from SystemConfiguration and known-networks plists.
public struct WifiParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "WIFI",
        tier: .tier2,
        description: "Preferred Wi-Fi networks (airport.preferences / known-networks)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var urls: [URL] = []

        if let primary = root.firstExisting([
            "Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist",
            "Library/Preferences/com.apple.wifi.known-networks.plist",
            "Library/Preferences/wifi_known_networks.json",
            "private/var/preferences/SystemConfiguration/com.apple.airport.preferences.plist",
        ]) {
            ArtifactRoot.appendUnique(&urls, primary)
        }

        // Pick up additional known-network style artifacts anywhere in the tree.
        for found in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "com.apple.airport.preferences.plist"
                || name == "com.apple.wifi.known-networks.plist"
                || name == "wifi_known_networks.json"
        }) {
            ArtifactRoot.appendUnique(&urls, found)
        }

        var events: [EventEnvelope] = []
        var seen = PathDeduper()
        for url in urls {
            if !seen.insert(url) { continue }
            if url.pathExtension == "json" {
                events.append(contentsOf: parseJSON(at: url))
            } else {
                events.append(contentsOf: parsePlist(at: url))
            }
        }
        return events
    }

    private func parseJSON(at url: URL) -> [EventEnvelope] {
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }

        let entries: [[String: Any]]
        if let arr = obj as? [[String: Any]] {
            entries = arr
        } else if let dict = obj as? [String: Any],
                  let arr = dict["networks"] as? [[String: Any]] {
            entries = arr
        } else if let arr = obj as? [Any] {
            entries = arr.compactMap { $0 as? [String: Any] }
        } else {
            return []
        }

        return entries.compactMap { entry in
            let ssid = stringValue(entry["ssid"]) ?? stringValue(entry["SSID"]) ?? ""
            guard !ssid.isEmpty else { return nil }
            let security = stringValue(entry["security"])
                ?? stringValue(entry["SecurityType"])
                ?? stringValue(entry["security_type"])
                ?? ""
            let lastConnected = stringValue(entry["last_connected"])
                ?? stringValue(entry["LastConnected"])
                ?? ""
            let hidden = boolString(entry["hidden"] ?? entry["Hidden"])
            return makeEvent(
                ssid: ssid,
                security: security,
                lastConnected: lastConnected,
                hidden: hidden,
                sourceURL: url
            )
        }
    }

    private func parsePlist(at url: URL) -> [EventEnvelope] {
        guard let data = ArtifactIO.data(contentsOf: url) else { return [] }
        var events: [EventEnvelope] = []

        // Structure A: KnownNetworks dict of SSID -> network dict
        if let dict = ArtifactIO.plistDict(from: data) {
            if let known = dict["KnownNetworks"] as? [String: Any] {
                for (key, value) in known {
                    let net = value as? [String: Any] ?? [:]
                    let ssid = stringValue(net["SSIDString"])
                        ?? stringValue(net["SSID"])
                        ?? stringValue(net["ssid"])
                        ?? key
                    guard !ssid.isEmpty else { continue }
                    let security = stringValue(net["SecurityType"])
                        ?? stringValue(net["security"])
                        ?? stringValue(net["SecurityTypeString"])
                        ?? ""
                    let lastConnected = dateString(net["LastConnected"] ?? net["last_connected"])
                    let hidden = boolString(net["Hidden"] ?? net["hidden"])
                    events.append(makeEvent(
                        ssid: ssid,
                        security: security,
                        lastConnected: lastConnected,
                        hidden: hidden,
                        sourceURL: url
                    ))
                }
            }

            // Structure B: top-level SSID keys that map to network dicts (simplified fixtures).
            if events.isEmpty {
                for (key, value) in dict {
                    guard let net = value as? [String: Any] else { continue }
                    // Heuristic: looks like a network entry if it has SecurityType / LastConnected / SSID.
                    let hasNetKeys = net["SecurityType"] != nil
                        || net["LastConnected"] != nil
                        || net["SSIDString"] != nil
                        || net["Hidden"] != nil
                        || net["security"] != nil
                    guard hasNetKeys else { continue }
                    let ssid = stringValue(net["SSIDString"])
                        ?? stringValue(net["SSID"])
                        ?? stringValue(net["ssid"])
                        ?? key
                    guard !ssid.isEmpty else { continue }
                    events.append(makeEvent(
                        ssid: ssid,
                        security: stringValue(net["SecurityType"]) ?? stringValue(net["security"]) ?? "",
                        lastConnected: dateString(net["LastConnected"] ?? net["last_connected"]),
                        hidden: boolString(net["Hidden"] ?? net["hidden"]),
                        sourceURL: url
                    ))
                }
            }

            // Structure C: array of SSIDs under PreferredOrder or similar.
            if events.isEmpty, let order = dict["PreferredOrder"] as? [String] {
                for ssid in order where !ssid.isEmpty {
                    events.append(makeEvent(
                        ssid: ssid,
                        security: "",
                        lastConnected: "",
                        hidden: "false",
                        sourceURL: url
                    ))
                }
            }
        }

        // Structure D: top-level array of network dicts.
        if events.isEmpty, let arr = ArtifactIO.plistArray(from: data) {
            for net in arr {
                let ssid = stringValue(net["SSIDString"])
                    ?? stringValue(net["SSID"])
                    ?? stringValue(net["ssid"])
                    ?? ""
                guard !ssid.isEmpty else { continue }
                events.append(makeEvent(
                    ssid: ssid,
                    security: stringValue(net["SecurityType"]) ?? stringValue(net["security"]) ?? "",
                    lastConnected: dateString(net["LastConnected"] ?? net["last_connected"]),
                    hidden: boolString(net["Hidden"] ?? net["hidden"]),
                    sourceURL: url
                ))
            }
        }

        return events
    }

    private func makeEvent(
        ssid: String,
        security: String,
        lastConnected: String,
        hidden: String,
        sourceURL: URL
    ) -> EventEnvelope {
        let attrs = try? FileManager.default.attributesOfItem(atPath: sourceURL.path)
        let mtime = (attrs?[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)
        let eventTime = ISO8601DateFormatter().date(from: lastConnected) ?? mtime

        return EventEnvelope(
            eventTime: eventTime,
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "WIFI",
            eventType: "network.wifi_preferred",
            entityRefs: [
                EntityID(kind: .network, value: "ssid=\(ssid)"),
            ],
            fields: [
                "wifi.ssid": ssid,
                "wifi.security": security,
                "wifi.last_connected": lastConnected,
                "wifi.hidden": hidden,
                "network.ssid": ssid,
                "wifi.source_path": ArtifactRoot.pathKey(sourceURL),
                FieldTaxonomy.eventType: "network.wifi_preferred",
            ],
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.93
        )
    }

    /// Wi‑Fi plists often store SSID as `Data` (UTF-8 bytes).
    private func stringValue(_ any: Any?) -> String? {
        if let d = any as? Data, let s = String(data: d, encoding: .utf8) { return s }
        return stringish(any)
    }

    private func dateString(_ any: Any?) -> String {
        if let d = parseDate(any) {
            return ISO8601DateFormatter().string(from: d)
        }
        if let s = any as? String { return s }
        return ""
    }

    private func boolString(_ any: Any?) -> String {
        if let b = boolish(any) { return b ? "true" : "false" }
        return "false"
    }
}
