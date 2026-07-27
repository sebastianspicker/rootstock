import Foundation
import RootstockBlueCore

/// Network locations / services from SystemConfiguration preferences or
/// fixture `network_locations.json`.
public struct NetworkLocationParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "NETLOCATION",
        tier: .tier2,
        description: "Network locations and interface/service configuration"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var urls: [URL] = []
        var seen = PathDeduper()

        for found in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            if name == "network_locations.json" { return true }
            if name == "preferences.plist" && url.path.contains("SystemConfiguration") {
                return true
            }
            return false
        }) {
            if !seen.insert(found) { continue }
            ArtifactRoot.appendUnique(&urls, found)
        }

        for rel in [
            "Library/Preferences/SystemConfiguration/network_locations.json",
            "Library/Preferences/SystemConfiguration/preferences.plist",
            "Library/Preferences/network_locations.json",
        ] {
            if let u = root.firstExisting([rel]) {
                if seen.insert(u) {
                    ArtifactRoot.appendUnique(&urls, u)
                }
            }
        }

        var events: [EventEnvelope] = []
        for url in urls {
            if url.pathExtension == "json" {
                events.append(contentsOf: parseJSON(at: url))
            } else {
                events.append(contentsOf: parsePreferencesPlist(at: url))
            }
        }
        return events
    }

    // MARK: - JSON fixture

    private func parseJSON(at url: URL) -> [EventEnvelope] {
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }

        let entries: [[String: Any]]
        if let arr = obj as? [[String: Any]] {
            entries = arr
        } else if let dict = obj as? [String: Any] {
            if let arr = dict["locations"] as? [[String: Any]] {
                entries = arr
            } else if let arr = dict["services"] as? [[String: Any]] {
                entries = arr
            } else if let arr = dict["items"] as? [[String: Any]] {
                entries = arr
            } else {
                return []
            }
        } else {
            return []
        }

        return entries.compactMap { item in
            makeEvent(
                service: stringValue(item["service"])
                    ?? stringValue(item["name"])
                    ?? stringValue(item["UserDefinedName"])
                    ?? "",
                interface: stringValue(item["interface"])
                    ?? interfaceFromNested(item)
                    ?? "",
                ipv4: stringValue(item["ipv4"])
                    ?? stringValue(item["IPv4"])
                    ?? ipv4FromNested(item)
                    ?? "",
                location: stringValue(item["location"]) ?? stringValue(item["Location"]) ?? "",
                sourceURL: url,
                extra: item
            )
        }
    }

    // MARK: - SystemConfiguration preferences.plist

    private func parsePreferencesPlist(at url: URL) -> [EventEnvelope] {
        guard let rootDict = ArtifactIO.plistDict(contentsOf: url) else { return [] }

        var events: [EventEnvelope] = []

        // NetworkServices dict: UUID -> service
        if let services = rootDict["NetworkServices"] as? [String: Any] {
            for (uuid, value) in services {
                guard let svc = value as? [String: Any] else { continue }
                let name = stringValue(svc["UserDefinedName"]) ?? uuid
                let iface = interfaceFromNested(svc) ?? ""
                let ipv4 = ipv4FromNested(svc) ?? ""
                if let event = makeEvent(
                    service: name,
                    interface: iface,
                    ipv4: ipv4,
                    location: "",
                    sourceURL: url,
                    extra: svc
                ) {
                    events.append(event)
                }
            }
        }

        // Sets / current location names
        if let sets = rootDict["Sets"] as? [String: Any] {
            for (_, value) in sets {
                guard let setDict = value as? [String: Any] else { continue }
                let locName = stringValue(setDict["UserDefinedName"]) ?? ""
                if !locName.isEmpty, events.isEmpty {
                    // Emit location-only if no services were found
                    if let event = makeEvent(
                        service: locName,
                        interface: "",
                        ipv4: "",
                        location: locName,
                        sourceURL: url,
                        extra: setDict
                    ) {
                        events.append(event)
                    }
                } else if !locName.isEmpty {
                    // Tag existing events? Prefer emit location summary
                    _ = locName
                }
            }
        }

        // CurrentSet path only - skip if we already have services
        return events
    }

    // MARK: - event

    private func makeEvent(
        service: String,
        interface: String,
        ipv4: String,
        location: String,
        sourceURL: URL,
        extra: [String: Any]
    ) -> EventEnvelope? {
        guard !service.isEmpty || !interface.isEmpty || !ipv4.isEmpty else { return nil }

        var fields: [String: String] = [
            "net.service": service,
            "net.interface": interface,
            FieldTaxonomy.eventType: "net.location",
            FieldTaxonomy.filePath: ArtifactRoot.pathKey(sourceURL),
        ]
        if !ipv4.isEmpty {
            fields["net.ipv4"] = ipv4
        }
        if !location.isEmpty {
            fields["net.location_name"] = location
        }
        if let mac = stringValue(extra["mac"]) ?? stringValue(extra["MAC"]) {
            fields["net.mac"] = mac
        }

        var entities: [EntityID] = [
            EntityID(kind: .network, value: "service=\(service.isEmpty ? interface : service)"),
        ]
        if !ipv4.isEmpty {
            entities.append(EntityID(kind: .network, value: "ipv4=\(ipv4)"))
        }

        return EventEnvelope(
            eventTime: fileMTime(sourceURL),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "NETLOCATION",
            eventType: "net.location",
            entityRefs: entities,
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.9
        )
    }

    private func interfaceFromNested(_ item: [String: Any]) -> String? {
        if let iface = item["Interface"] as? [String: Any] {
            return stringValue(iface["DeviceName"])
                ?? stringValue(iface["Hardware"])
                ?? stringValue(iface["Type"])
        }
        if let s = stringValue(item["DeviceName"]) { return s }
        if let s = stringValue(item["BSD Name"]) { return s }
        return nil
    }

    private func ipv4FromNested(_ item: [String: Any]) -> String? {
        if let ip = item["IPv4"] as? [String: Any] {
            if let addrs = ip["Addresses"] as? [String], let first = addrs.first {
                return first
            }
            if let addr = stringValue(ip["Address"]) { return addr }
            if let addr = stringValue(ip["Router"]) { return addr }
        }
        if let s = stringValue(item["Addresses"]) { return s }
        return nil
    }

    private func fileMTime(_ url: URL) -> Date {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs?[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)
    }
}
