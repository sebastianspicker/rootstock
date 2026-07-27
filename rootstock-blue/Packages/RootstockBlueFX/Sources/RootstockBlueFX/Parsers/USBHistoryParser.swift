import Foundation
import RootstockBlueCore

/// USB device connection history from fixture JSON / JSONL exports.
///
/// Surfaces vendor/product IDs, serials, product names, and connection times
/// for removable-media and HID-injection IR hunting.
/// Offline-only - does not query live IOKit.
public struct USBHistoryParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "USBHISTORY",
        tier: .tier2,
        description: "USB device connection history (VID/PID/serial/product)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/usb_history.json",
            "Library/Logs/usb_devices.jsonl",
            "Library/Preferences/com.apple.iokit.usb.json",
        ] {
            if let url = root.firstExisting([rel]), seen.insert(url) {
                events.append(contentsOf: parseFile(at: url))
            }
        }

        // Per-user USB preference exports
        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            let path = url.path
            if name == "usb_history.json" { return true }
            if name == "usb_devices.jsonl" || name == "usb_devices.json" { return true }
            if name == "com.apple.iokit.usb.json" { return true }
            if path.contains("iokit") && name.hasSuffix(".json") && path.lowercased().contains("usb") {
                return true
            }
            return false
        }) {
            guard seen.insert(url) else { continue }
            events.append(contentsOf: parseFile(at: url))
        }

        return events
    }

    private func parseFile(at url: URL) -> [EventEnvelope] {
        if url.pathExtension == "jsonl" || url.lastPathComponent.hasSuffix(".jsonl") {
            return ArtifactIO.jsonlDictionaries(contentsOf: url).compactMap { makeEvent(from: $0, sourceURL: url) }
        }
        return parseJSON(at: url)
    }

    private func parseJSON(at url: URL) -> [EventEnvelope] {
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }

        let entries = ArtifactIO.dictionaryEntries(
            from: obj,
            nestedKeys: ["devices", "history", "items", "usb"],
            identityKeys: ["vendor_id", "product_id", "serial"]
        )
        return entries.compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let vendorID = stringish(item["vendor_id"])
            ?? stringish(item["vid"])
            ?? stringish(item["idVendor"])
            ?? ""
        let productID = stringish(item["product_id"])
            ?? stringish(item["pid"])
            ?? stringish(item["idProduct"])
            ?? ""
        let serial = stringish(item["serial"])
            ?? stringish(item["serial_number"])
            ?? stringish(item["USBSerialNumber"])
            ?? ""
        let productName = stringish(item["product_name"])
            ?? stringish(item["product"])
            ?? stringish(item["name"])
            ?? stringish(item["USBProductName"])
            ?? ""
        let connectedAt = stringish(item["connected_at"])
            ?? stringish(item["timestamp"])
            ?? stringish(item["time"])
            ?? stringish(item["first_seen"])
            ?? ""

        guard !vendorID.isEmpty || !productID.isEmpty || !serial.isEmpty || !productName.isEmpty else {
            return nil
        }

        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        }

        let lowerName = productName.lowercased()
        let vendorLower = vendorID.lowercased()
        let classHint = (stringish(item["device_class"])
            ?? stringish(item["class"])
            ?? stringish(item["usb_class"])
            ?? "").lowercased()

        // Mass storage class (08) or name hints
        if classHint.contains("mass") || classHint == "08" || classHint.contains("storage")
            || lowerName.contains("mass storage") || lowerName.contains("usb drive")
            || lowerName.contains("flash") || boolish(item["mass_storage"]) == true {
            if !risk.contains("mass_storage") { risk.append("mass_storage") }
        }
        // HID injection (BadUSB-class)
        if classHint.contains("hid") || lowerName.contains("hid inject")
            || lowerName.contains("rubber ducky") || lowerName.contains("badusb")
            || boolish(item["hid_inject"]) == true
            || lowerName.contains("inject") {
            if !risk.contains("hid_inject") { risk.append("hid_inject") }
        }
        // Unknown / suspicious vendor
        if lowerName.contains("evil") || vendorLower.contains("evil")
            || vendorLower == "ffff" || vendorLower == "0000"
            || boolish(item["unknown_vendor"]) == true {
            if !risk.contains("unknown_vendor") { risk.append("unknown_vendor") }
        }

        var fields: [String: String] = [
            "usb.vendor_id": vendorID,
            "usb.product_id": productID,
            "usb.serial": serial,
            "usb.product_name": productName,
            "usb.connected_at": connectedAt,
            FieldTaxonomy.eventType: "device.usb",
        ]
        if !risk.isEmpty {
            fields["usb.risk_tags"] = risk.joined(separator: ",")
        }
        if let manufacturer = stringish(item["manufacturer"]) ?? stringish(item["vendor_name"]) {
            fields["usb.manufacturer"] = manufacturer
        }

        let entities: [EntityID] = [
            EntityID(kind: .host, value: "usb|\(vendorID)|\(productID)|\(serial)"),
        ]

        let eventTime = parseDate(item["connected_at"] ?? item["timestamp"] ?? item["time"])
            ?? Date(timeIntervalSince1970: 0)

        return EventEnvelope(
            eventTime: eventTime,
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "USBHISTORY",
            eventType: "device.usb",
            entityRefs: entities,
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.9
        )
    }
}
