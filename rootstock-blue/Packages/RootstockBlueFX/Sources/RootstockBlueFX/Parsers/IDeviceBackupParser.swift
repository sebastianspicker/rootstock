import Foundation
import RootstockBlueCore

/// iTunes / Finder iDevice backup markers - device inventory + encryption posture.
///
/// Surfaces backup presence, last backup time, encrypted flag, and device name
/// markers for dual-device evidence IR. Does not dump backup payload contents.
public struct IDeviceBackupParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "IDEVICEBACKUP",
        tier: .tier2,
        description: "iDevice backup markers (device/encrypt posture, not payload dump)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/idevice_backups.json",
            "Library/Preferences/mobile_sync_backups.json",
            "Library/Application Support/MobileSync/backup_inventory.json",
            "Library/Logs/idevice_backups.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "idevice_backups.json"
                || name == "mobile_sync_backups.json"
                || name == "backup_inventory.json"
                || name == "idevice_backups.jsonl"
                || name == "Info.plist.json"
        }) {
            // Info.plist.json only under MobileSync/Backup trees
            if url.lastPathComponent == "Info.plist.json"
                && !url.path.contains("MobileSync")
                && !url.path.contains("Backup") {
                continue
            }
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
            nestedKeys: ["backups", "items", "devices"],
            identityKeys: ["device_name", "DeviceName", "encrypted", "IsEncrypted"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url)
            .compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let deviceName = stringish(item["device_name"])
            ?? stringish(item["DeviceName"])
            ?? stringish(item["name"])
            ?? ""
        let encrypted = boolish(item["encrypted"])
            ?? boolish(item["IsEncrypted"])
            ?? boolish(item["is_encrypted"])
        let lastBackup = stringish(item["last_backup"])
            ?? stringish(item["LastBackupDate"])
            ?? stringish(item["timestamp"])
            ?? ""
        let product = stringish(item["product_type"])
            ?? stringish(item["ProductType"])
            ?? stringish(item["product"])
            ?? ""
        let iosVersion = stringish(item["ios_version"])
            ?? stringish(item["ProductVersion"])
            ?? ""
        // UDID marker only - truncate full UDID if present
        var udidMarker = stringish(item["udid_marker"])
            ?? stringish(item["UniqueDeviceID"])
            ?? stringish(item["udid"])
            ?? ""
        if udidMarker.count > 12 {
            udidMarker = String(udidMarker.prefix(8)) + "…"
        }
        let path = stringish(item["backup_path"])
            ?? stringish(item["path"])
            ?? ""

        guard !deviceName.isEmpty || encrypted != nil || !lastBackup.isEmpty else { return nil }

        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        }
        if encrypted == false {
            if !risk.contains("unencrypted_backup") { risk.append("unencrypted_backup") }
        }
        if encrypted == true {
            if !risk.contains("encrypted_backup") { risk.append("encrypted_backup") }
        }
        if deviceName.lowercased().contains("evil") {
            if !risk.contains("suspicious_device") { risk.append("suspicious_device") }
        }

        let user = stringish(item["user"]) ?? inferUser(from: sourceURL.path) ?? ""

        var fields: [String: String] = [
            "backup.device_name": deviceName,
            "backup.last_backup": lastBackup,
            "backup.product_type": product,
            "backup.ios_version": iosVersion,
            "backup.udid_marker": udidMarker,
            "backup.path": path,
            FieldTaxonomy.eventType: "backup.idevice",
            FieldTaxonomy.userName: user,
        ]
        if let enc = encrypted {
            fields["backup.encrypted"] = enc ? "true" : "false"
        }
        if !risk.isEmpty {
            fields["backup.risk_tags"] = risk.joined(separator: ",")
        }

        return EventEnvelope(
            eventTime: parseDate(item["last_backup"] ?? item["LastBackupDate"] ?? item["timestamp"])
                ?? Date(timeIntervalSince1970: 0),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "IDEVICEBACKUP",
            eventType: "backup.idevice",
            entityRefs: [
                EntityID(kind: .host, value: "idevice|\(deviceName.isEmpty ? udidMarker : deviceName)"),
            ],
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.9
        )
    }
}
