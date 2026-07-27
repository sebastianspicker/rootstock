import Foundation
import RootstockBlueCore

/// iCloud account / sync **posture markers** - not full content sync dumps.
///
/// Surfaces account presence, Drive enablement, Desktop & Documents sync,
/// and service toggles for IR data-exfil / cloud-sync narrative.
public struct ICloudParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "ICLOUD",
        tier: .tier2,
        description: "iCloud account/sync posture markers (Drive, Desktop&Documents)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/icloud_account.json",
            "Library/Preferences/com.apple.bird.plist.json",
            "Library/Preferences/icloud_sync.json",
            "Library/Logs/icloud_export.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "icloud_account.json"
                || name == "icloud_sync.json"
                || name == "icloud_export.jsonl"
                || name == "com.apple.bird.plist.json"
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
        // Prefer single-account posture keys before nested accounts/items arrays.
        // Original order checked identity keys first, then accounts, then items.
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }
        if let dict = obj as? [String: Any] {
            if dict["account_present"] != nil
                || dict["drive_enabled"] != nil
                || dict["desktop_documents_sync"] != nil
                || dict["services"] != nil {
                if let e = makeAccountEvent(from: dict, sourceURL: url) {
                    return [e]
                }
            }
        }
        return ArtifactIO.dictionaryEntries(
            from: obj,
            nestedKeys: ["accounts", "items"],
            identityKeys: []
        ).compactMap { makeAccountEvent(from: $0, sourceURL: url) }
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url)
            .compactMap { makeAccountEvent(from: $0, sourceURL: url) }
    }

    private func makeAccountEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let accountPresent = boolish(item["account_present"]) ?? true
        let driveEnabled = boolish(item["drive_enabled"])
            ?? serviceEnabled(item, name: "iCloudDrive")
            ?? false
        let desktopDocs = boolish(item["desktop_documents_sync"])
            ?? serviceEnabled(item, name: "DesktopDocuments")
            ?? false
        let photos = boolish(item["photos_enabled"])
            ?? serviceEnabled(item, name: "Photos")
            ?? false
        let keychainSync = boolish(item["keychain_sync"])
            ?? serviceEnabled(item, name: "Keychain")
            ?? false
        let findMy = boolish(item["find_my"])
            ?? serviceEnabled(item, name: "FindMy")
            ?? false
        let user = stringish(item["signed_in_user"])
            ?? stringish(item["user"])
            ?? ""
        let domain = stringish(item["apple_id_domain"])
            ?? stringish(item["account_domain"])
            ?? ""

        // At least one posture signal
        guard accountPresent
            || driveEnabled
            || desktopDocs
            || item["services"] != nil
            || !user.isEmpty
        else { return nil }

        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        }
        if desktopDocs {
            if !risk.contains("desktop_documents_sync") { risk.append("desktop_documents_sync") }
        }
        if driveEnabled {
            if !risk.contains("drive_enabled") { risk.append("drive_enabled") }
        }

        var fields: [String: String] = [
            "icloud.account_present": accountPresent ? "true" : "false",
            "icloud.drive_enabled": driveEnabled ? "true" : "false",
            "icloud.desktop_documents_sync": desktopDocs ? "true" : "false",
            "icloud.photos_enabled": photos ? "true" : "false",
            "icloud.keychain_sync": keychainSync ? "true" : "false",
            "icloud.find_my": findMy ? "true" : "false",
            "icloud.signed_in_user": user,
            "icloud.apple_id_domain": domain,
            FieldTaxonomy.eventType: "cloud.sync_posture",
        ]
        // Never export full Apple ID email as secret-bearing identity if present
        if let email = stringish(item["apple_id"]), !email.isEmpty {
            // Store domain-only marker, not full address, when possible
            if email.contains("@") {
                let parts = email.split(separator: "@")
                if parts.count == 2 {
                    fields["icloud.apple_id_domain"] = String(parts[1])
                    fields["icloud.apple_id_present"] = "true"
                } else {
                    fields["icloud.apple_id_present"] = "true"
                }
            } else {
                fields["icloud.apple_id_present"] = "true"
            }
        }
        if !risk.isEmpty {
            fields["icloud.risk_tags"] = risk.joined(separator: ",")
        }
        if !user.isEmpty {
            fields[FieldTaxonomy.userName] = user
        }

        return EventEnvelope(
            eventTime: Date(),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "ICLOUD",
            eventType: "cloud.sync_posture",
            entityRefs: [
                EntityID(kind: .host, value: "icloud|\(user.isEmpty ? "account" : user)"),
            ],
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.9
        )
    }

    private func serviceEnabled(_ item: [String: Any], name: String) -> Bool? {
        guard let services = item["services"] as? [[String: Any]] else { return nil }
        for svc in services {
            let n = (stringish(svc["name"]) ?? "").lowercased()
            if n == name.lowercased() || n.contains(name.lowercased()) {
                return boolish(svc["enabled"]) ?? true
            }
        }
        return nil
    }
}
