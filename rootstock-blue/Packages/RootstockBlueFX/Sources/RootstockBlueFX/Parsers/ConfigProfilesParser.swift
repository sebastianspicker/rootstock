import Foundation
import RootstockBlueCore

/// MDM / configuration profiles - forensic JSON exports, managed preferences, payload plists.
public struct ConfigProfilesParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "CONFIGPROFILES",
        tier: .tier2,
        description: "MDM and configuration profile payloads"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        // Forensic export JSON.
        if let jsonURL = root.firstExisting([
            "Library/ConfigurationProfiles/profiles.json",
            "var/db/ConfigurationProfiles/profiles.json",
            "private/var/db/ConfigurationProfiles/profiles.json",
        ]) {
            if seen.insert(jsonURL) {
                events.append(contentsOf: parseProfilesJSON(at: jsonURL))
            }
        }

        // Payload plists under ConfigurationProfiles/payloads/
        for url in root.enumerate(matching: { url in
            url.pathExtension == "plist"
                && (url.path.contains("ConfigurationProfiles")
                    || url.path.contains("/payloads/")
                    || url.path.contains("Managed Preferences")
                    || url.path.contains("ManagedPreferences"))
        }) {
            if !seen.insert(url) { continue }
            if let e = parsePayloadPlist(at: url) {
                events.append(e)
            }
        }

        // Settings directory under var/db/ConfigurationProfiles/Settings/
        for dirRel in [
            "var/db/ConfigurationProfiles/Settings",
            "private/var/db/ConfigurationProfiles/Settings",
            "Library/ConfigurationProfiles/Settings",
        ] {
            let dir = root.file(dirRel)
            guard let items = try? FileManager.default.contentsOfDirectory(
                at: dir,
                includingPropertiesForKeys: nil
            ) else { continue }
            for item in items where item.pathExtension == "plist" || item.pathExtension == "json" {
                if !seen.insert(item) { continue }
                if item.pathExtension == "json" {
                    events.append(contentsOf: parseProfilesJSON(at: item))
                } else if let e = parsePayloadPlist(at: item) {
                    events.append(e)
                }
            }
        }

        // Managed Preferences directory (enumerate plists already covered above;
        // also catch non-payload preference names as host config).
        for dirRel in [
            "Library/Managed Preferences",
            "private/var/db/Managed Preferences",
        ] {
            let dir = root.file(dirRel)
            guard let items = try? FileManager.default.contentsOfDirectory(
                at: dir,
                includingPropertiesForKeys: nil
            ) else { continue }
            for item in items where item.pathExtension == "plist" {
                if !seen.insert(item) { continue }
                if let e = parsePayloadPlist(at: item) {
                    events.append(e)
                } else if let e = parseManagedPreference(at: item) {
                    events.append(e)
                }
            }
        }

        return events
    }

    private func parseProfilesJSON(at url: URL) -> [EventEnvelope] {
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }

        let entries: [[String: Any]]
        if let arr = obj as? [[String: Any]] {
            entries = arr
        } else if let dict = obj as? [String: Any] {
            if let arr = dict["profiles"] as? [[String: Any]] {
                entries = arr
            } else if let arr = dict["PayloadContent"] as? [[String: Any]] {
                entries = arr
            } else {
                entries = [dict]
            }
        } else if let arr = obj as? [Any] {
            entries = arr.compactMap { $0 as? [String: Any] }
        } else {
            return []
        }

        return entries.compactMap { entry in
            makeEvent(
                displayName: stringValue(entry["PayloadDisplayName"])
                    ?? stringValue(entry["display_name"])
                    ?? stringValue(entry["name"])
                    ?? "",
                identifier: stringValue(entry["PayloadIdentifier"])
                    ?? stringValue(entry["identifier"])
                    ?? "",
                type: stringValue(entry["PayloadType"])
                    ?? stringValue(entry["type"])
                    ?? "",
                organization: stringValue(entry["PayloadOrganization"])
                    ?? stringValue(entry["organization"])
                    ?? "",
                path: ArtifactRoot.pathKey(url),
                sourceURL: url
            )
        }
    }

    private func parsePayloadPlist(at url: URL) -> EventEnvelope? {
        guard let dict = ArtifactIO.plistDict(contentsOf: url) else { return nil }

        let displayName = stringValue(dict["PayloadDisplayName"]) ?? ""
        let identifier = stringValue(dict["PayloadIdentifier"])
            ?? url.deletingPathExtension().lastPathComponent
        let type = stringValue(dict["PayloadType"]) ?? ""
        let organization = stringValue(dict["PayloadOrganization"]) ?? ""

        // Require at least one profile-like field so random plists are skipped.
        let looksLikeProfile = dict["PayloadDisplayName"] != nil
            || dict["PayloadIdentifier"] != nil
            || dict["PayloadType"] != nil
            || dict["PayloadUUID"] != nil
            || dict["PayloadOrganization"] != nil
        guard looksLikeProfile else { return nil }
        guard !displayName.isEmpty || !identifier.isEmpty || !type.isEmpty else { return nil }

        return makeEvent(
            displayName: displayName,
            identifier: identifier,
            type: type,
            organization: organization,
            path: ArtifactRoot.pathKey(url),
            sourceURL: url
        )
    }

    private func parseManagedPreference(at url: URL) -> EventEnvelope? {
        // Fallback for managed preference domain plists without payload keys.
        let domain = url.deletingPathExtension().lastPathComponent
        guard !domain.isEmpty else { return nil }
        return makeEvent(
            displayName: domain,
            identifier: domain,
            type: "managed_preference",
            organization: "",
            path: ArtifactRoot.pathKey(url),
            sourceURL: url
        )
    }

    private func makeEvent(
        displayName: String,
        identifier: String,
        type: String,
        organization: String,
        path: String,
        sourceURL: URL
    ) -> EventEnvelope? {
        guard !displayName.isEmpty || !identifier.isEmpty else { return nil }

        let attrs = try? FileManager.default.attributesOfItem(atPath: sourceURL.path)
        let mtime = (attrs?[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)
        let idKey = identifier.isEmpty ? displayName : identifier

        return EventEnvelope(
            eventTime: mtime,
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "CONFIGPROFILES",
            eventType: "host.config_profile",
            entityRefs: [
                EntityID(kind: .host, value: "profile=\(idKey)"),
                .file(path: path),
            ],
            fields: [
                "profile.display_name": displayName,
                "profile.identifier": identifier,
                "profile.type": type,
                "profile.organization": organization,
                "profile.path": path,
                FieldTaxonomy.filePath: path,
                FieldTaxonomy.eventType: "host.config_profile",
            ],
            rawRef: path,
            confidence: 0.94
        )
    }

}
