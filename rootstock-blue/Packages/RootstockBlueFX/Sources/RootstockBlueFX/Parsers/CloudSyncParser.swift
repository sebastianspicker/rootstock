import Foundation
import RootstockBlueCore

/// Multi-provider cloud-sync **posture markers** beyond iCloud.
///
/// Covers Dropbox, OneDrive, Google Drive, Box, and similar clients,
/// account markers, sync enablement, and folder paths for exfil IR.
/// Does not dump full cloud file listings or account secrets.
public struct CloudSyncParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "CLOUDSYNC",
        tier: .tier2,
        description: "Multi-provider cloud sync markers (Dropbox/OneDrive/GDrive/Box)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/cloud_sync.json",
            "Library/Preferences/cloud_providers.json",
            "Library/Preferences/dropbox_sync.json",
            "Library/Preferences/onedrive_sync.json",
            "Library/Logs/cloud_sync.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "cloud_sync.json"
                || name == "cloud_providers.json"
                || name == "dropbox_sync.json"
                || name == "onedrive_sync.json"
                || name == "gdrive_sync.json"
                || name == "box_sync.json"
                || name == "cloud_sync.jsonl"
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
            nestedKeys: ["providers", "items", "accounts"],
            identityKeys: ["provider", "sync_enabled"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url)
            .compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        var provider = stringish(item["provider"])
            ?? stringish(item["name"])
            ?? stringish(item["service"])
            ?? ""
        // Infer provider from filename when missing
        if provider.isEmpty {
            let path = sourceURL.path.lowercased()
            if path.contains("dropbox") { provider = "dropbox" }
            else if path.contains("onedrive") { provider = "onedrive" }
            else if path.contains("gdrive") || path.contains("google") { provider = "google_drive" }
            else if path.contains("box") { provider = "box" }
        }
        let syncEnabled = boolish(item["sync_enabled"])
            ?? boolish(item["enabled"])
            ?? true
        let folderPath = stringish(item["folder_path"])
            ?? stringish(item["path"])
            ?? stringish(item["sync_folder"])
            ?? ""
        // Account marker only - domain or partial, not full secrets
        var accountMarker = stringish(item["account_marker"])
            ?? stringish(item["account"])
            ?? stringish(item["email"])
            ?? ""
        if accountMarker.contains("@") {
            let parts = accountMarker.split(separator: "@")
            if parts.count == 2 {
                accountMarker = "***@" + String(parts[1])
            }
        }
        let selectiveSync = boolish(item["selective_sync"]) ?? false

        guard !provider.isEmpty || !folderPath.isEmpty || syncEnabled else { return nil }
        if provider.isEmpty { provider = "unknown" }

        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        }
        if syncEnabled {
            if !risk.contains("sync_enabled") { risk.append("sync_enabled") }
        }
        let knownExfil = ["dropbox", "onedrive", "google_drive", "gdrive", "box", "mega", "pcloud"]
        if knownExfil.contains(provider.lowercased()) && syncEnabled {
            if !risk.contains("exfil_capable_provider") { risk.append("exfil_capable_provider") }
        }
        if folderPath.lowercased().contains("desktop")
            || folderPath.lowercased().contains("documents") {
            if !risk.contains("desktop_documents_scope") { risk.append("desktop_documents_scope") }
        }
        if folderPath.lowercased().contains("evil") || provider.lowercased().contains("evil") {
            if !risk.contains("suspicious_provider") { risk.append("suspicious_provider") }
        }

        let user = stringish(item["user"]) ?? inferUser(from: sourceURL.path) ?? ""

        var fields: [String: String] = [
            "cloud.provider": provider.lowercased(),
            "cloud.account_marker": accountMarker,
            "cloud.sync_enabled": syncEnabled ? "true" : "false",
            "cloud.folder_path": folderPath,
            "cloud.selective_sync": selectiveSync ? "true" : "false",
            FieldTaxonomy.eventType: "cloud.provider_sync",
            FieldTaxonomy.userName: user,
        ]
        if !risk.isEmpty {
            fields["cloud.risk_tags"] = risk.joined(separator: ",")
        }

        return EventEnvelope(
            eventTime: parseDate(item["last_sync"] ?? item["timestamp"])
                ?? Date(),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "CLOUDSYNC",
            eventType: "cloud.provider_sync",
            entityRefs: [
                EntityID(kind: .host, value: "cloud|\(provider.lowercased())|\(accountMarker)"),
            ],
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.9
        )
    }
}
