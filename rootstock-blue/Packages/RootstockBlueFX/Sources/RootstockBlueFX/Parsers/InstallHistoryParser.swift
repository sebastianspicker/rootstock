import Foundation
import RootstockBlueCore

/// Software install history from InstallHistory.plist (Library/Receipts).
/// Emits `software.install` envelopes with package/file entity refs for timeline/SQL.
public struct InstallHistoryParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "INSTALLHISTORY",
        tier: .tier2,
        description: "InstallHistory.plist software package installs"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var urls: [URL] = []
        if let primary = root.firstExisting([
            "Library/Receipts/InstallHistory.plist",
            "private/var/db/receipts/InstallHistory.plist",
        ]) {
            ArtifactRoot.appendUnique(&urls, primary)
        }
        for found in root.enumerate(matching: { $0.lastPathComponent == "InstallHistory.plist" }) {
            ArtifactRoot.appendUnique(&urls, found)
        }

        var events: [EventEnvelope] = []
        for url in urls {
            events.append(contentsOf: parseHistory(at: url))
        }
        return events
    }

    private func parseHistory(at url: URL) -> [EventEnvelope] {
        guard let data = ArtifactIO.data(contentsOf: url) else { return [] }

        let entries: [[String: Any]]
        if let dict = ArtifactIO.plistDict(from: data),
           let arr = dict["InstallHistory"] as? [[String: Any]] {
            entries = arr
        } else if let arr = ArtifactIO.plistArray(from: data) {
            entries = arr
        } else {
            return []
        }

        var out: [EventEnvelope] = []
        for (idx, entry) in entries.enumerated() {
            let displayName = stringValue(entry["displayName"]) ?? stringValue(entry["DisplayName"]) ?? ""
            let version = stringValue(entry["displayVersion"]) ?? stringValue(entry["DisplayVersion"]) ?? ""
            let process = stringValue(entry["processName"]) ?? stringValue(entry["ProcessName"]) ?? ""
            let contentType = stringValue(entry["contentType"]) ?? stringValue(entry["ContentType"]) ?? ""
            let packages = stringArray(entry["packageIdentifiers"] ?? entry["PackageIdentifiers"])
            let date = parseDate(entry["date"] ?? entry["Date"]) ?? Date(timeIntervalSince1970: 0)

            guard !displayName.isEmpty || !packages.isEmpty else { continue }

            let pkgKey = packages.first ?? displayName
            var entities: [EntityID] = [
                EntityID(kind: .file, value: "pkg:\(pkgKey)"),
            ]
            if !process.isEmpty {
                entities.append(EntityID(kind: .process, value: "name=\(process)"))
            }

            out.append(
                EventEnvelope(
                    eventTime: date,
                    collectedAt: Date(),
                    source: .parser,
                    sourcePlugin: "INSTALLHISTORY",
                    eventType: "software.install",
                    entityRefs: entities,
                    fields: [
                        "software.display_name": displayName,
                        "software.version": version,
                        "software.process_name": process,
                        "software.content_type": contentType,
                        "software.package_identifiers": packages.joined(separator: ","),
                        "software.install_index": String(idx),
                        "software.source_path": ArtifactRoot.pathKey(url),
                        FieldTaxonomy.processPath: process,
                        FieldTaxonomy.eventType: "software.install",
                    ],
                    rawRef: ArtifactRoot.pathKey(url),
                    confidence: 0.96
                )
            )
        }
        return out
    }
}
