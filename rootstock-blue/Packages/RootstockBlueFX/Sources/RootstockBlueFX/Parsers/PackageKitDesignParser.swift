import Foundation
import RootstockBlueCore

/// PackageKit installer **design surface** markers (Wave-8 residual red↔blue pair).
///
/// Inventories installer services, receipts, and plugin paths from offline markers.
/// Honesty: path/presence posture only - never builds pkgs or invokes installd.
public struct PackageKitDesignParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "PACKAGEKITDESIGN",
        tier: .tier2,
        description: "PackageKit installer design surface (services/receipts/plugins)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/packagekit_design.json",
            "Library/Logs/packagekit_design.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "packagekit_design.json" || name == "packagekit_design.jsonl"
        }) {
            if seen.insert(url) {
                events.append(contentsOf: parseFile(at: url))
            }
        }

        return events
    }

    private func parseFile(at url: URL) -> [EventEnvelope] {
        if url.pathExtension == "jsonl" {
            return ArtifactIO.jsonlDictionaries(contentsOf: url)
                .compactMap { makeEvent(from: $0, sourceURL: url) }
        }
        return ArtifactIO.jsonDictionaryEntries(
            contentsOf: url,
            nestedKeys: ["items", "surfaces", "entries"],
            identityKeys: ["service_present", "receipt_paths", "plugin_paths", "design_surface"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let servicePresent = boolish(item["service_present"])
            ?? boolish(item["services_present"])
            ?? !stringArray(item["service_paths"]).isEmpty
        let receiptPaths = stringArray(item["receipt_paths"])
        let pluginPaths = stringArray(item["plugin_paths"])
        let notes = stringish(item["notes"])
            ?? "PackageKit design surface: path presence only - never builds pkgs"
        let user = stringish(item["user"]) ?? inferUser(from: sourceURL.path) ?? ""

        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        }
        let designSurface = boolish(item["design_surface"])
            ?? (servicePresent || !receiptPaths.isEmpty)
        if designSurface, !risk.contains("design_surface") {
            risk.append("design_surface")
        }
        if servicePresent, !risk.contains("installer_service") {
            risk.append("installer_service")
        }
        if !receiptPaths.isEmpty, !risk.contains("receipt_inventory") {
            risk.append("receipt_inventory")
        }

        // Require at least one signal
        guard servicePresent || !receiptPaths.isEmpty || !pluginPaths.isEmpty || designSurface else {
            return nil
        }

        let receiptField: String
        if !receiptPaths.isEmpty {
            receiptField = receiptPaths.joined(separator: ",")
        } else if let count = stringish(item["receipt_count"]), !count.isEmpty {
            receiptField = count
        } else {
            receiptField = "0"
        }

        var fields: [String: String] = [
            "packagekit.service_present": servicePresent ? "true" : "false",
            "packagekit.receipt_paths": receiptField,
            "packagekit.plugin_paths": pluginPaths.joined(separator: ","),
            "packagekit.notes": notes,
            FieldTaxonomy.eventType: "packagekit.design",
            FieldTaxonomy.userName: user,
        ]
        if !risk.isEmpty {
            fields["packagekit.risk_tags"] = risk.joined(separator: ",")
        }

        return EventEnvelope(
            eventTime: parseDate(item["timestamp"] ?? item["collected_at"]) ?? Date(),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "PACKAGEKITDESIGN",
            eventType: "packagekit.design",
            entityRefs: [
                EntityID(kind: .host, value: "packagekit|design|\(servicePresent)"),
            ],
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.9
        )
    }
}
