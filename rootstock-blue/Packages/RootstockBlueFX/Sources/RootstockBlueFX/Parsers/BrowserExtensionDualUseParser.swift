import Foundation
import RootstockBlueCore

/// Browser extension dual-use markers (Wave-11 red↔blue pair).
///
/// Complements BROWSEREXTENSIONS inventory with dual-use risk tags for residual pairs.
/// Honesty: never dumps extension storage secrets or cookies.
public struct BrowserExtensionDualUseParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "BROWSEREXTDUALUSE",
        tier: .tier2,
        description: "Browser extension dual-use persistence/collection markers (no secrets)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/browser_extension_dualuse.json",
            "Library/Logs/browser_extension_dualuse.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "browser_extension_dualuse.json" || name == "browser_extension_dualuse.jsonl"
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
            nestedKeys: ["items", "extensions", "entries", "paths"],
            identityKeys: ["extension_path", "path", "browser", "extension_id"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let secretKeys = ["password", "cookie", "cookie_value", "secret", "token", "oauth"]
        for k in secretKeys {
            _ = item[k] // explicit non-export - drop by never mapping
        }

        let path = stringish(item["extension_path"])
            ?? stringish(item["path"])
            ?? ""
        let browser = (stringish(item["browser"]) ?? inferBrowser(path)).lowercased()
        let extID = stringish(item["extension_id"]) ?? stringish(item["id"]) ?? ""
        guard !path.isEmpty || !extID.isEmpty else { return nil }

        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map {
                $0.trimmingCharacters(in: .whitespaces)
            }.filter { !$0.lowercased().contains("password_dump") }
        }
        if boolish(item["broad_permissions"]) == true, !risk.contains("broad_permissions") {
            risk.append("broad_permissions")
        }
        if boolish(item["dual_use_surface"]) == true || !path.isEmpty {
            if !risk.contains("dual_use_surface") { risk.append("dual_use_surface") }
        }
        if boolish(item["fda_adjacent"]) == true, !risk.contains("fda_adjacent") {
            risk.append("fda_adjacent")
        }

        let user = stringish(item["user"]) ?? inferUser(from: path) ?? inferUser(from: sourceURL.path) ?? ""
        var fields: [String: String] = [
            "ext_dualuse.browser": browser,
            "ext_dualuse.path": path,
            "ext_dualuse.extension_id": extID,
            "ext_dualuse.secrets_exported": "false",
            "ext_dualuse.notes": stringish(item["notes"])
                ?? "Browser extension dual-use path markers - secrets not exported",
            FieldTaxonomy.eventType: "browser.extension_dualuse",
            FieldTaxonomy.userName: user,
        ]
        if !risk.isEmpty {
            fields["ext_dualuse.risk_tags"] = risk.joined(separator: ",")
        }

        return EventEnvelope(
            eventTime: parseDate(item["timestamp"] ?? item["seen_at"]) ?? Date(),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "BROWSEREXTDUALUSE",
            eventType: "browser.extension_dualuse",
            entityRefs: [
                EntityID(kind: .host, value: "ext_dualuse|\(browser)|\(extID.isEmpty ? path : extID)"),
            ],
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.88
        )
    }

    private func inferBrowser(_ path: String) -> String {
        let p = path.lowercased()
        if p.contains("chrome") { return "chrome" }
        if p.contains("edge") { return "edge" }
        if p.contains("brave") { return "brave" }
        if p.contains("safari") { return "safari" }
        if p.contains("firefox") { return "firefox" }
        return "browser"
    }
}
