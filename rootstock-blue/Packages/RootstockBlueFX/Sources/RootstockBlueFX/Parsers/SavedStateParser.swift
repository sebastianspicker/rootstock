import Foundation
import RootstockBlueCore

/// Saved Application State inventory - which apps left restore windows/state.
///
/// Useful for pattern-of-life and for spotting non-Apple bundles with tmp-backed
/// app paths (suspicious implant UI restore).
public struct SavedStateParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "SAVEDSTATE",
        tier: .tier2,
        description: "Saved Application State inventory (bundle_id / restore paths)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/saved_state.json",
            "Library/Preferences/saved_application_state.json",
            "Library/Logs/saved_state.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "saved_state.json"
                || name == "saved_application_state.json"
                || name == "saved_state.jsonl"
        }) {
            if seen.insert(url) {
                events.append(contentsOf: parseFile(at: url))
            }
        }

        // Discover *.savedState directories
        for url in root.enumerate(matching: { url in
            url.path.contains("Saved Application State")
                && (url.lastPathComponent.hasSuffix(".savedState")
                    || url.lastPathComponent == "windows.plist"
                    || url.lastPathComponent == "data.data")
        }) {
            // Prefer directory-level entity: if windows.plist, use parent
            let stateURL: URL
            if url.lastPathComponent.hasSuffix(".savedState") {
                stateURL = url
            } else if url.path.contains(".savedState") {
                // Walk up to .savedState component
                var cur = url
                while !cur.lastPathComponent.hasSuffix(".savedState"), cur.path != "/" {
                    cur = cur.deletingLastPathComponent()
                }
                stateURL = cur
            } else {
                continue
            }
            let key = "savedstate-dir:" + ArtifactRoot.pathKey(stateURL)
            if seen.insert(pathKey: key) {
                let bundleHint = stateURL.lastPathComponent
                    .replacingOccurrences(of: ".savedState", with: "")
                events.append(
                    EventEnvelope(
                        eventTime: Date(timeIntervalSince1970: 0),
                        collectedAt: Date(),
                        source: .parser,
                        sourcePlugin: "SAVEDSTATE",
                        eventType: "app.saved_state",
                        entityRefs: [
                            EntityID(kind: .host, value: "savedstate|\(bundleHint)"),
                            .file(path: ArtifactRoot.pathKey(stateURL)),
                        ],
                        fields: makeFields(
                            bundleID: bundleHint,
                            path: ArtifactRoot.pathKey(stateURL),
                            appPath: "",
                            risk: riskFor(bundleID: bundleHint, appPath: "")
                        ),
                        rawRef: ArtifactRoot.pathKey(stateURL),
                        confidence: 0.85
                    )
                )
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
            nestedKeys: ["states", "items", "saved_state"],
            identityKeys: ["bundle_id"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url)
            .compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let bundleID = stringish(item["bundle_id"])
            ?? stringish(item["bundleID"])
            ?? stringish(item["app_id"])
            ?? ""
        let path = stringish(item["path"])
            ?? stringish(item["state_path"])
            ?? ""
        let appPath = stringish(item["app_path"])
            ?? stringish(item["executable"])
            ?? ""
        guard !bundleID.isEmpty || !path.isEmpty else { return nil }

        var risk = riskFor(bundleID: bundleID, appPath: appPath)
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            for t in tags.split(separator: ",") {
                let s = t.trimmingCharacters(in: .whitespaces)
                if !s.isEmpty, !risk.contains(s) { risk.append(s) }
            }
        }

        return EventEnvelope(
            eventTime: parseDate(item["last_restored"] ?? item["mtime"]) ?? Date(timeIntervalSince1970: 0),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "SAVEDSTATE",
            eventType: "app.saved_state",
            entityRefs: [
                EntityID(kind: .host, value: "savedstate|\(bundleID.isEmpty ? path : bundleID)"),
            ] + (path.isEmpty ? [] : [.file(path: path)]),
            fields: makeFields(bundleID: bundleID, path: path, appPath: appPath, risk: risk),
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.9
        )
    }

    private func makeFields(bundleID: String, path: String, appPath: String, risk: [String]) -> [String: String] {
        var fields: [String: String] = [
            "savedstate.bundle_id": bundleID,
            "savedstate.path": path,
            "savedstate.app_path": appPath,
            FieldTaxonomy.eventType: "app.saved_state",
        ]
        if !risk.isEmpty {
            fields["savedstate.risk_tags"] = risk.joined(separator: ",")
        }
        return fields
    }

    private func riskFor(bundleID: String, appPath: String) -> [String] {
        var risk: [String] = []
        let b = bundleID.lowercased()
        let p = appPath.lowercased()
        if b.contains("evil") || b.contains("implant") || b.contains("malware") {
            risk.append("suspicious_bundle")
        }
        if p.contains("/tmp/") || p.hasPrefix("/var/tmp") || p.contains("/downloads/") {
            risk.append("tmp_path")
        }
        if !b.hasPrefix("com.apple.") && !b.hasPrefix("com.microsoft.")
            && !b.hasPrefix("com.google.") && !b.isEmpty
            && (b.contains("unknown") || b.contains("hack")) {
            risk.append("unknown_vendor")
        }
        return risk
    }
}
