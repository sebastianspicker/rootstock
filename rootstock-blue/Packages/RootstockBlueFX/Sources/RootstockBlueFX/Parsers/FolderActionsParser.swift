import Foundation
import RootstockBlueCore

/// Folder Actions / Automator-class event-triggered persistence (ATT&CK T1546).
///
/// Watches folder attach scripts/workflows under user and system Script libraries.
/// Not always-on like LaunchAgents - quiet in process lists until file events fire.
///
/// Significant improvement over directory listing: association inventory (watched
/// folder + script), risk tags (do shell script, Downloads watch, curl/tmp),
/// entity IDs, case custody, fixture CI.
public struct FolderActionsParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "FOLDERACTIONS",
        tier: .tier1,
        description: "Folder Actions scripts/workflows and dispatcher associations"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        // JSON inventory (fixture-friendly associations)
        for rel in [
            "Library/Preferences/folder_actions.json",
            "Users/alice/Library/Workflows/folder_actions.json",
            "Users/alice/Library/Preferences/com.apple.FolderActionsDispatcher.json",
        ] {
            if let url = root.firstExisting([rel]),
               let json = ArtifactIO.jsonObject(contentsOf: url),
               seen.insert(url) {
                let key = ArtifactRoot.pathKey(url)
                events.append(contentsOf: parseJSONInventory(json, rawRef: key, defaultUser: inferUser(from: key)))
            }
        }

        // Per-user JSON under Users/*/
        for url in root.enumerate(matching: { url in
            let path = url.path
            guard !url.hasDirectoryPath else { return false }
            let name = url.lastPathComponent
            return name == "folder_actions.json"
                || name == "com.apple.FolderActionsDispatcher.json"
                || (path.contains("/FolderActions") && name.hasSuffix(".json"))
        }) {
            guard seen.insert(url) else { continue }
            let key = ArtifactRoot.pathKey(url)
            if let json = ArtifactIO.jsonObject(contentsOf: url) {
                events.append(contentsOf: parseJSONInventory(
                    json,
                    rawRef: key,
                    defaultUser: inferUser(from: key)
                ))
            }
        }

        // Scripts / workflows on disk
        for url in root.enumerate(matching: { url in
            let path = url.path
            if url.hasDirectoryPath { return false }
            let name = url.lastPathComponent
            if name.hasPrefix(".") { return false }
            if path.contains("Folder Action Scripts") { return true }
            if path.contains("/Workflows/Applications/Folder Actions/") { return true }
            if path.contains("/Workflows/") && (name.hasSuffix(".workflow") || name.hasSuffix(".scpt") || name.hasSuffix(".applescript") || name.hasSuffix(".sh")) {
                return path.lowercased().contains("folder")
            }
            return false
        }) {
            guard seen.insert(url) else { continue }
            let key = ArtifactRoot.pathKey(url)

            let name = url.deletingPathExtension().lastPathComponent
            let user = inferUser(from: key)
            let textSample = loadTextSample(url) ?? ""
            var risk = riskTags(forScriptPath: key, watched: "", scriptText: textSample)
            risk = Array(Set(risk)).sorted()

            events.append(
                makeEvent(
                    name: name,
                    scriptPath: key,
                    watchedPath: "",
                    enabled: "true",
                    user: user,
                    riskTags: risk,
                    rawRef: key
                )
            )
        }

        return events
    }

    private func parseJSONInventory(_ json: Any, rawRef: String, defaultUser: String?) -> [EventEnvelope] {
        var items = ArtifactIO.dictionaryEntries(
            from: json,
            nestedKeys: ["actions", "folder_actions", "folderActions"]
        )
        if items.isEmpty, let dict = json as? [String: Any] {
            items = [dict]
        } else if items.isEmpty, let arr = json as? [[String: Any]] {
            items = arr
        }

        return items.compactMap { item -> EventEnvelope? in
            let name = stringish(item["name"])
                ?? stringish(item["label"])
                ?? stringish(item["script"])
                ?? "unnamed"
            let script = stringish(item["script_path"])
                ?? stringish(item["script"])
                ?? stringish(item["path"])
                ?? stringish(item["workflow"])
                ?? ""
            let watched = stringish(item["watched_path"])
                ?? stringish(item["folder"])
                ?? stringish(item["watched"])
                ?? ""
            let enabled = boolish(item["enabled"]).map { $0 ? "true" : "false" } ?? "true"
            let user = stringish(item["user"]) ?? defaultUser
            var risk: [String] = []
            if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
                risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            }
            let command = stringish(item["command"]) ?? stringish(item["body"]) ?? script
            risk.append(contentsOf: riskTags(forScriptPath: script, watched: watched, scriptText: command))
            risk = Array(Set(risk)).sorted()

            guard !script.isEmpty || !watched.isEmpty || !name.isEmpty else { return nil }
            return makeEvent(
                name: name,
                scriptPath: script.isEmpty ? rawRef : script,
                watchedPath: watched,
                enabled: enabled,
                user: user,
                riskTags: risk,
                rawRef: rawRef
            )
        }
    }

    private func makeEvent(
        name: String,
        scriptPath: String,
        watchedPath: String,
        enabled: String,
        user: String?,
        riskTags: [String],
        rawRef: String
    ) -> EventEnvelope {
        var fields: [String: String] = [
            "persistence.kind": "folder_action",
            "persistence.label": name,
            "persistence.command": scriptPath,
            "persistence.path": scriptPath,
            "folder_action.name": name,
            "folder_action.script_path": scriptPath,
            "folder_action.enabled": enabled,
            FieldTaxonomy.filePath: scriptPath,
            FieldTaxonomy.eventType: "persistence.item",
        ]
        if !watchedPath.isEmpty {
            fields["folder_action.watched_path"] = watchedPath
            fields["persistence.watched_path"] = watchedPath
        }
        if let user, !user.isEmpty {
            fields[FieldTaxonomy.userName] = user
            fields["folder_action.scope"] = "user"
        } else {
            fields["folder_action.scope"] = "system"
        }
        if !riskTags.isEmpty {
            fields["persistence.risk_tags"] = riskTags.joined(separator: ",")
            fields["folder_action.risk_tags"] = riskTags.joined(separator: ",")
        }

        var entities: [EntityID] = [
            EntityID(kind: .persistence, value: "folder_action|\(user ?? "system")|\(name)|\(scriptPath)"),
            .file(path: scriptPath),
        ]
        if let user, !user.isEmpty {
            entities.append(.user(name: user))
        }
        if !watchedPath.isEmpty {
            entities.append(.file(path: watchedPath))
        }

        return EventEnvelope(
            eventTime: Date(timeIntervalSince1970: 0),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "FOLDERACTIONS",
            eventType: "persistence.item",
            entityRefs: entities,
            fields: fields,
            rawRef: rawRef,
            confidence: 0.93
        )
    }

    private func riskTags(forScriptPath script: String, watched: String, scriptText: String) -> [String] {
        var tags: [String] = []
        let lower = (script + " " + scriptText).lowercased()
        let watchedLower = watched.lowercased()
        if lower.contains("do shell script") || lower.contains("doshellscript") {
            tags.append("do_shell_script")
        }
        if lower.contains("curl") || lower.contains("wget") {
            tags.append("network_fetch")
        }
        if lower.contains("/tmp/") || lower.contains("/var/tmp/") {
            tags.append("tmp_payload")
        }
        if lower.contains("base64") {
            tags.append("base64_payload")
        }
        if watchedLower.contains("/downloads") || watchedLower.hasSuffix("downloads") {
            tags.append("downloads_watch")
        }
        if watchedLower.contains("/desktop") || watchedLower.hasSuffix("desktop") {
            tags.append("desktop_watch")
        }
        if script.lowercased().contains("evil") || scriptText.lowercased().contains("evil") {
            tags.append("suspicious_name")
        }
        return tags
    }

    private func loadTextSample(_ url: URL) -> String? {
        guard let data = try? Data(contentsOf: url), data.count < 256_000 else { return nil }
        if let text = String(data: data, encoding: .utf8) { return text }
        // Binary .scpt: extract printable ASCII for heuristics
        var printable = ""
        for b in data.prefix(8192) {
            if b >= 32 && b < 127 {
                printable.append(Character(UnicodeScalar(b)))
            } else {
                printable.append(" ")
            }
        }
        return printable
    }
}
