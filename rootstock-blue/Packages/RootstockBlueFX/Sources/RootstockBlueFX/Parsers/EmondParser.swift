import Foundation
import RootstockBlueCore

/// Event Monitor Daemon (emond) rules - classic macOS persistence (ATT&CK T1546.014).
///
/// mac_apt / KnockKnock-class examiners still expect emond.d inventory even though
/// Apple has reduced emond prominence; offline images and older fleets retain it.
///
/// Significant improvement over a CSV dump: normalized `persistence.item` envelopes,
/// entity IDs, and action/command extraction from plist + JSON fixtures for CI.
public struct EmondParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "EMOND",
        tier: .tier1,
        description: "Event Monitor Daemon (emond) rules under /etc/emond.d"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        // JSON inventory export (fixture-friendly, mirrors systemextensions.json style)
        for rel in [
            "etc/emond.d/rules.json",
            "private/etc/emond.d/rules.json",
            "Library/Preferences/emond_rules.json",
        ] {
            if let url = root.firstExisting([rel]),
               let json = ArtifactIO.jsonObject(contentsOf: url),
               seen.insert(url) {
                events.append(contentsOf: parseJSONInventory(json, rawRef: ArtifactRoot.pathKey(url)))
            }
        }

        // Plist / text rules under emond.d/rules
        for url in root.enumerate(matching: { url in
            let path = url.path
            guard path.contains("/emond.d/") || path.contains("/emond/") else { return false }
            if url.hasDirectoryPath { return false }
            let name = url.lastPathComponent
            if name.hasSuffix(".plist") || name.hasSuffix(".json") || name.hasSuffix(".rules") {
                return true
            }
            // Bare rule files without extension under rules/
            return path.contains("/emond.d/rules/") && !name.hasPrefix(".")
        }) {
            guard seen.insert(url) else { continue }
            let key = ArtifactRoot.pathKey(url)
            if url.pathExtension == "json" {
                if let json = ArtifactIO.jsonObject(contentsOf: url) {
                    events.append(contentsOf: parseJSONInventory(json, rawRef: key))
                }
            } else if url.pathExtension == "plist" || isBinaryOrXMLPlist(url) {
                events.append(contentsOf: parsePlistRule(at: url))
            } else if let text = try? String(contentsOf: url, encoding: .utf8) {
                events.append(contentsOf: parseTextRule(at: url, text: text))
            }
        }

        return events
    }

    private func parseJSONInventory(_ json: Any, rawRef: String) -> [EventEnvelope] {
        var items = ArtifactIO.dictionaryEntries(
            from: json,
            nestedKeys: ["rules", "emond_rules"]
        )
        if items.isEmpty, let dict = json as? [String: Any] {
            items = [dict]
        } else if items.isEmpty, let arr = json as? [[String: Any]] {
            items = arr
        }
        return items.compactMap { item in
            let name = stringish(item["name"]) ?? stringish(item["label"]) ?? "unnamed"
            let action = stringish(item["action"])
                ?? stringish(item["command"])
                ?? stringish(item["program"])
                ?? ""
            let enabled = boolish(item["enabled"]).map { $0 ? "true" : "false" } ?? "unknown"
            let eventTypes = stringish(item["eventTypes"])
                ?? stringish(item["event_types"])
                ?? (item["eventTypes"] as? [Any])?.compactMap { stringish($0) }.joined(separator: ",")
                ?? ""
            return makeEvent(
                name: name,
                command: action.isEmpty ? name : action,
                enabled: enabled,
                eventTypes: eventTypes,
                path: rawRef,
                extra: item.compactMapValues { stringish($0) }
            )
        }
    }

    private func parsePlistRule(at url: URL) -> [EventEnvelope] {
        guard let data = ArtifactIO.data(contentsOf: url),
              let obj = ArtifactIO.plistObject(from: data)
        else { return [] }

        let pathKey = ArtifactRoot.pathKey(url)
        if let arr = obj as? [[String: Any]] {
            return arr.compactMap { dict in
                eventFromPlistDict(dict, path: pathKey, fallbackName: url.deletingPathExtension().lastPathComponent)
            }
        }
        if let dict = obj as? [String: Any] {
            // Nested rules array
            if let rules = dict["rules"] as? [[String: Any]] {
                return rules.compactMap {
                    eventFromPlistDict($0, path: pathKey, fallbackName: url.deletingPathExtension().lastPathComponent)
                }
            }
            if let event = eventFromPlistDict(
                dict,
                path: pathKey,
                fallbackName: url.deletingPathExtension().lastPathComponent
            ) {
                return [event]
            }
        }
        return []
    }

    private func eventFromPlistDict(
        _ dict: [String: Any],
        path: String,
        fallbackName: String
    ) -> EventEnvelope? {
        let name = stringish(dict["name"])
            ?? stringish(dict["Name"])
            ?? stringish(dict["label"])
            ?? fallbackName
        // emond actions often under "actions" array with "command" / "type"
        var command = stringish(dict["command"])
            ?? stringish(dict["Command"])
            ?? stringish(dict["programArguments"])
            ?? ""
        if command.isEmpty, let actions = dict["actions"] as? [[String: Any]] {
            let cmds = actions.compactMap { a -> String? in
                stringish(a["command"]) ?? stringish(a["Command"])
                    ?? (a["command"] as? [String])?.joined(separator: " ")
            }
            command = cmds.joined(separator: " | ")
        }
        if command.isEmpty, let args = dict["programArguments"] as? [String] {
            command = args.joined(separator: " ")
        }
        let enabled = boolish(dict["enabled"]).map { $0 ? "true" : "false" }
            ?? boolish(dict["Enabled"]).map { $0 ? "true" : "false" }
            ?? "true"
        var eventTypes = ""
        if let et = dict["eventTypes"] as? [String] {
            eventTypes = et.joined(separator: ",")
        } else if let et = dict["EventTypes"] as? [String] {
            eventTypes = et.joined(separator: ",")
        }
        return makeEvent(
            name: name,
            command: command.isEmpty ? name : command,
            enabled: enabled,
            eventTypes: eventTypes,
            path: path,
            extra: [:]
        )
    }

    private func parseTextRule(at url: URL, text: String) -> [EventEnvelope] {
        let pathKey = ArtifactRoot.pathKey(url)
        let name = url.deletingPathExtension().lastPathComponent
        // First non-comment line as command summary
        var command = name
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = String(raw).trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            command = line
            break
        }
        return [
            makeEvent(
                name: name,
                command: command,
                enabled: "true",
                eventTypes: "",
                path: pathKey,
                extra: [:]
            ),
        ]
    }

    private func makeEvent(
        name: String,
        command: String,
        enabled: String,
        eventTypes: String,
        path: String,
        extra: [String: String]
    ) -> EventEnvelope {
        var fields: [String: String] = [
            "persistence.kind": "emond",
            "persistence.label": name,
            "persistence.command": command,
            "persistence.path": path,
            "emond.rule_name": name,
            "emond.enabled": enabled,
            FieldTaxonomy.filePath: path,
            FieldTaxonomy.eventType: "persistence.item",
        ]
        if !eventTypes.isEmpty {
            fields["emond.event_types"] = eventTypes
        }
        for (k, v) in extra where !v.isEmpty && fields[k] == nil {
            if k.hasPrefix("emond.") || k == "name" || k == "action" { continue }
            fields["emond.\(k)"] = v
        }
        let first = command.split(whereSeparator: { $0 == " " || $0 == "\t" }).first.map(String.init) ?? ""
        if first.hasPrefix("/") {
            fields[FieldTaxonomy.processPath] = first
            fields["persistence.program"] = first
        }

        var entities: [EntityID] = [
            EntityID(kind: .persistence, value: "emond|\(name)|\(command)"),
            .file(path: path),
        ]
        if first.hasPrefix("/") {
            entities.append(.file(path: first))
        }

        return EventEnvelope(
            eventTime: Date(timeIntervalSince1970: 0),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "EMOND",
            eventType: "persistence.item",
            entityRefs: entities,
            fields: fields,
            rawRef: path,
            confidence: 0.94
        )
    }

    private func isBinaryOrXMLPlist(_ url: URL) -> Bool {
        guard let data = try? Data(contentsOf: url, options: [.mappedIfSafe]), data.count >= 6 else {
            return false
        }
        if data.starts(with: Data("bplist".utf8)) { return true }
        if let head = String(data: data.prefix(64), encoding: .utf8),
           head.contains("<?xml") || head.contains("<plist") {
            return true
        }
        return false
    }
}
