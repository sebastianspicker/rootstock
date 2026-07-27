import Foundation
import RootstockBlueCore

/// Login / Logout hooks (`com.apple.loginwindow` LoginHook / LogoutHook).
///
/// Deprecated root-context scripts at interactive boundary (ATT&CK T1037.002).
/// Still hunted on fleets with residual malware, old MDM, or red-team tooling.
/// Runtime on latest macOS is version-variable - presence of configuration is the finding.
///
/// Significant improvement over `defaults read`: offline plist + JSON inventory,
/// script existence metadata, risk tags, harden findings, entity IDs, fixture CI.
/// Does not execute hooks or dump secrets.
public struct LoginHooksParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "LOGINHOOKS",
        tier: .tier1,
        description: "loginwindow LoginHook/LogoutHook persistence scripts"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        // JSON inventory (fixture-friendly)
        for rel in [
            "Library/Preferences/login_hooks.json",
            "Library/Preferences/com.apple.loginwindow.hooks.json",
        ] {
            if let url = root.firstExisting([rel]),
               let json = ArtifactIO.jsonObject(contentsOf: url),
               seen.insert(url) {
                events.append(contentsOf: parseJSONInventory(json, rawRef: ArtifactRoot.pathKey(url)))
            }
        }

        // Classic plists
        let plistPaths = [
            "Library/Preferences/com.apple.loginwindow.plist",
            "var/root/Library/Preferences/com.apple.loginwindow.plist",
            "private/var/root/Library/Preferences/com.apple.loginwindow.plist",
        ]
        for rel in plistPaths {
            guard let url = root.firstExisting([rel]) else { continue }
            guard seen.insert(url) else { continue }
            events.append(contentsOf: parseLoginwindowPlist(at: url))
        }

        // Also accept JSON-encoded loginwindow export used by some collectors
        for rel in [
            "Library/Preferences/com.apple.loginwindow.json",
            "Library/Preferences/loginwindow.json",
        ] {
            guard let url = root.firstExisting([rel]),
                  let json = ArtifactIO.jsonDict(contentsOf: url)
            else { continue }
            guard seen.insert(url) else { continue }
            events.append(contentsOf: eventsFromLoginwindowDict(json, rawRef: ArtifactRoot.pathKey(url)))
        }

        return events
    }

    private func parseJSONInventory(_ json: Any, rawRef: String) -> [EventEnvelope] {
        var items: [[String: Any]] = []
        if let arr = json as? [[String: Any]] {
            items = arr
        } else if let dict = json as? [String: Any] {
            if let hooks = dict["hooks"] as? [[String: Any]] {
                items = hooks
            } else if dict["LoginHook"] != nil || dict["LogoutHook"] != nil {
                return eventsFromLoginwindowDict(dict, rawRef: rawRef)
            } else {
                items = [dict]
            }
        }
        return items.compactMap { item -> EventEnvelope? in
            let hookType = (stringish(item["hook_type"])
                ?? stringish(item["type"])
                ?? stringish(item["kind"])
                ?? "login").lowercased()
            let script = stringish(item["script_path"])
                ?? stringish(item["path"])
                ?? stringish(item["script"])
                ?? ""
            guard !script.isEmpty else { return nil }
            let normalizedType = hookType.contains("out") ? "logout" : "login"
            return makeEvent(
                hookType: normalizedType,
                scriptPath: script,
                scriptExists: boolish(item["script_exists"]).map { $0 ? "true" : "false" },
                rawRef: rawRef
            )
        }
    }

    private func parseLoginwindowPlist(at url: URL) -> [EventEnvelope] {
        // Prefer binary/xml plist; also accept JSON written as .plist in fixtures
        guard let dict = ArtifactIO.jsonOrPlistDict(contentsOf: url) else { return [] }
        return eventsFromLoginwindowDict(dict, rawRef: ArtifactRoot.pathKey(url))
    }

    private func eventsFromLoginwindowDict(_ dict: [String: Any], rawRef: String) -> [EventEnvelope] {
        var events: [EventEnvelope] = []
        if let login = stringish(dict["LoginHook"]), !login.isEmpty {
            events.append(makeEvent(hookType: "login", scriptPath: login, scriptExists: nil, rawRef: rawRef))
        }
        if let logout = stringish(dict["LogoutHook"]), !logout.isEmpty {
            events.append(makeEvent(hookType: "logout", scriptPath: logout, scriptExists: nil, rawRef: rawRef))
        }
        // Alternate keys some exports use
        if let login = stringish(dict["login_hook"]), !login.isEmpty {
            events.append(makeEvent(hookType: "login", scriptPath: login, scriptExists: nil, rawRef: rawRef))
        }
        if let logout = stringish(dict["logout_hook"]), !logout.isEmpty {
            events.append(makeEvent(hookType: "logout", scriptPath: logout, scriptExists: nil, rawRef: rawRef))
        }
        return events
    }

    private func makeEvent(
        hookType: String,
        scriptPath: String,
        scriptExists: String?,
        rawRef: String
    ) -> EventEnvelope {
        let kind = hookType == "logout" ? "logout_hook" : "login_hook"
        var risk: [String] = []
        let lower = scriptPath.lowercased()
        if lower.contains("/tmp/") || lower.contains("/var/tmp/") {
            risk.append("tmp_path")
        }
        if lower.contains("/users/shared/") {
            risk.append("shared_writable")
        }
        if lower.contains("evil") || lower.contains("persist") {
            risk.append("suspicious_name")
        }

        var fields: [String: String] = [
            "persistence.kind": kind,
            "persistence.label": "loginwindow.\(hookType)",
            "persistence.command": scriptPath,
            "persistence.path": scriptPath,
            "loginwindow.hook_type": hookType,
            "loginwindow.script_path": scriptPath,
            "attack.technique": "T1037.002",
            FieldTaxonomy.filePath: scriptPath,
            FieldTaxonomy.eventType: "persistence.item",
        ]
        if let scriptExists {
            fields["loginwindow.script_exists"] = scriptExists
        }
        if !risk.isEmpty {
            fields["persistence.risk_tags"] = risk.joined(separator: ",")
            fields["loginwindow.risk_tags"] = risk.joined(separator: ",")
        }

        let entities: [EntityID] = [
            EntityID(kind: .persistence, value: "loginwindow|\(hookType)|\(scriptPath)"),
            .file(path: scriptPath),
            .file(path: rawRef),
        ]

        return EventEnvelope(
            eventTime: Date(timeIntervalSince1970: 0),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "LOGINHOOKS",
            eventType: "persistence.item",
            entityRefs: entities,
            fields: fields,
            rawRef: rawRef,
            confidence: 0.96
        )
    }
}
