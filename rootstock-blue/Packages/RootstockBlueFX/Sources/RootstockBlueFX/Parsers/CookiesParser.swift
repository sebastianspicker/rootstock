import Foundation
import RootstockBlueCore

/// Browser cookie **domain inventory** - session/domain risk without secret values.
///
/// Emits domain, name markers, secure/httpOnly flags, and risk tags.
/// Does not export raw cookie values (privacy / anti-hijack non-goal).
public struct CookiesParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "COOKIES",
        tier: .tier2,
        description: "Browser cookie domain inventory (no raw session values)"
    )

    private static let forbiddenValueKeys: Set<String> = [
        "value", "cookie_value", "raw_value", "session_value", "secret",
        "token", "session_token", "auth_token", "bearer",
    ]

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/cookies_inventory.json",
            "Library/Preferences/browser_cookies.json",
            "Library/Logs/cookies_export.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "cookies_inventory.json"
                || name == "browser_cookies.json"
                || name == "cookies_export.jsonl"
                || name == "Cookies.json"
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
            nestedKeys: ["cookies", "items", "entries"],
            identityKeys: ["domain", "host"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url)
            .compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let domain = stringish(item["domain"])
            ?? stringish(item["host"])
            ?? stringish(item["cookie.domain"])
            ?? ""
        let nameMarker = stringish(item["name_marker"])
            ?? stringish(item["name"])
            ?? stringish(item["cookie_name"])
            ?? ""
        let engine = stringish(item["engine"])
            ?? stringish(item["browser"])
            ?? stringish(item["browser.engine"])
            ?? ""
        let path = stringish(item["path"]) ?? "/"
        let secure = boolish(item["secure"]) ?? boolish(item["is_secure"]) ?? false
        let httpOnly = boolish(item["http_only"])
            ?? boolish(item["httponly"])
            ?? boolish(item["httpOnly"])
            ?? false
        let sameSite = stringish(item["same_site"]) ?? stringish(item["samesite"]) ?? ""

        guard !domain.isEmpty || !nameMarker.isEmpty else { return nil }

        // Never copy raw values even if present in source JSON
        for key in item.keys {
            if Self.forbiddenValueKeys.contains(key.lowercased()) {
                continue
            }
        }

        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        }
        let lowerDomain = domain.lowercased()
        if lowerDomain.contains("evil") || lowerDomain.contains("malware")
            || lowerDomain.contains("c2.") || lowerDomain.hasSuffix(".evil") {
            if !risk.contains("evil_domain") { risk.append("evil_domain") }
        }
        if lowerDomain.contains("pastebin") || lowerDomain.contains("ngrok")
            || lowerDomain.contains("trycloudflare") {
            if !risk.contains("suspicious_domain") { risk.append("suspicious_domain") }
        }
        let lowerName = nameMarker.lowercased()
        if lowerName.contains("session") || lowerName.contains("sid")
            || lowerName.contains("auth") || lowerName.contains("token") {
            if !risk.contains("session_cookie") { risk.append("session_cookie") }
        }
        if !secure && (risk.contains("session_cookie") || risk.contains("evil_domain")) {
            if !risk.contains("insecure_flag") { risk.append("insecure_flag") }
        }

        let user = stringish(item["user"]) ?? inferUser(from: sourceURL.path) ?? ""

        var fields: [String: String] = [
            "cookie.domain": domain,
            "cookie.name_marker": String(nameMarker.prefix(80)),
            "cookie.path": path,
            "cookie.secure": secure ? "true" : "false",
            "cookie.http_only": httpOnly ? "true" : "false",
            "cookie.same_site": sameSite,
            "cookie.engine": engine,
            "cookie.value_exported": "false",
            FieldTaxonomy.eventType: "browser.cookie",
            FieldTaxonomy.browserName: engine,
            FieldTaxonomy.userName: user,
        ]
        if let expires = stringish(item["expires"]) ?? stringish(item["expiry"]) {
            fields["cookie.expires"] = expires
        }
        if !risk.isEmpty {
            fields["cookie.risk_tags"] = risk.joined(separator: ",")
        }

        // Defense: strip any accidental value fields
        fields.removeValue(forKey: "cookie.value")
        fields.removeValue(forKey: "value")

        return EventEnvelope(
            eventTime: parseDate(item["created"] ?? item["last_access"] ?? item["timestamp"])
                ?? Date(timeIntervalSince1970: 0),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "COOKIES",
            eventType: "browser.cookie",
            entityRefs: [
                EntityID(kind: .network, value: "cookie|\(domain)"),
            ],
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.9
        )
    }
}
