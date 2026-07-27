import Foundation
import RootstockBlueCore

/// Keychain metadata inventory from collector/fixture JSON exports.
///
/// Emits item class, label, access group, account (username-like), and mtime only.
///
/// Non-goal: Never emit password, secret, key material, private keys, tokens,
/// or any `kSecValueData`-equivalent fields. Metadata hunting only (labels,
/// access groups, generic-password presence in system keychains).
public struct KeychainMetaParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "KEYCHAINMETA",
        tier: .tier2,
        description: "Keychain item metadata only (no secrets/passwords/keys)"
    )

    /// Field names that must never be copied into envelopes (defense in depth).
    private static let forbiddenKeys: Set<String> = [
        "password", "secret", "key", "private_key", "privatekey", "token",
        "ksecvaluedata", "data", "value_data", "credential", "passwd",
        "passphrase", "api_key", "apikey", "auth_token", "refresh_token",
        "session_key", "symmetric_key", "key_data", "secret_data",
    ]

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/keychain_metadata.json",
            "Library/Preferences/keychain_meta.json",
        ] {
            if let url = root.firstExisting([rel]),
               let json = ArtifactIO.jsonObject(contentsOf: url),
               seen.insert(url) {
                events.append(contentsOf: parseJSONInventory(json, rawRef: ArtifactRoot.pathKey(url), defaultUser: nil))
            }
        }

        // Users/*/Library/Preferences/keychain_metadata.json
        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "keychain_metadata.json" || name == "keychain_meta.json"
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

        return events
    }

    private func parseJSONInventory(_ json: Any, rawRef: String, defaultUser: String?) -> [EventEnvelope] {
        let items = ArtifactIO.dictionaryEntries(
            from: json,
            nestedKeys: ["items", "entries", "keychain", "metadata"],
            identityKeys: ["label", "item_class", "access_group"]
        )
        return items.compactMap { makeEvent(from: $0, rawRef: rawRef, defaultUser: defaultUser) }
    }

    private func makeEvent(from item: [String: Any], rawRef: String, defaultUser: String?) -> EventEnvelope? {
        // Strip any forbidden keys if a collector mistakenly included them
        let sanitized = item.filter { key, _ in
            !Self.forbiddenKeys.contains(key.lowercased().replacingOccurrences(of: "-", with: "_"))
        }

        let itemClass = stringish(sanitized["item_class"])
            ?? stringish(sanitized["class"])
            ?? stringish(sanitized["kSecClass"])
            ?? ""
        let label = stringish(sanitized["label"])
            ?? stringish(sanitized["labl"])
            ?? stringish(sanitized["service"])
            ?? ""
        let accessGroup = stringish(sanitized["access_group"])
            ?? stringish(sanitized["agrp"])
            ?? stringish(sanitized["accessGroup"])
            ?? ""
        // Account is username-like identity only - never a password field
        let account = stringish(sanitized["account"])
            ?? stringish(sanitized["acct"])
            ?? stringish(sanitized["username"])
            ?? stringish(sanitized["user"])
            ?? ""
        let mtime = stringish(sanitized["mtime"])
            ?? stringish(sanitized["modification_date"])
            ?? stringish(sanitized["modified"])
            ?? stringish(sanitized["cdat"])
            ?? ""

        guard !itemClass.isEmpty || !label.isEmpty || !accessGroup.isEmpty || !account.isEmpty else {
            return nil
        }

        var risk: [String] = []
        if let tags = stringish(sanitized["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        }

        let lowerLabel = label.lowercased()
        let lowerGroup = accessGroup.lowercased()
        let lowerClass = itemClass.lowercased()

        if lowerLabel.contains("evil") || lowerLabel.contains("implant") || lowerLabel.contains("backdoor") {
            if !risk.contains("suspicious_label") { risk.append("suspicious_label") }
        }
        // Unexpected access groups (non-Apple, non-standard)
        if !accessGroup.isEmpty
            && !lowerGroup.hasPrefix("apple")
            && !lowerGroup.hasPrefix("com.apple")
            && (lowerGroup.contains("evil") || lowerGroup.contains("unknown")
                || boolish(sanitized["unexpected_access_group"]) == true) {
            if !risk.contains("unexpected_access_group") { risk.append("unexpected_access_group") }
        }
        // Generic password items in system-scoped keychains are interesting
        let isGenericPassword = lowerClass.contains("generic")
            || lowerClass == "genp"
            || lowerClass.contains("internet")
        let systemScope = rawRef.contains("/Library/Preferences/keychain")
            && !rawRef.contains("/Users/")
        if isGenericPassword && (systemScope || boolish(sanitized["system_keychain"]) == true) {
            if !risk.contains("generic_password_in_system") { risk.append("generic_password_in_system") }
        }

        var fields: [String: String] = [
            "keychain.item_class": itemClass,
            "keychain.label": label,
            "keychain.access_group": accessGroup,
            "keychain.account": account,
            "keychain.mtime": mtime,
            FieldTaxonomy.eventType: "keychain.metadata",
        ]
        // Explicitly do NOT set any password/secret/key fields
        if !risk.isEmpty {
            fields["keychain.risk_tags"] = risk.joined(separator: ",")
        }
        let user = defaultUser ?? inferUser(from: rawRef)
        if let user {
            fields[FieldTaxonomy.userName] = user
        }

        var entities: [EntityID] = [
            EntityID(kind: .auth, value: "keychain|\(itemClass)|\(label)|\(account)"),
            .file(path: rawRef),
        ]
        if let user {
            entities.append(.user(name: user))
        }

        let eventTime = parseDate(sanitized["mtime"] ?? sanitized["modification_date"] ?? sanitized["timestamp"])
            ?? Date(timeIntervalSince1970: 0)

        return EventEnvelope(
            eventTime: eventTime,
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "KEYCHAINMETA",
            eventType: "keychain.metadata",
            entityRefs: entities,
            fields: fields,
            rawRef: rawRef,
            confidence: 0.91
        )
    }
}
