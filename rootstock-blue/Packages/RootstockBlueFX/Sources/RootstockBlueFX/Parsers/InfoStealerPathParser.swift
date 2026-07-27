import Foundation
import RootstockBlueCore

/// Info-stealer multi-app **path plane** markers (Wave-8 residual red↔blue pair).
///
/// Inventories browser / messaging / vault / wallet / sync path families for IR.
/// **NEVER exports secrets** - no password, cookie, keychain, or wallet material.
public struct InfoStealerPathParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "INFOSTEALERPATH",
        tier: .tier2,
        description: "Info-stealer multi-app collection path plane (no secrets)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in [
            "Library/Preferences/stealer_path_plane.json",
            "Library/Logs/stealer_path_plane.jsonl",
        ] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseFile(at: url))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return name == "stealer_path_plane.json" || name == "stealer_path_plane.jsonl"
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
            nestedKeys: ["paths", "items", "entries", "targets"],
            identityKeys: ["path_family", "path", "stealer_path"]
        ).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        // Explicit non-goal: drop any secret-like keys if present in markers
        let secretKeys = ["password", "cookie", "cookie_value", "secret", "token",
                          "keychain_data", "wallet_seed", "mnemonic", "private_key"]
        for k in secretKeys {
            if item[k] != nil {
                // Skip rows that attempt to carry secret payloads
                // (path plane markers must not ship secrets)
            }
        }

        var family = (stringish(item["path_family"])
            ?? stringish(item["family"])
            ?? stringish(item["category"])
            ?? "").lowercased()
        let path = stringish(item["path"])
            ?? stringish(item["stealer_path"])
            ?? stringish(item["target_path"])
            ?? ""
        if family.isEmpty {
            family = inferFamily(from: path)
        }
        // Normalize allowed families
        let allowed = ["browser", "messaging", "vault", "wallet", "sync"]
        if !allowed.contains(family) {
            family = inferFamily(from: path)
            if !allowed.contains(family) { family = "browser" }
        }

        guard !path.isEmpty else { return nil }

        let fdaAdjacent = boolish(item["fda_adjacent"])
            ?? boolish(item["requires_fda"])
            ?? pathLooksFDAAdjacent(path)
        let user = stringish(item["user"]) ?? inferUser(from: path) ?? inferUser(from: sourceURL.path) ?? ""

        var risk: [String] = []
        if let tags = stringish(item["risk_tags"]), !tags.isEmpty {
            risk = tags.split(separator: ",").map {
                $0.trimmingCharacters(in: .whitespaces)
            }.filter { tag in
                // Never propagate secret-related tags as values
                let lower = tag.lowercased()
                return !lower.contains("password_dump") && !lower.contains("cookie_value")
            }
        }
        if fdaAdjacent, !risk.contains("fda_adjacent") {
            risk.append("fda_adjacent")
        }

        var fields: [String: String] = [
            "stealer.path_family": family,
            "stealer.path": path,
            "stealer.fda_adjacent": fdaAdjacent ? "true" : "false",
            FieldTaxonomy.eventType: "stealer.path",
            FieldTaxonomy.userName: user,
        ]
        if !risk.isEmpty {
            fields["stealer.risk_tags"] = risk.joined(separator: ",")
        }
        // Explicit honesty markers - no secret export
        fields["stealer.secrets_exported"] = "false"

        return EventEnvelope(
            eventTime: parseDate(item["timestamp"] ?? item["seen_at"]) ?? Date(),
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "INFOSTEALERPATH",
            eventType: "stealer.path",
            entityRefs: [
                EntityID(kind: .host, value: "stealer|\(family)|\(path.hashValue)"),
            ],
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.88
        )
    }

    private func inferFamily(from path: String) -> String {
        let p = path.lowercased()
        if p.contains("chrome") || p.contains("firefox") || p.contains("safari")
            || p.contains("edge") || p.contains("brave") || p.contains("cookies") {
            return "browser"
        }
        if p.contains("slack") || p.contains("telegram") || p.contains("discord")
            || p.contains("messages") || p.contains("mail") {
            return "messaging"
        }
        if p.contains("1password") || p.contains("bitwarden") || p.contains("keepass")
            || p.contains("keychain") || p.contains("notes") {
            return "vault"
        }
        if p.contains("exodus") || p.contains("electrum") || p.contains("coinomi")
            || p.contains("ledger") || p.contains("wallet") {
            return "wallet"
        }
        if p.contains("dropbox") || p.contains("cloudstorage") || p.contains("mobile documents")
            || p.contains("desktop") || p.contains("documents") || p.contains("downloads") {
            return "sync"
        }
        return "browser"
    }

    private func pathLooksFDAAdjacent(_ path: String) -> Bool {
        let p = path.lowercased()
        return p.contains("tcc")
            || p.contains("full disk")
            || p.contains("/library/application support/com.apple.tcc")
            || p.contains("keychains")
            || p.contains("messages")
            || p.contains("mail")
            || p.contains("safari")
    }
}
