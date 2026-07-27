import Foundation
import RootstockBlueCore

/// Gatekeeper assessment history from fixture JSON / JSONL exports.
///
/// Paths: `Library/Preferences/com.apple.security.gk.json` or
/// `Library/Logs/Gatekeeper/assessments.jsonl`.
public struct GatekeeperHistoryParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "GATEKEEPER",
        tier: .tier2,
        description: "Gatekeeper assessment history (allowed/denied paths)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var urls: [URL] = []
        var seen = PathDeduper()

        for found in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            let path = url.path
            if name == "com.apple.security.gk.json" { return true }
            if name == "assessments.jsonl" || name == "assessments.json" {
                return path.contains("Gatekeeper") || path.contains("gatekeeper") || path.contains("security")
            }
            if name == "gk.json" || name == "gatekeeper.json" { return true }
            return false
        }) {
            if !seen.insert(found) { continue }
            ArtifactRoot.appendUnique(&urls, found)
        }

        for rel in [
            "Library/Preferences/com.apple.security.gk.json",
            "Library/Logs/Gatekeeper/assessments.jsonl",
        ] {
            if let u = root.firstExisting([rel]) {
                if seen.insert(u) {
                    ArtifactRoot.appendUnique(&urls, u)
                }
            }
        }

        var events: [EventEnvelope] = []
        for url in urls {
            if url.pathExtension == "jsonl" || url.lastPathComponent.hasSuffix(".jsonl") {
                events.append(contentsOf: parseJSONL(at: url))
            } else {
                events.append(contentsOf: parseJSON(at: url))
            }
        }
        return events
    }

    private func parseJSONL(at url: URL) -> [EventEnvelope] {
        ArtifactIO.jsonlDictionaries(contentsOf: url).compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func parseJSON(at url: URL) -> [EventEnvelope] {
        guard let obj = ArtifactIO.jsonObject(contentsOf: url) else { return [] }
        let entries = ArtifactIO.dictionaryEntries(
            from: obj,
            nestedKeys: ["assessments", "items", "history"],
            identityKeys: ["path", "result"]
        )
        return entries.compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let path = stringValue(item["path"])
            ?? stringValue(item["file"])
            ?? stringValue(item["file_path"])
            ?? stringValue(item["url"])
            ?? ""
        let result = stringValue(item["result"])
            ?? stringValue(item["assessment"])
            ?? stringValue(item["status"])
            ?? ""
        let policy = stringValue(item["policy"])
            ?? stringValue(item["gatekeeper_policy"])
            ?? stringValue(item["rule"])
            ?? ""

        guard !path.isEmpty || !result.isEmpty else { return nil }

        // Override = operator/user bypass of Gatekeeper only - NOT a normal deny/unsigned fail.
        let overrideFlag: Bool = {
            if let b = item["override"] as? Bool { return b }
            if let n = item["override"] as? NSNumber { return n.boolValue }
            if let s = item["override"] as? String {
                return ["true", "1", "yes"].contains(s.lowercased())
            }
            let r = result.lowercased()
            let p = policy.lowercased()
            // Explicit override language only (not denied / unsigned / fail)
            return r.contains("override")
                || r.contains("user-approved")
                || r.contains("user_override")
                || r.contains("user approved")
                || p.contains("user_override")
                || p.contains("user-override")
        }()

        let lowerResult = result.lowercased()
        let deniedOrUnsigned = lowerResult.contains("denied")
            || lowerResult.contains("unsigned")
            || lowerResult.contains("fail")
            || lowerResult.contains("reject")

        var fields: [String: String] = [
            FieldTaxonomy.filePath: path.isEmpty ? ArtifactRoot.pathKey(sourceURL) : path,
            "gatekeeper.result": result,
            "gatekeeper.policy": policy,
            "gatekeeper.override": overrideFlag ? "true" : "false",
            FieldTaxonomy.eventType: "gatekeeper.assessment",
        ]
        // Suspicious covers denials and overrides; override stays a distinct signal.
        if overrideFlag || deniedOrUnsigned {
            fields["gatekeeper.suspicious"] = "true"
        }
        if !path.isEmpty {
            fields["gatekeeper.path"] = path
        }
        if let signer = stringValue(item["signer"]) ?? stringValue(item["signing_id"]) {
            fields["gatekeeper.signer"] = signer
        }
        if let team = stringValue(item["team_id"]) ?? stringValue(item["teamId"]) {
            fields["gatekeeper.team_id"] = team
        }

        var entities: [EntityID] = [
            EntityID(kind: .host, value: "gatekeeper|\(result)|\(path)"),
        ]
        if !path.isEmpty {
            entities.append(.file(path: path))
        }

        let eventTime = parseDate(item["timestamp"] ?? item["time"] ?? item["assessed_at"])
            ?? fileMTime(sourceURL)

        return EventEnvelope(
            eventTime: eventTime,
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "GATEKEEPER",
            eventType: "gatekeeper.assessment",
            entityRefs: entities,
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.9
        )
    }

    private func fileMTime(_ url: URL) -> Date {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs?[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)
    }
}
