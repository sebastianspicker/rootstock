import Foundation
import RootstockBlueCore

/// Login session records from fixture-friendly utmpx/wtmp JSONL exports.
///
/// Binary utmpx is platform-specific; collectors typically dump JSONL under
/// `private/var/run/utmpx.jsonl`, `var/log/wtmp.jsonl`, or `Library/Logs/utmpx_export.jsonl`.
public struct UtmpxParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "UTMPX",
        tier: .tier1,
        description: "utmpx/wtmp login session records (JSONL export)"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var urls: [URL] = []
        var seen = PathDeduper()

        for found in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            if name == "utmpx.jsonl" || name == "wtmp.jsonl" || name == "utmpx_export.jsonl"
                || name == "btmp.jsonl" || name == "lastlog.jsonl" {
                return true
            }
            if name == "utmpx.json" || name == "wtmp.json" {
                return true
            }
            return false
        }) {
            if !seen.insert(found) { continue }
            ArtifactRoot.appendUnique(&urls, found)
        }

        for rel in [
            "private/var/run/utmpx.jsonl",
            "var/run/utmpx.jsonl",
            "var/log/wtmp.jsonl",
            "private/var/log/wtmp.jsonl",
            "Library/Logs/utmpx_export.jsonl",
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
            nestedKeys: ["records", "entries"]
        )
        return entries.compactMap { makeEvent(from: $0, sourceURL: url) }
    }

    private func makeEvent(from item: [String: Any], sourceURL: URL) -> EventEnvelope? {
        let user = stringValue(item["user"])
            ?? stringValue(item["user_name"])
            ?? stringValue(item["username"])
            ?? stringValue(item["ut_user"])
            ?? ""
        let tty = stringValue(item["tty"])
            ?? stringValue(item["line"])
            ?? stringValue(item["ut_line"])
            ?? ""
        let host = stringValue(item["host"])
            ?? stringValue(item["hostname"])
            ?? stringValue(item["ut_host"])
            ?? ""
        let typeRaw = stringValue(item["type"])
            ?? stringValue(item["ut_type"])
            ?? stringValue(item["event"])
            ?? ""
        let pid = stringValue(item["pid"]) ?? stringValue(item["ut_pid"]) ?? ""

        guard !user.isEmpty || !typeRaw.isEmpty || !tty.isEmpty else { return nil }

        let (eventType, authType) = mapType(typeRaw, item: item)

        var fields: [String: String] = [
            "auth.tty": tty,
            "auth.host": host,
            "auth.type": authType,
            FieldTaxonomy.eventType: eventType,
            FieldTaxonomy.filePath: ArtifactRoot.pathKey(sourceURL),
        ]
        // Remote login when host populated (or explicit remote flag)
        let remoteFlag: Bool = {
            if let b = item["remote"] as? Bool { return b }
            if let n = item["remote"] as? NSNumber { return n.boolValue }
            if let s = item["remote"] as? String {
                return ["true", "1", "yes"].contains(s.lowercased())
            }
            return !host.isEmpty && host != "localhost" && host != ":" && host != ":0"
        }()
        fields["auth.remote"] = remoteFlag ? "true" : "false"
        if !user.isEmpty {
            fields[FieldTaxonomy.userName] = user
            fields["auth.user"] = user
        }
        if !pid.isEmpty {
            fields["auth.pid"] = pid
        }

        var entities: [EntityID] = [
            EntityID(kind: .auth, value: "\(authType)|\(user)|\(tty)|\(host)"),
        ]
        if !user.isEmpty {
            entities.append(.user(name: user))
        }
        if !host.isEmpty {
            entities.append(EntityID(kind: .network, value: "host=\(host)"))
        }

        let eventTime = parseDate(item["timestamp"] ?? item["time"] ?? item["tv_sec"] ?? item["login_time"])
            ?? fileMTime(sourceURL)

        return EventEnvelope(
            eventTime: eventTime,
            collectedAt: Date(),
            source: .parser,
            sourcePlugin: "UTMPX",
            eventType: eventType,
            entityRefs: entities,
            fields: fields,
            rawRef: ArtifactRoot.pathKey(sourceURL),
            confidence: 0.91
        )
    }

    private func mapType(_ raw: String, item: [String: Any]) -> (eventType: String, authType: String) {
        let lower = raw.lowercased()
        // Numeric utmpx types (common): 7=USER_PROCESS, 8=DEAD_PROCESS, 6=INIT_PROCESS, 5=LOGIN_PROCESS
        if let n = Int(raw) {
            switch n {
            case 7: return ("auth.login", "USER_PROCESS")
            case 8: return ("auth.logout", "DEAD_PROCESS")
            case 6: return ("auth.session", "INIT_PROCESS")
            case 5: return ("auth.login", "LOGIN_PROCESS")
            case 2: return ("auth.boot", "BOOT_TIME")
            default: return ("auth.session", "UTMPX_\(n)")
            }
        }
        if lower.contains("logout") || lower.contains("dead") || lower == "out" {
            return ("auth.logout", raw.isEmpty ? "logout" : raw)
        }
        if lower.contains("login") || lower.contains("user_process") || lower == "in" {
            return ("auth.login", raw.isEmpty ? "login" : raw)
        }
        if lower.contains("boot") {
            return ("auth.boot", raw)
        }
        // Infer from action field
        if let action = stringValue(item["action"])?.lowercased() {
            if action.contains("out") || action == "logout" {
                return ("auth.logout", action)
            }
            if action.contains("in") || action == "login" {
                return ("auth.login", action)
            }
        }
        return ("auth.session", raw.isEmpty ? "session" : raw)
    }

    private func fileMTime(_ url: URL) -> Date {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs?[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)
    }
}
