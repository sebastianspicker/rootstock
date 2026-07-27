import Foundation
import RootstockBlueCore

/// Integrate with Santa - do not reimplement the allowlist decision engine.
/// Pure EventEnvelope production (no Case dependency); CLI/case layer writes results.
public enum SantaBridge {
    public static let status = "integrate_only"

    /// Ingest Santa decision logs (JSONL preferred; also accepts single JSON objects per line).
    /// Fixture shape:
    /// `{"decision":"DENY","path":"/tmp/evil_payload","sha256":"abc","reason":"BLOCKLIST","timestamp":"2026-01-15T12:00:00Z"}`
    public static func eventsFromSantaLog(at url: URL) throws -> [EventEnvelope] {
        let data = try Data(contentsOf: url)
        guard let text = String(data: data, encoding: .utf8) else {
            throw RootstockBlueError.io("Santa log is not UTF-8: \(url.path)")
        }

        var events: [EventEnvelope] = []
        let iso = ISO8601DateFormatter()
        iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let isoBasic = ISO8601DateFormatter()
        isoBasic.formatOptions = [.withInternetDateTime]

        let lines = text.components(separatedBy: .newlines)
        for (lineNo, rawLine) in lines.enumerated() {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty || line.hasPrefix("#") { continue }

            // JSONL object per line
            if line.hasPrefix("{") {
                guard let lineData = line.data(using: String.Encoding.utf8),
                      let obj = try? JSONSerialization.jsonObject(with: lineData) as? [String: Any]
                else {
                    throw RootstockBlueError.io("Santa log JSON parse failed at line \(lineNo + 1)")
                }
                if let event = eventFromDecisionObject(obj, iso: iso, isoBasic: isoBasic, rawRef: "\(url.path)#L\(lineNo + 1)") {
                    events.append(event)
                }
                continue
            }

            // Simple CSV: decision,path,sha256,reason,timestamp
            let cols = line.components(separatedBy: ",").map {
                $0.trimmingCharacters(in: .whitespaces)
            }
            if cols.count >= 2 {
                var obj: [String: Any] = [
                    "decision": cols[0],
                    "path": cols[1],
                ]
                if cols.count > 2 { obj["sha256"] = cols[2] }
                if cols.count > 3 { obj["reason"] = cols[3] }
                if cols.count > 4 { obj["timestamp"] = cols[4] }
                if let event = eventFromDecisionObject(obj, iso: iso, isoBasic: isoBasic, rawRef: "\(url.path)#L\(lineNo + 1)") {
                    events.append(event)
                }
            }
        }

        if events.isEmpty {
            throw RootstockBlueError.io("No Santa decisions parsed from \(url.path)")
        }
        return events
    }

    /// Suggest a manual Santa rule snippet from an event (review required).
    public static func suggestRule(from event: EventEnvelope) -> String {
        let path = event.fields[FieldTaxonomy.processPath]
            ?? event.fields[FieldTaxonomy.filePath]
            ?? "unknown"
        let team = event.fields[FieldTaxonomy.processTeamID] ?? ""
        let sha = event.fields["santa.sha256"] ?? event.fields["file.sha256"] ?? ""
        return """
        # Suggested Santa rule (manual review)
        # path: \(path)
        # teamid: \(team)
        # sha256: \(sha)
        """
    }

    // MARK: - Private

    private static func eventFromDecisionObject(
        _ obj: [String: Any],
        iso: ISO8601DateFormatter,
        isoBasic: ISO8601DateFormatter,
        rawRef: String
    ) -> EventEnvelope? {
        let decision = stringField(obj, keys: ["decision", "Decision", "action"]) ?? "UNKNOWN"
        let path = stringField(obj, keys: ["path", "file_path", "executable", "filePath"]) ?? ""
        let sha256 = stringField(obj, keys: ["sha256", "SHA256", "hash"]) ?? ""
        let reason = stringField(obj, keys: ["reason", "Reason", "rule_type"]) ?? ""
        let tsRaw = stringField(obj, keys: ["timestamp", "time", "ts", "decision_time"])

        var eventTime = Date()
        if let tsRaw {
            if let d = iso.date(from: tsRaw) ?? isoBasic.date(from: tsRaw) {
                eventTime = d
            }
        }

        var entityRefs: [EntityID] = []
        if !path.isEmpty {
            entityRefs.append(.file(path: path))
            entityRefs.append(.process(pid: 0, path: path))
        } else {
            entityRefs.append(EntityID(kind: .host, value: "santa=decision"))
        }

        var fields: [String: String] = [
            "santa.decision": decision,
            "santa.reason": reason,
            FieldTaxonomy.eventType: "santa.decision",
        ]
        if !path.isEmpty {
            fields[FieldTaxonomy.processPath] = path
            fields[FieldTaxonomy.filePath] = path
            fields["process.path"] = path
        }
        if !sha256.isEmpty {
            fields["santa.sha256"] = sha256
            fields["file.sha256"] = sha256
        }
        if let rule = stringField(obj, keys: ["rule", "rule_name"]) {
            fields["santa.rule"] = rule
        }

        return EventEnvelope(
            eventTime: eventTime,
            collectedAt: Date(),
            source: .santa,
            sourcePlugin: "SANTA",
            eventType: "santa.decision",
            entityRefs: entityRefs,
            fields: fields,
            rawRef: rawRef,
            confidence: 0.95
        )
    }

    private static func stringField(_ obj: [String: Any], keys: [String]) -> String? {
        for k in keys {
            if let s = obj[k] as? String, !s.isEmpty { return s }
            if let n = obj[k] as? NSNumber { return n.stringValue }
        }
        return nil
    }
}
