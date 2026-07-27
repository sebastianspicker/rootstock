import Foundation

/// Provenance of a normalized event in a case.
public enum EventSource: String, Codable, Sendable {
    case es
    case parser
    case uls
    case santa
    case collect
    case network
    case synthetic
}

/// JSONL-friendly event wrapper shared by live ES, offline parsers, and fixtures.
public struct EventEnvelope: Codable, Sendable, Identifiable {
    public var id: UUID
    public var eventTime: Date
    public var collectedAt: Date
    public var source: EventSource
    public var sourcePlugin: String
    public var eventType: String
    public var entityRefs: [EntityID]
    public var fields: [String: String]
    public var rawRef: String?
    public var confidence: Double

    public init(
        id: UUID = UUID(),
        eventTime: Date = Date(),
        collectedAt: Date = Date(),
        source: EventSource,
        sourcePlugin: String,
        eventType: String,
        entityRefs: [EntityID] = [],
        fields: [String: String] = [:],
        rawRef: String? = nil,
        confidence: Double = 1.0
    ) {
        self.id = id
        self.eventTime = eventTime
        self.collectedAt = collectedAt
        self.source = source
        self.sourcePlugin = sourcePlugin
        self.eventType = eventType
        self.entityRefs = entityRefs
        self.fields = fields
        self.rawRef = rawRef
        self.confidence = confidence
    }
}

/// Decode/encode `EventEnvelope` rows as JSONL (one ISO-8601 JSON object per line).
public enum EventJSONL {
    public static func decode(text: String, skipInvalid: Bool = false) throws -> [EventEnvelope] {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        var events: [EventEnvelope] = []
        for line in text.split(whereSeparator: \.isNewline) {
            let s = String(line).trimmingCharacters(in: .whitespaces)
            guard !s.isEmpty, let data = s.data(using: .utf8) else { continue }
            if skipInvalid {
                if let e = try? decoder.decode(EventEnvelope.self, from: data) {
                    events.append(e)
                }
            } else {
                events.append(try decoder.decode(EventEnvelope.self, from: data))
            }
        }
        return events
    }

    public static func decode(contentsOf url: URL, skipInvalid: Bool = false) throws -> [EventEnvelope] {
        let text = try String(contentsOf: url, encoding: .utf8)
        return try decode(text: text, skipInvalid: skipInvalid)
    }

    public static func encode(_ events: [EventEnvelope]) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        var data = Data()
        for event in events {
            data.append(try encoder.encode(event))
            data.append(contentsOf: "\n".utf8)
        }
        return data
    }

    public static func encodeLine(_ event: EventEnvelope) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.sortedKeys]
        var data = try encoder.encode(event)
        data.append(contentsOf: "\n".utf8)
        return data
    }
}

/// Detection finding produced by rules against events.
public struct Finding: Codable, Sendable, Identifiable {
    public var id: UUID
    public var ruleID: String
    public var title: String
    public var severity: String
    public var eventIDs: [UUID]
    public var attackTechniques: [String]
    public var evidenceSummary: String
    public var createdAt: Date

    public init(
        id: UUID = UUID(),
        ruleID: String,
        title: String,
        severity: String,
        eventIDs: [UUID],
        attackTechniques: [String] = [],
        evidenceSummary: String,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.ruleID = ruleID
        self.title = title
        self.severity = severity
        self.eventIDs = eventIDs
        self.attackTechniques = attackTechniques
        self.evidenceSummary = evidenceSummary
        self.createdAt = createdAt
    }
}
