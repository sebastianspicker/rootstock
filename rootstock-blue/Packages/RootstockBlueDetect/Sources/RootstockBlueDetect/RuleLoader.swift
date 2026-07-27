/// RuleLoader - Rootstock product source (see package README for product doctrine).
import Foundation
import RootstockBlueCore

public struct DetectionRule: Codable, Sendable {
    public var id: String
    public var title: String
    public var severity: String
    public var description: String
    public var attackTechniques: [String]
    public var match: Match
    public var fixture: String
    public var atomicMapping: String?

    public struct Match: Codable, Sendable {
        public var eventType: String?
        public var fieldEquals: [String: String]?
        public var fieldContains: [String: String]?

        public init(
            eventType: String? = nil,
            fieldEquals: [String: String]? = nil,
            fieldContains: [String: String]? = nil
        ) {
            self.eventType = eventType
            self.fieldEquals = fieldEquals
            self.fieldContains = fieldContains
        }
    }
}

public enum RuleLoader {
    public static func load(from url: URL) throws -> DetectionRule {
        let text = try String(contentsOf: url, encoding: .utf8)
        return try parseSimpleYAML(text, fileName: url.lastPathComponent)
    }

    public static func loadDirectory(_ dir: URL) throws -> [DetectionRule] {
        let fm = FileManager.default
        guard let items = try? fm.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil) else {
            return []
        }
        return try items
            .filter { $0.pathExtension == "yaml" || $0.pathExtension == "yml" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
            .map { try load(from: $0) }
    }

    private static func parseSimpleYAML(_ text: String, fileName: String) throws -> DetectionRule {
        var id: String?
        var title: String?
        var severity = "medium"
        var description = ""
        var fixture: String?
        var atomicMapping: String?
        var techniques: [String] = []
        var eventType: String?
        var fieldEquals: [String: String] = [:]
        var fieldContains: [String: String] = [:]

        enum Section {
            case root
            case attack
            case match
            case fieldEquals
            case fieldContains
        }
        var section: Section = .root

        for rawLine in text.components(separatedBy: .newlines) {
            let withoutComment = rawLine.split(separator: "#", maxSplits: 1).first.map(String.init) ?? rawLine
            if withoutComment.trimmingCharacters(in: .whitespaces).isEmpty { continue }

            let indent = withoutComment.prefix(while: { $0 == " " }).count
            let trimmed = withoutComment.trimmingCharacters(in: .whitespaces)

            // List items
            if trimmed.hasPrefix("- ") {
                let item = unquote(String(trimmed.dropFirst(2)))
                if section == .attack {
                    techniques.append(item)
                }
                continue
            }

            guard let colon = trimmed.firstIndex(of: ":") else { continue }
            let key = String(trimmed[..<colon]).trimmingCharacters(in: .whitespaces)
            let value = unquote(String(trimmed[trimmed.index(after: colon)...]).trimmingCharacters(in: .whitespaces))

            // Section switches (indent 0 = root keys)
            if indent == 0 {
                switch key {
                case "id":
                    id = value
                    section = .root
                case "title":
                    title = value
                    section = .root
                case "severity":
                    severity = value.isEmpty ? severity : value
                    section = .root
                case "description":
                    description = value
                    section = .root
                case "fixture":
                    fixture = value
                    section = .root
                case "atomic_mapping":
                    atomicMapping = value
                    section = .root
                case "attack_techniques":
                    section = .attack
                    if !value.isEmpty { techniques.append(value) }
                case "match":
                    section = .match
                default:
                    section = .root
                }
                continue
            }

            // Nested under match (indent 2+)
            if section == .match || section == .fieldEquals || section == .fieldContains {
                if indent == 2 {
                    switch key {
                    case "event_type":
                        eventType = value
                        section = .match
                    case "field_equals":
                        section = .fieldEquals
                    case "field_contains":
                        section = .fieldContains
                    default:
                        break
                    }
                } else if indent >= 4 {
                    if section == .fieldEquals {
                        fieldEquals[key] = value
                    } else if section == .fieldContains {
                        fieldContains[key] = value
                    }
                }
            }
        }

        guard let id, let title, let fixture else {
            throw RootstockBlueError.detectionRuleInvalid("missing id/title/fixture in \(fileName)")
        }

        return DetectionRule(
            id: id,
            title: title,
            severity: severity,
            description: description,
            attackTechniques: techniques,
            match: DetectionRule.Match(
                eventType: eventType,
                fieldEquals: fieldEquals.isEmpty ? nil : fieldEquals,
                fieldContains: fieldContains.isEmpty ? nil : fieldContains
            ),
            fixture: fixture,
            atomicMapping: atomicMapping
        )
    }

    private static func unquote(_ s: String) -> String {
        var t = s.trimmingCharacters(in: .whitespaces)
        if t.count >= 2 {
            if (t.hasPrefix("\"") && t.hasSuffix("\"")) || (t.hasPrefix("'") && t.hasSuffix("'")) {
                t.removeFirst()
                t.removeLast()
            }
        }
        return t
    }
}
