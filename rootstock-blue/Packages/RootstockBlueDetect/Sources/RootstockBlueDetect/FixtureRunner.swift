/// FixtureRunner - Rootstock product source (see package README for product doctrine).
import Foundation
import RootstockBlueCore

public enum FixtureRunner {
    public static func loadEvents(from url: URL) throws -> [EventEnvelope] {
        try EventJSONL.decode(contentsOf: url)
    }

    public static func evaluate(rule: DetectionRule, events: [EventEnvelope]) -> [Finding] {
        var findings: [Finding] = []
        for event in events {
            if matches(rule: rule, event: event) {
                findings.append(
                    Finding(
                        ruleID: rule.id,
                        title: rule.title,
                        severity: rule.severity,
                        eventIDs: [event.id],
                        attackTechniques: rule.attackTechniques,
                        evidenceSummary: "Matched \(event.eventType) via \(rule.id)"
                    )
                )
            }
        }
        return findings
    }

    public static func matches(rule: DetectionRule, event: EventEnvelope) -> Bool {
        if let et = rule.match.eventType, et != event.eventType {
            return false
        }
        if let eq = rule.match.fieldEquals {
            for (k, v) in eq {
                if event.fields[k] != v { return false }
            }
        }
        if let contains = rule.match.fieldContains {
            for (k, v) in contains {
                guard let actual = event.fields[k], actual.contains(v) else { return false }
            }
        }
        return rule.match.eventType != nil
            || rule.match.fieldEquals != nil
            || rule.match.fieldContains != nil
    }
}
