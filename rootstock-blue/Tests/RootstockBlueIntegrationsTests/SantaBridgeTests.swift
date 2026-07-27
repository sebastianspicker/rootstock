import XCTest
@testable import RootstockBlueIntegrations
@testable import RootstockBlueCore

final class SantaBridgeTests: XCTestCase {
    var fixtureURL: URL {
        URL(fileURLWithPath: "Fixtures/santa/decisions.jsonl")
    }

    func testEventsFromSantaLogJSONL() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: fixtureURL.path))
        let events = try SantaBridge.eventsFromSantaLog(at: fixtureURL)
        XCTAssertEqual(events.count, 2)
        XCTAssertTrue(events.allSatisfy { $0.source == .santa })
        XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == "SANTA" })
        XCTAssertTrue(events.allSatisfy { $0.eventType == "santa.decision" })
        XCTAssertTrue(events.allSatisfy { !$0.entityRefs.isEmpty })

        let deny = events.first { ($0.fields["santa.decision"] ?? "") == "DENY" }
        XCTAssertNotNil(deny)
        XCTAssertEqual(deny?.fields["santa.reason"], "BLOCKLIST")
        XCTAssertEqual(deny?.fields[FieldTaxonomy.processPath], "/tmp/evil_payload")
        XCTAssertEqual(deny?.fields["santa.sha256"], "abc123def456")
        XCTAssertTrue(deny?.entityRefs.contains { $0.kind == .file } == true)

        let allow = events.first { ($0.fields["santa.decision"] ?? "") == "ALLOW" }
        XCTAssertNotNil(allow)
        XCTAssertEqual(allow?.fields["santa.reason"], "ALLOWLIST")
        XCTAssertTrue((allow?.fields[FieldTaxonomy.processPath] ?? "").contains("Safari"))
    }

    func testSuggestRuleIncludesPath() {
        let event = EventEnvelope(
            source: .santa,
            sourcePlugin: "SANTA",
            eventType: "santa.decision",
            fields: [
                FieldTaxonomy.processPath: "/tmp/evil_payload",
                "santa.sha256": "abc",
            ]
        )
        let rule = SantaBridge.suggestRule(from: event)
        XCTAssertTrue(rule.contains("/tmp/evil_payload"))
        XCTAssertTrue(rule.contains("abc"))
    }

    func testOsqueryRowIncludesSourcePlugin() {
        let event = EventEnvelope(
            source: .santa,
            sourcePlugin: "SANTA",
            eventType: "santa.decision",
            fields: ["santa.decision": "DENY"]
        )
        let row = OsqueryExport.asOsqueryRow(event)
        XCTAssertEqual(row["rootstock_blue_source_plugin"], "SANTA")
        XCTAssertEqual(row["rootstock_blue_source"], "santa")
    }
}
