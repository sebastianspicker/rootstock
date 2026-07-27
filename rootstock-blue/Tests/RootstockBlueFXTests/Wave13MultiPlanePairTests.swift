import XCTest
@testable import RootstockBlueFX
@testable import RootstockBlueCore
@testable import RootstockBlueCase
@testable import RootstockBlueDetect

/// Wave-13 multi-plane red↔blue pairs (5 net-new themes beyond Wave-12).
final class Wave13MultiPlanePairTests: XCTestCase {
    var relativeRoot: URL { URL(fileURLWithPath: "Fixtures/artifacts/macos_sample") }
    var absoluteRoot: URL { relativeRoot.standardizedFileURL.resolvingSymlinksInPath() }

    private let wave13IDs = [
        "CALENDARREMINDERS",
        "GKASSESSMENTHIST",
        "HOMEBREWPKG",
        "CUPSPRINTDUAL",
        "SCREENCAPTUREPRIV"
    ]
    private let wave13HardenControls = [
        "calendar_reminders_automation",
        "gatekeeper_assessment_history",
        "homebrew_package_dualuse",
        "cups_print_dualuse",
        "screencapture_privacy_dualuse"
    ]

    func testPluginRuntimeIncludesWave13Parsers() {
        let ids = Set(PluginRuntime().parserIDs())
        for id in wave13IDs {
            XCTAssertTrue(ids.contains(id), "missing wave-13 parser \(id)")
        }
        for id in ["WEBLOCINETLOC", "MAILRULESAUTO", "UNIFIEDLOGOBS", "DOCKPERSIST", "OSASCRIPTSCPT", "NETWORKSHAREMOUNT"] {
            XCTAssertTrue(ids.contains(id), "regression missing wave-12 \(id)")
        }
    }

    func testWave13ParsersEmitEventsFromFixtures() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let parsers: [any ArtifactParser] = [
            CalendarRemindersAutomationParser(),
            GatekeeperAssessmentHistoryParser(),
            HomebrewPackageDualUseParser(),
            CupsPrintDualUseParser(),
            ScreenCapturePrivacyDualUseParser()
        ]
        for parser in parsers {
            let events = try parser.parse(source: .directory(relativeRoot))
            XCTAssertFalse(events.isEmpty, "\(parser.manifest.id) expected events")
            XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == parser.manifest.id })
            for e in events {
                let joined = e.fields.values.joined(separator: " ").lowercased()
                XCTAssertFalse(joined.contains("password=secret"))
                if let exported = e.fields.first(where: { $0.key.hasSuffix("secrets_exported") })?.value {
                    XCTAssertEqual(exported, "false")
                }
            }
        }
    }

    func testRelativeAbsoluteParityWave13() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let parsers: [any ArtifactParser] = [
            CalendarRemindersAutomationParser(),
            GatekeeperAssessmentHistoryParser(),
            HomebrewPackageDualUseParser(),
            CupsPrintDualUseParser(),
            ScreenCapturePrivacyDualUseParser()
        ]
        for parser in parsers {
            let rel = try parser.parse(source: .directory(relativeRoot))
            let abs = try parser.parse(source: .directory(absoluteRoot))
            XCTAssertEqual(rel.count, abs.count)
            XCTAssertFalse(rel.isEmpty)
        }
    }

    func testHardenAssessSyntheticEmitsFiveWave13Controls() {
        let synthetic: [EventEnvelope] = [
            EventEnvelope(
                source: .parser,
                sourcePlugin: "CALENDARREMINDERS",
                eventType: "calendar.reminders",
                fields: [
                    "calrem.path": "/Users/alice/Library/Preferences/calendar_reminders_automation.json",
                    "calrem.name": "Calendar/Reminders automation",
                    "calrem.risk_tags": "automation_surface,wave13",
                    "calrem.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser,
                sourcePlugin: "GKASSESSMENTHIST",
                eventType: "gatekeeper.assessment",
                fields: [
                    "gkh.path": "/Users/alice/Library/Preferences/gatekeeper_assessment_history.json",
                    "gkh.name": "Gatekeeper assessment history",
                    "gkh.risk_tags": "assessment_surface,wave13",
                    "gkh.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser,
                sourcePlugin: "HOMEBREWPKG",
                eventType: "homebrew.package",
                fields: [
                    "brew.path": "/Users/alice/Library/Preferences/homebrew_package_dualuse.json",
                    "brew.name": "Homebrew package dual-use",
                    "brew.risk_tags": "package_surface,wave13",
                    "brew.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser,
                sourcePlugin: "CUPSPRINTDUAL",
                eventType: "cups.print",
                fields: [
                    "cups.path": "/Users/alice/Library/Preferences/cups_print_dualuse.json",
                    "cups.name": "CUPS printer dual-use",
                    "cups.risk_tags": "print_surface,wave13",
                    "cups.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser,
                sourcePlugin: "SCREENCAPTUREPRIV",
                eventType: "screencapture.privacy",
                fields: [
                    "scpriv.path": "/Users/alice/Library/Preferences/screencapture_privacy_dualuse.json",
                    "scpriv.name": "ScreenCapture privacy dual-use",
                    "scpriv.risk_tags": "capture_surface,wave13",
                    "scpriv.secrets_exported": "false",
                ]
            ),
        ]
        let findings = HardeningAssessment.assess(events: synthetic)
        let controls = Set(findings.map(\.control))
        for c in wave13HardenControls {
            XCTAssertTrue(controls.contains(c), "missing harden \(c); got \(controls.sorted())")
        }
        for f in findings where wave13HardenControls.contains(f.control) {
            XCTAssertFalse(f.remediation.isEmpty)
            let blob = (f.detail + f.remediation + f.evidence).lowercased()
            XCTAssertFalse(blob.contains("password=secret"))
        }
    }

    func testWave13DetectionFixturesViaFixtureRunner() throws {
        let rulesDir = URL(fileURLWithPath: "Content/detections/samples")
        let fixturesDir = rulesDir.appendingPathComponent("fixtures")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: rulesDir.path))
        let wave13Rules = [
            "calendar_reminders_automation.yaml",
            "gatekeeper_assessment_history.yaml",
            "homebrew_package_dualuse.yaml",
            "cups_print_dualuse.yaml",
            "screencapture_privacy_dualuse.yaml"
        ]
        var hitIDs: [String] = []
        for name in wave13Rules {
            let ruleURL = rulesDir.appendingPathComponent(name)
            XCTAssertTrue(FileManager.default.fileExists(atPath: ruleURL.path))
            let rule = try RuleLoader.load(from: ruleURL)
            let fixtureURL = fixturesDir.appendingPathComponent(rule.fixture)
            XCTAssertTrue(FileManager.default.fileExists(atPath: fixtureURL.path))
            let events = try FixtureRunner.loadEvents(from: fixtureURL)
            let findings = FixtureRunner.evaluate(rule: rule, events: events)
            XCTAssertFalse(findings.isEmpty, "rule \(rule.id) zero findings")
            XCTAssertEqual(findings.first?.ruleID, rule.id)
            hitIDs.append(rule.id)
        }
        print("WAVE13_DETECTION_RULE_IDS=" + hitIDs.joined(separator: ","))
        print("WAVE13_HARDEN_CONTROLS=" + wave13HardenControls.joined(separator: ","))
    }

    func testMissingMarkersReturnEmptyWave13() throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("wave13-empty-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }
        XCTAssertEqual(try CalendarRemindersAutomationParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try GatekeeperAssessmentHistoryParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try HomebrewPackageDualUseParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try CupsPrintDualUseParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try ScreenCapturePrivacyDualUseParser().parse(source: .directory(tmp)).count, 0)
    }
}
