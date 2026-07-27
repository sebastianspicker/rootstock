import XCTest
@testable import RootstockBlueFX
@testable import RootstockBlueCore
@testable import RootstockBlueCase
@testable import RootstockBlueDetect

/// Wave-12 multi-plane red↔blue pairs (6 net-new themes beyond Wave-11).
final class Wave12MultiPlanePairTests: XCTestCase {
    var relativeRoot: URL {
        URL(fileURLWithPath: "Fixtures/artifacts/macos_sample")
    }

    var absoluteRoot: URL {
        relativeRoot.standardizedFileURL.resolvingSymlinksInPath()
    }

    private let wave12IDs = [
        "WEBLOCINETLOC",
        "MAILRULESAUTO",
        "UNIFIEDLOGOBS",
        "DOCKPERSIST",
        "OSASCRIPTSCPT",
        "NETWORKSHAREMOUNT"
    ]

    private let wave12HardenControls = [
        "webloc_inetloc_delivery",
        "mail_rules_automation",
        "unified_log_observation",
        "dock_persistence_surface",
        "osascript_scpt_delivery",
        "network_share_mount"
    ]

    func testPluginRuntimeIncludesWave12Parsers() {
        let ids = Set(PluginRuntime().parserIDs())
        for id in wave12IDs {
            XCTAssertTrue(ids.contains(id), "defaultTier1 missing wave-12 parser \(id)")
        }
        // Regression: Wave-11 still present
        for id in ["URLSCHEMEHANDLER", "LAUNCHDOVERRIDEDEPTH", "BROWSEREXTDUALUSE", "SHORTCUTSAPPINTENTS"] {
            XCTAssertTrue(ids.contains(id), "regression: missing wave-11 \(id)")
        }
    }

    func testWave12ParsersEmitEventsFromFixtures() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let parsers: [any ArtifactParser] = [
            WeblocInetlocParser(),
            MailRulesAutomationParser(),
            UnifiedLogObservationParser(),
            DockPersistenceSurfaceParser(),
            OsascriptScptDeliveryParser(),
            NetworkShareMountParser()
        ]
        for parser in parsers {
            let events = try parser.parse(source: .directory(relativeRoot))
            XCTAssertFalse(events.isEmpty, "\(parser.manifest.id) expected events")
            XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == parser.manifest.id })
            for e in events {
                let joined = e.fields.values.joined(separator: " ").lowercased()
                XCTAssertFalse(joined.contains("password=secret"), "\(parser.manifest.id) no secrets")
                if let exported = e.fields.first(where: { $0.key.hasSuffix("secrets_exported") })?.value {
                    XCTAssertEqual(exported, "false")
                }
            }
        }
    }

    func testRelativeAbsoluteParityWave12() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let parsers: [any ArtifactParser] = [
            WeblocInetlocParser(),
            MailRulesAutomationParser(),
            UnifiedLogObservationParser(),
            DockPersistenceSurfaceParser(),
            OsascriptScptDeliveryParser(),
            NetworkShareMountParser()
        ]
        for parser in parsers {
            let rel = try parser.parse(source: .directory(relativeRoot))
            let abs = try parser.parse(source: .directory(absoluteRoot))
            XCTAssertEqual(rel.count, abs.count, "\(parser.manifest.id) relative/absolute mismatch")
            XCTAssertFalse(rel.isEmpty)
        }
    }

    func testHardenAssessSyntheticEmitsSixWave12Controls() {
        let synthetic: [EventEnvelope] = [
            EventEnvelope(
                source: .parser,
                sourcePlugin: "WEBLOCINETLOC",
                eventType: "webloc.delivery",
                fields: [
                    "webloc.path": "/Users/alice/Library/Preferences/webloc_inetloc_delivery.json",
                    "webloc.name": "Webloc/inetloc delivery",
                    "webloc.risk_tags": "delivery_surface,wave12",
                    "webloc.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser,
                sourcePlugin: "MAILRULESAUTO",
                eventType: "mail.rules",
                fields: [
                    "mail_rules.path": "/Users/alice/Library/Preferences/mail_rules_automation.json",
                    "mail_rules.name": "Mail rules automation",
                    "mail_rules.risk_tags": "rules_surface,wave12",
                    "mail_rules.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser,
                sourcePlugin: "UNIFIEDLOGOBS",
                eventType: "unified_log.observation",
                fields: [
                    "ulog.path": "/Users/alice/Library/Preferences/unified_log_observation.json",
                    "ulog.name": "Unified log observation",
                    "ulog.risk_tags": "observation_surface,wave12",
                    "ulog.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser,
                sourcePlugin: "DOCKPERSIST",
                eventType: "dock.persistence",
                fields: [
                    "dock.path": "/Users/alice/Library/Preferences/dock_persistence_surface.json",
                    "dock.name": "Dock persistence dual-use",
                    "dock.risk_tags": "dock_surface,wave12",
                    "dock.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser,
                sourcePlugin: "OSASCRIPTSCPT",
                eventType: "osascript.scpt",
                fields: [
                    "osa.path": "/Users/alice/Library/Preferences/osascript_scpt_delivery.json",
                    "osa.name": "OSA/scpt delivery",
                    "osa.risk_tags": "scpt_surface,wave12",
                    "osa.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser,
                sourcePlugin: "NETWORKSHAREMOUNT",
                eventType: "network.share_mount",
                fields: [
                    "share.path": "/Users/alice/Library/Preferences/network_share_mount.json",
                    "share.name": "Network share mount",
                    "share.risk_tags": "share_surface,wave12",
                    "share.secrets_exported": "false",
                ]
            ),
        ]
        let findings = HardeningAssessment.assess(events: synthetic)
        let controls = Set(findings.map(\.control))
        for c in wave12HardenControls {
            XCTAssertTrue(controls.contains(c), "missing harden control \(c); got \(controls.sorted())")
        }
        for f in findings where wave12HardenControls.contains(f.control) {
            XCTAssertFalse(f.remediation.isEmpty, "\(f.control) remediation")
            let blob = (f.detail + f.remediation + f.evidence).lowercased()
            XCTAssertFalse(blob.contains("password=secret"), "\(f.control) no secrets")
        }
    }

    func testWave12DetectionFixturesViaFixtureRunner() throws {
        let rulesDir = URL(fileURLWithPath: "Content/detections/samples")
        let fixturesDir = rulesDir.appendingPathComponent("fixtures")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: rulesDir.path))

        let wave12Rules = [
            "webloc_inetloc_delivery.yaml",
            "mail_rules_automation.yaml",
            "unified_log_observation.yaml",
            "dock_persistence_surface.yaml",
            "osascript_scpt_delivery.yaml",
            "network_share_mount.yaml"
        ]
        var hitIDs: [String] = []
        for name in wave12Rules {
            let ruleURL = rulesDir.appendingPathComponent(name)
            XCTAssertTrue(FileManager.default.fileExists(atPath: ruleURL.path), "missing rule \(name)")
            let rule = try RuleLoader.load(from: ruleURL)
            let fixtureURL = fixturesDir.appendingPathComponent(rule.fixture)
            XCTAssertTrue(FileManager.default.fileExists(atPath: fixtureURL.path), "missing fixture \(rule.fixture)")
            let events = try FixtureRunner.loadEvents(from: fixtureURL)
            let findings = FixtureRunner.evaluate(rule: rule, events: events)
            XCTAssertFalse(findings.isEmpty, "rule \(rule.id) produced zero findings")
            XCTAssertEqual(findings.first?.ruleID, rule.id)
            hitIDs.append(rule.id)
        }
        print("WAVE12_DETECTION_RULE_IDS=\(hitIDs.joined(separator: ","))")
        print("WAVE12_HARDEN_CONTROLS=\(wave12HardenControls.joined(separator: ","))")
    }

    func testMissingMarkersReturnEmptyWave12() throws {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("wave12-empty-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }
        XCTAssertEqual(try WeblocInetlocParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try MailRulesAutomationParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try UnifiedLogObservationParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try DockPersistenceSurfaceParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try OsascriptScptDeliveryParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try NetworkShareMountParser().parse(source: .directory(tmp)).count, 0)
    }
}
