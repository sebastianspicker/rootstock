import XCTest
@testable import RootstockBlueFX
@testable import RootstockBlueCore
@testable import RootstockBlueCase
@testable import RootstockBlueDetect

/// Wave-14 multi-plane red↔blue pairs (10 net-new themes beyond Wave-13).
final class Wave14MultiPlanePairTests: XCTestCase {
    var relativeRoot: URL { URL(fileURLWithPath: "Fixtures/artifacts/macos_sample") }
    var absoluteRoot: URL { relativeRoot.standardizedFileURL.resolvingSymlinksInPath() }
    private let wave14IDs = [
        "AUTOMATORWF",
        "ICLOUDDRIVEPATH",
        "BTCONTINUITY",
        "FONTVALIDATION",
        "QUICKLOOKCACHE",
        "DNSRESOLVER",
        "LSQUARANTINEDB",
        "PAMAUTHMODULE",
        "CRONATJOB",
        "NOTESMETADATA"
    ]
    private let wave14HardenControls = [
        "automator_workflow",
        "icloud_drive_path",
        "bluetooth_continuity_depth",
        "font_validation_dualuse",
        "quicklook_cache_depth",
        "dns_resolver_dualuse",
        "ls_quarantine_db_depth",
        "pam_auth_module",
        "cron_at_job_depth",
        "notes_metadata_plane"
    ]

    func testPluginRuntimeIncludesWave14Parsers() {
        let ids = Set(PluginRuntime().parserIDs())
        for id in wave14IDs { XCTAssertTrue(ids.contains(id), "missing \(id)") }
        for id in ["CALENDARREMINDERS", "HOMEBREWPKG", "CUPSPRINTDUAL", "SCREENCAPTUREPRIV"] {
            XCTAssertTrue(ids.contains(id), "regression \(id)")
        }
    }

    func testWave14ParsersEmitEventsFromFixtures() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let parsers: [any ArtifactParser] = [
            AutomatorWorkflowParser(),
            IcloudDrivePathParser(),
            BluetoothContinuityDepthParser(),
            FontValidationDualuseParser(),
            QuicklookCacheDepthParser(),
            DnsResolverDualuseParser(),
            LsQuarantineDbDepthParser(),
            PamAuthModuleParser(),
            CronAtJobDepthParser(),
            NotesMetadataPlaneParser()
        ]
        for parser in parsers {
            let events = try parser.parse(source: .directory(relativeRoot))
            XCTAssertFalse(events.isEmpty, "\(parser.manifest.id)")
            XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == parser.manifest.id })
            for e in events {
                let joined = e.fields.values.joined(separator: " ").lowercased()
                XCTAssertFalse(joined.contains("password=secret"))
                if let exp = e.fields.first(where: { $0.key.hasSuffix("secrets_exported") })?.value {
                    XCTAssertEqual(exp, "false")
                }
            }
        }
    }

    func testRelativeAbsoluteParityWave14() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let parsers: [any ArtifactParser] = [
            AutomatorWorkflowParser(),
            IcloudDrivePathParser(),
            BluetoothContinuityDepthParser(),
            FontValidationDualuseParser(),
            QuicklookCacheDepthParser(),
            DnsResolverDualuseParser(),
            LsQuarantineDbDepthParser(),
            PamAuthModuleParser(),
            CronAtJobDepthParser(),
            NotesMetadataPlaneParser()
        ]
        for parser in parsers {
            let rel = try parser.parse(source: .directory(relativeRoot))
            let abs = try parser.parse(source: .directory(absoluteRoot))
            XCTAssertEqual(rel.count, abs.count)
            XCTAssertFalse(rel.isEmpty)
        }
    }

    func testHardenAssessSyntheticEmitsTenWave14Controls() {
        let synthetic: [EventEnvelope] = [
            EventEnvelope(
                source: .parser, sourcePlugin: "AUTOMATORWF", eventType: "automator.workflow",
                fields: [
                    "automator.path": "/Users/alice/Library/Preferences/automator_workflow.json",
                    "automator.name": "Automator workflow delivery",
                    "automator.risk_tags": "workflow_surface,wave14",
                    "automator.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "ICLOUDDRIVEPATH", eventType: "icloud.drive_path",
                fields: [
                    "icldrv.path": "/Users/alice/Library/Preferences/icloud_drive_path.json",
                    "icldrv.name": "iCloud Drive path plane",
                    "icldrv.risk_tags": "icloud_path_surface,wave14",
                    "icldrv.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "BTCONTINUITY", eventType: "bluetooth.continuity",
                fields: [
                    "btcont.path": "/Users/alice/Library/Preferences/bluetooth_continuity_depth.json",
                    "btcont.name": "Bluetooth Continuity depth",
                    "btcont.risk_tags": "bt_continuity_surface,wave14",
                    "btcont.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "FONTVALIDATION", eventType: "font.validation",
                fields: [
                    "fontval.path": "/Users/alice/Library/Preferences/font_validation_dualuse.json",
                    "fontval.name": "Font validation dual-use",
                    "fontval.risk_tags": "font_surface,wave14",
                    "fontval.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "QUICKLOOKCACHE", eventType: "quicklook.cache",
                fields: [
                    "qlcache.path": "/Users/alice/Library/Preferences/quicklook_cache_depth.json",
                    "qlcache.name": "QuickLook cache depth",
                    "qlcache.risk_tags": "quicklook_surface,wave14",
                    "qlcache.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "DNSRESOLVER", eventType: "dns.resolver",
                fields: [
                    "dnsres.path": "/Users/alice/Library/Preferences/dns_resolver_dualuse.json",
                    "dnsres.name": "DNS resolver dual-use",
                    "dnsres.risk_tags": "dns_surface,wave14",
                    "dnsres.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "LSQUARANTINEDB", eventType: "ls.quarantine_db",
                fields: [
                    "lsqdb.path": "/Users/alice/Library/Preferences/ls_quarantine_db_depth.json",
                    "lsqdb.name": "LS QuarantineEvents depth",
                    "lsqdb.risk_tags": "quarantine_db_surface,wave14",
                    "lsqdb.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "PAMAUTHMODULE", eventType: "pam.module",
                fields: [
                    "pammod.path": "/Users/alice/Library/Preferences/pam_auth_module.json",
                    "pammod.name": "PAM auth module surface",
                    "pammod.risk_tags": "pam_surface,wave14",
                    "pammod.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "CRONATJOB", eventType: "cron.at_job",
                fields: [
                    "cronat.path": "/Users/alice/Library/Preferences/cron_at_job_depth.json",
                    "cronat.name": "Cron/at job depth",
                    "cronat.risk_tags": "cron_at_surface,wave14",
                    "cronat.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "NOTESMETADATA", eventType: "notes.metadata",
                fields: [
                    "notesmeta.path": "/Users/alice/Library/Preferences/notes_metadata_plane.json",
                    "notesmeta.name": "Notes metadata plane",
                    "notesmeta.risk_tags": "notes_surface,wave14",
                    "notesmeta.secrets_exported": "false",
                ]
            ),
        ]
        let findings = HardeningAssessment.assess(events: synthetic)
        let controls = Set(findings.map(\.control))
        for c in wave14HardenControls {
            XCTAssertTrue(controls.contains(c), "missing \(c); got \(controls.sorted())")
        }
        for f in findings where wave14HardenControls.contains(f.control) {
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertFalse((f.detail + f.remediation + f.evidence).lowercased().contains("password=secret"))
        }
    }

    func testWave14DetectionFixturesViaFixtureRunner() throws {
        let rulesDir = URL(fileURLWithPath: "Content/detections/samples")
        let fixturesDir = rulesDir.appendingPathComponent("fixtures")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: rulesDir.path))
        let wave14Rules = [
            "automator_workflow.yaml",
            "icloud_drive_path.yaml",
            "bluetooth_continuity_depth.yaml",
            "font_validation_dualuse.yaml",
            "quicklook_cache_depth.yaml",
            "dns_resolver_dualuse.yaml",
            "ls_quarantine_db_depth.yaml",
            "pam_auth_module.yaml",
            "cron_at_job_depth.yaml",
            "notes_metadata_plane.yaml"
        ]
        var hitIDs: [String] = []
        for name in wave14Rules {
            let rule = try RuleLoader.load(from: rulesDir.appendingPathComponent(name))
            let events = try FixtureRunner.loadEvents(from: fixturesDir.appendingPathComponent(rule.fixture))
            let findings = FixtureRunner.evaluate(rule: rule, events: events)
            XCTAssertFalse(findings.isEmpty, "\(rule.id)")
            XCTAssertEqual(findings.first?.ruleID, rule.id)
            hitIDs.append(rule.id)
        }
        print("WAVE14_DETECTION_RULE_IDS=" + hitIDs.joined(separator: ","))
        print("WAVE14_HARDEN_CONTROLS=" + wave14HardenControls.joined(separator: ","))
    }

    func testMissingMarkersReturnEmptyWave14() throws {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("wave14-empty-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }
        XCTAssertEqual(try AutomatorWorkflowParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try IcloudDrivePathParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try BluetoothContinuityDepthParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try FontValidationDualuseParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try QuicklookCacheDepthParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try DnsResolverDualuseParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try LsQuarantineDbDepthParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try PamAuthModuleParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try CronAtJobDepthParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try NotesMetadataPlaneParser().parse(source: .directory(tmp)).count, 0)
    }
}
