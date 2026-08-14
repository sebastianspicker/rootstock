import XCTest
@testable import RootstockBlueFX
@testable import RootstockBlueCore
@testable import RootstockBlueCase
@testable import RootstockBlueDetect

/// Wave-16 multi-plane red↔blue pairs (25 themes / 50 half-pairs beyond Wave-15).
final class Wave16MultiPlanePairTests: XCTestCase {
    var relativeRoot: URL { URL(fileURLWithPath: "Fixtures/artifacts/macos_sample") }
    var absoluteRoot: URL { relativeRoot.standardizedFileURL.resolvingSymlinksInPath() }
    func testPluginRuntimeIncludesWave16Parsers() {
        let registrations = Wave16ParserRegistry.registrations
        let ids = Set(PluginRuntime().parserIDs())
        XCTAssertEqual(registrations.count, 25)
        XCTAssertEqual(Array(PluginRuntime().parserIDs().suffix(registrations.count)), Wave16ParserRegistry.expectedIDs)
        XCTAssertEqual(
            PluginRuntime.defaultForensics().map(\.manifest.id),
            PluginRuntime.defaultTier1().map(\.manifest.id)
        )
        for registration in registrations {
            let parser = registration.parser()
            XCTAssertEqual(parser.manifest.id, registration.manifest.id)
            XCTAssertEqual(parser.manifest.tier, registration.manifest.tier)
            XCTAssertEqual(parser.manifest.description, registration.manifest.description)
        }
        XCTAssertTrue(ids.contains("SHELLPLUGINMGR"))
        XCTAssertTrue(ids.contains("PHOTOSLIBRARY"))
    }

    func testWave16RegistryResolvesEveryIDAndWrappersUseItsContract() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let registrations = Wave16ParserRegistry.registrations
        XCTAssertEqual(Set(Wave16ParserRegistry.expectedIDs).count, registrations.count)

        for registration in registrations {
            let resolved = Wave16ParserRegistry.registration(for: registration.manifest.id)
            XCTAssertEqual(resolved.manifest.id, registration.manifest.id)
            XCTAssertEqual(resolved.spec, registration.spec)

            let wrapperEvents = try registration.parser().parse(source: .directory(relativeRoot))
            let registryEvents = Wave16ParserSupport.parse(source: .directory(relativeRoot), spec: resolved.spec)
            XCTAssertEqual(wrapperEvents.map(\.fields), registryEvents.map(\.fields), registration.manifest.id)
            XCTAssertEqual(wrapperEvents.map(\.entityRefs), registryEvents.map(\.entityRefs), registration.manifest.id)
            XCTAssertEqual(wrapperEvents.map(\.rawRef), registryEvents.map(\.rawRef), registration.manifest.id)
        }
    }

    func testWave16ParsersEmitEventsFromFixtures() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        for parser in Wave16ParserRegistry.parsers {
            let events = try parser.parse(source: .directory(relativeRoot))
            XCTAssertFalse(events.isEmpty, "\(parser.manifest.id)")
            XCTAssertTrue(events.allSatisfy { $0.sourcePlugin == parser.manifest.id })
            for e in events {
                XCTAssertFalse(e.fields.values.joined(separator: " ").lowercased().contains("password=secret"))
                if let exp = e.fields.first(where: { $0.key.hasSuffix("secrets_exported") })?.value {
                    XCTAssertEqual(exp, "false")
                }
            }
        }
    }

    func testRelativeAbsoluteParityWave16() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        for parser in Wave16ParserRegistry.parsers {
            let rel = try parser.parse(source: .directory(relativeRoot))
            let abs = try parser.parse(source: .directory(absoluteRoot))
            XCTAssertEqual(rel.count, abs.count, parser.manifest.id)
            XCTAssertFalse(rel.isEmpty)
        }
    }

    func testHardenAssessSyntheticEmitsTwentyFiveWave16Controls() {
        let registrations = Wave16ParserRegistry.registrations
        let synthetic = HardeningTestFixtures.planeEvents(wave: "wave16", specifications: registrations.map {
            .init(
                plugin: $0.manifest.id,
                eventType: $0.spec.eventType,
                fieldPrefix: $0.spec.fieldPrefix,
                fileName: "\($0.spec.fileStem).json",
                name: $0.hardeningName,
                riskTag: $0.spec.defaultRiskTag
            )
        })
        let findings = HardeningAssessment.assess(events: synthetic)
        let controls = Set(findings.map(\.control))
        let wave16HardenControls = Set(registrations.map(\.hardeningControl))
        for control in wave16HardenControls {
            XCTAssertTrue(controls.contains(control), "missing \(control)")
        }
        for finding in findings where wave16HardenControls.contains(finding.control) {
            XCTAssertFalse(finding.remediation.isEmpty)
        }
    }

    func testWave16DetectionFixturesViaFixtureRunner() throws {
        let rulesDir = URL(fileURLWithPath: "Content/detections/samples")
        let fixturesDir = rulesDir.appendingPathComponent("fixtures")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: rulesDir.path))
        var hitIDs: [String] = []
        for registration in Wave16ParserRegistry.registrations {
            let name = "\(registration.spec.fileStem).yaml"
            let rule = try RuleLoader.load(from: rulesDir.appendingPathComponent(name))
            let events = try FixtureRunner.loadEvents(from: fixturesDir.appendingPathComponent(rule.fixture))
            let findings = FixtureRunner.evaluate(rule: rule, events: events)
            XCTAssertFalse(findings.isEmpty, "\(rule.id)")
            XCTAssertEqual(findings.first?.ruleID, rule.id)
            hitIDs.append(rule.id)
        }
        print("WAVE16_DETECTION_RULE_IDS=" + hitIDs.joined(separator: ","))
        print("WAVE16_HALF_PAIRS=" + String(Wave16ParserRegistry.registrations.count * 2))
    }

    func testWave16SupportUsesOnlyTheStableJSONEnvelope() throws {
        let root = try makeWave16SupportRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let preferences = root.appendingPathComponent("Library/Preferences", isDirectory: true)
        try FileManager.default.createDirectory(at: preferences, withIntermediateDirectories: true)
        let artifact = preferences.appendingPathComponent("airplay_receiver_surface.json")
        let record: [String: Any] = [
            "path": "/Users/alice/Library/AirPlay/receiver",
            "tool_path": "/ignored/tool/path",
            "name": "Receiver",
            "kind": "ignored-kind",
            "label": "ignored-label",
            "notes": "stable note",
            "risk_tags": "first,password_dump,second",
            "password": "secret",
            "token": "secret-token",
            "url_host": "must-not-propagate.example",
            "share_url": "smb://must-not-propagate",
            "depth": "9",
            "runs_script": true,
            "tool_present": true,
        ]
        try JSONSerialization.data(withJSONObject: ["items": [record, [:]]]).write(to: artifact)

        let events = Wave16ParserSupport.parse(
            source: .directory(root),
            spec: try XCTUnwrap(Wave16ParserRegistry.registrations.first?.spec)
        )
        XCTAssertEqual(events.count, 1, "canonical discovery and recursive discovery must deduplicate the same path")
        let event = try XCTUnwrap(events.first)
        XCTAssertEqual(event.source, .parser)
        XCTAssertEqual(event.sourcePlugin, "AIRPLAYRX")
        XCTAssertEqual(event.eventType, "airplay.receiver")
        XCTAssertEqual(event.entityRefs, [EntityID(kind: .host, value: "airplayrx|Receiver")])
        XCTAssertEqual(event.rawRef, ArtifactRoot.pathKey(artifact))
        XCTAssertEqual(event.confidence, 0.88)
        XCTAssertEqual(event.fields, [
            "airplayrx.path": "/Users/alice/Library/AirPlay/receiver",
            "airplayrx.name": "Receiver",
            "airplayrx.notes": "stable note",
            "airplayrx.risk_tags": "first,second,airplay_surface",
            "airplayrx.secrets_exported": "false",
            FieldTaxonomy.eventType: "airplay.receiver",
            FieldTaxonomy.userName: "alice",
        ])
        let allValues = event.fields.values.joined(separator: " ").lowercased()
        XCTAssertFalse(allValues.contains("secret"))
        XCTAssertFalse(event.fields.keys.contains { $0.contains("url_host") || $0.contains("share_url") || $0.contains("depth") || $0.contains("runs_script") || $0.contains("tool_present") })
    }

    func testWave16SupportReadsJSONLAndRejectsMissingMarkers() throws {
        let root = try makeWave16SupportRoot()
        defer { try? FileManager.default.removeItem(at: root) }
        let logs = root.appendingPathComponent("Library/Logs", isDirectory: true)
        try FileManager.default.createDirectory(at: logs, withIntermediateDirectories: true)
        let artifact = logs.appendingPathComponent("airplay_receiver_surface.jsonl")
        try [
            "{\"tool_path\":\"/Library/AirPlay/tool\",\"kind\":\"Tool\",\"risk_tags\":\"observed\"}",
            "{\"label\":\"Name-only\"}",
            "{\"token\":\"secret-only\"}",
            "{}",
        ].joined(separator: "\n").write(to: artifact, atomically: true, encoding: .utf8)

        let events = Wave16ParserSupport.parse(
            source: .directory(root),
            spec: try XCTUnwrap(Wave16ParserRegistry.registrations.first?.spec)
        )
        XCTAssertEqual(events.count, 2, "canonical and recursive JSONL discovery must deduplicate the same path")
        XCTAssertEqual(events[0].fields["airplayrx.path"], "/Library/AirPlay/tool")
        XCTAssertEqual(events[0].fields["airplayrx.name"], "Tool")
        XCTAssertEqual(events[0].fields["airplayrx.risk_tags"], "observed,airplay_surface")
        XCTAssertEqual(events[1].fields["airplayrx.path"], "")
        XCTAssertEqual(events[1].fields["airplayrx.name"], "Name-only")
    }

    private func makeWave16SupportRoot() throws -> URL {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("wave16-support-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        return root
    }

    func testMissingMarkersReturnEmptyWave16() throws {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("wave16-empty-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }
        XCTAssertEqual(try AirplayReceiverSurfaceParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try HandoffClipboardDepthParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try ImessagePathPlaneParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try FacetimeCameraSurfaceParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try FinderSyncExtensionParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try FileproviderDomainParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try NotificationCenterDepthParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try SiriSuggestionsPlaneParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try SpotlightImporterDepthParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try ContactsPathPlaneParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try CalendarServerPathParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try RemindersCloudPathParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try MapsLocationPathParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try WeatherWidgetPathParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try MusicLibraryPathParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try BooksPathPlaneParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try PodcastsPathPlaneParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try TvAppPathPlaneParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try HomekitPathPlaneParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try HealthPathPlaneParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try WalletPassPathParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try FindmyPathPlaneParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try ShortcutsIcloudSyncParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try DevicemanagementProfileParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try SoftwareupdateCatalogParser().parse(source: .directory(tmp)).count, 0)
    }
}
