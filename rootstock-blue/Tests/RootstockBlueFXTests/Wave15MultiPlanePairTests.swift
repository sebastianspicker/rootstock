import XCTest
@testable import RootstockBlueFX
@testable import RootstockBlueCore
@testable import RootstockBlueCase
@testable import RootstockBlueDetect

/// Wave-15 multi-plane red↔blue pairs (10 net-new themes beyond Wave-14).
final class Wave15MultiPlanePairTests: XCTestCase {
    var relativeRoot: URL { URL(fileURLWithPath: "Fixtures/artifacts/macos_sample") }
    var absoluteRoot: URL { relativeRoot.standardizedFileURL.resolvingSymlinksInPath() }
    private let wave15IDs = [
        "PHOTOSLIBRARY",
        "VPNCONFIGDUAL",
        "SANDBOXCONTAINER",
        "XPCMACHSERVICE",
        "TMLOCALSNAPSHOT",
        "EMONDLEGACY",
        "SCREENSHARINGARD",
        "KEYCHAINACLPATH",
        "PYTHONRUNTIME",
        "SHELLPLUGINMGR"
    ]
    private let wave15HardenControls = [
        "photos_library_path",
        "vpn_config_dualuse",
        "sandbox_container_depth",
        "xpc_mach_service_depth",
        "tm_local_snapshot_depth",
        "emond_legacy_depth",
        "screen_sharing_ard_depth",
        "keychain_acl_path",
        "python_runtime_dualuse",
        "shell_plugin_manager"
    ]

    func testPluginRuntimeIncludesWave15Parsers() {
        let ids = Set(PluginRuntime().parserIDs())
        for id in wave15IDs { XCTAssertTrue(ids.contains(id), "missing \(id)") }
        for id in ["AUTOMATORWF", "PAMAUTHMODULE", "NOTESMETADATA", "CRONATJOB"] {
            XCTAssertTrue(ids.contains(id), "regression \(id)")
        }
    }

    func testWave15ParsersEmitEventsFromFixtures() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let parsers: [any ArtifactParser] = [
            PhotosLibraryPathParser(),
            VpnConfigDualuseParser(),
            SandboxContainerDepthParser(),
            XpcMachServiceDepthParser(),
            TmLocalSnapshotDepthParser(),
            EmondLegacyDepthParser(),
            ScreenSharingArdDepthParser(),
            KeychainAclPathParser(),
            PythonRuntimeDualuseParser(),
            ShellPluginManagerParser()
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

    func testRelativeAbsoluteParityWave15() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let parsers: [any ArtifactParser] = [
            PhotosLibraryPathParser(),
            VpnConfigDualuseParser(),
            SandboxContainerDepthParser(),
            XpcMachServiceDepthParser(),
            TmLocalSnapshotDepthParser(),
            EmondLegacyDepthParser(),
            ScreenSharingArdDepthParser(),
            KeychainAclPathParser(),
            PythonRuntimeDualuseParser(),
            ShellPluginManagerParser()
        ]
        for parser in parsers {
            let rel = try parser.parse(source: .directory(relativeRoot))
            let abs = try parser.parse(source: .directory(absoluteRoot))
            XCTAssertEqual(rel.count, abs.count)
            XCTAssertFalse(rel.isEmpty)
        }
    }

    func testHardenAssessSyntheticEmitsTenWave15Controls() {
        let synthetic: [EventEnvelope] = [
            EventEnvelope(
                source: .parser, sourcePlugin: "PHOTOSLIBRARY", eventType: "photos.library",
                fields: [
                    "photoslib.path": "/Users/alice/Library/Preferences/photos_library_path.json",
                    "photoslib.name": "Photos library path plane",
                    "photoslib.risk_tags": "photos_surface,wave15",
                    "photoslib.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "VPNCONFIGDUAL", eventType: "vpn.config",
                fields: [
                    "vpncfg.path": "/Users/alice/Library/Preferences/vpn_config_dualuse.json",
                    "vpncfg.name": "VPN config dual-use",
                    "vpncfg.risk_tags": "vpn_surface,wave15",
                    "vpncfg.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "SANDBOXCONTAINER", eventType: "sandbox.container",
                fields: [
                    "sbxctr.path": "/Users/alice/Library/Preferences/sandbox_container_depth.json",
                    "sbxctr.name": "Sandbox container depth",
                    "sbxctr.risk_tags": "sandbox_surface,wave15",
                    "sbxctr.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "XPCMACHSERVICE", eventType: "xpc.mach_service",
                fields: [
                    "xpcmach.path": "/Users/alice/Library/Preferences/xpc_mach_service_depth.json",
                    "xpcmach.name": "XPC Mach service depth",
                    "xpcmach.risk_tags": "xpc_mach_surface,wave15",
                    "xpcmach.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "TMLOCALSNAPSHOT", eventType: "tm.local_snapshot",
                fields: [
                    "tmsnap.path": "/Users/alice/Library/Preferences/tm_local_snapshot_depth.json",
                    "tmsnap.name": "TM local snapshot depth",
                    "tmsnap.risk_tags": "tm_snapshot_surface,wave15",
                    "tmsnap.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "EMONDLEGACY", eventType: "emond.legacy",
                fields: [
                    "emondleg.path": "/Users/alice/Library/Preferences/emond_legacy_depth.json",
                    "emondleg.name": "Emond legacy depth",
                    "emondleg.risk_tags": "emond_surface,wave15",
                    "emondleg.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "SCREENSHARINGARD", eventType: "ard.screen_sharing",
                fields: [
                    "ardss.path": "/Users/alice/Library/Preferences/screen_sharing_ard_depth.json",
                    "ardss.name": "Screen Sharing ARD depth",
                    "ardss.risk_tags": "ard_surface,wave15",
                    "ardss.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "KEYCHAINACLPATH", eventType: "keychain.acl_path",
                fields: [
                    "kcacl.path": "/Users/alice/Library/Preferences/keychain_acl_path.json",
                    "kcacl.name": "Keychain ACL path plane",
                    "kcacl.risk_tags": "keychain_acl_surface,wave15",
                    "kcacl.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "PYTHONRUNTIME", eventType: "python.runtime",
                fields: [
                    "pyrun.path": "/Users/alice/Library/Preferences/python_runtime_dualuse.json",
                    "pyrun.name": "Python runtime dual-use",
                    "pyrun.risk_tags": "python_surface,wave15",
                    "pyrun.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "SHELLPLUGINMGR", eventType: "shell.plugin_manager",
                fields: [
                    "shplug.path": "/Users/alice/Library/Preferences/shell_plugin_manager.json",
                    "shplug.name": "Shell plugin manager dual-use",
                    "shplug.risk_tags": "shell_plugin_surface,wave15",
                    "shplug.secrets_exported": "false",
                ]
            ),
        ]
        let findings = HardeningAssessment.assess(events: synthetic)
        let controls = Set(findings.map(\.control))
        for c in wave15HardenControls {
            XCTAssertTrue(controls.contains(c), "missing \(c); got \(controls.sorted())")
        }
        for f in findings where wave15HardenControls.contains(f.control) {
            XCTAssertFalse(f.remediation.isEmpty)
            XCTAssertFalse((f.detail + f.remediation + f.evidence).lowercased().contains("password=secret"))
        }
    }

    func testWave15DetectionFixturesViaFixtureRunner() throws {
        let rulesDir = URL(fileURLWithPath: "Content/detections/samples")
        let fixturesDir = rulesDir.appendingPathComponent("fixtures")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: rulesDir.path))
        let wave15Rules = [
            "photos_library_path.yaml",
            "vpn_config_dualuse.yaml",
            "sandbox_container_depth.yaml",
            "xpc_mach_service_depth.yaml",
            "tm_local_snapshot_depth.yaml",
            "emond_legacy_depth.yaml",
            "screen_sharing_ard_depth.yaml",
            "keychain_acl_path.yaml",
            "python_runtime_dualuse.yaml",
            "shell_plugin_manager.yaml"
        ]
        var hitIDs: [String] = []
        for name in wave15Rules {
            let rule = try RuleLoader.load(from: rulesDir.appendingPathComponent(name))
            let events = try FixtureRunner.loadEvents(from: fixturesDir.appendingPathComponent(rule.fixture))
            let findings = FixtureRunner.evaluate(rule: rule, events: events)
            XCTAssertFalse(findings.isEmpty, "\(rule.id)")
            XCTAssertEqual(findings.first?.ruleID, rule.id)
            hitIDs.append(rule.id)
        }
        print("WAVE15_DETECTION_RULE_IDS=" + hitIDs.joined(separator: ","))
        print("WAVE15_HARDEN_CONTROLS=" + wave15HardenControls.joined(separator: ","))
    }

    func testMissingMarkersReturnEmptyWave15() throws {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("wave15-empty-" + UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }
        XCTAssertEqual(try PhotosLibraryPathParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try VpnConfigDualuseParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try SandboxContainerDepthParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try XpcMachServiceDepthParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try TmLocalSnapshotDepthParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try EmondLegacyDepthParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try ScreenSharingArdDepthParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try KeychainAclPathParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try PythonRuntimeDualuseParser().parse(source: .directory(tmp)).count, 0)
        XCTAssertEqual(try ShellPluginManagerParser().parse(source: .directory(tmp)).count, 0)
    }
}
