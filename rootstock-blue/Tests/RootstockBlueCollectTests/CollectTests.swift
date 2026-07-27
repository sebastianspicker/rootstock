import XCTest
@testable import RootstockBlueCollect
@testable import RootstockBlueCase
@testable import RootstockBlueCore

final class CollectTests: XCTestCase {
    func testCollectWritesArtifactsAndEvents() throws {
        let fixture = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("Fixtures/artifacts/macos_sample")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: fixture.path))

        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("cf-collect-\(UUID().uuidString).rsbcase")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let pkg = try CasePackage.create(at: tmp, name: "collect-test")

        let pack = CollectionPack(
            name: "triage-lite",
            description: "test",
            requiresFDA: true,
            requiresES: false,
            artifacts: ["tcc", "quarantine", "autostart", "users"]
        )
        let runner = CollectRunner(skipStrictPreflight: true)
        let result = try runner.run(pack: pack, sourceRoot: fixture, into: pkg)
        XCTAssertGreaterThan(result.filesCopied, 0)
        XCTAssertGreaterThan(result.eventsWritten, 0)
        XCTAssertTrue(result.preflight.passed)

        let events = try pkg.loadAllEvents()
        XCTAssertTrue(events.contains { $0.eventType == "collect.summary" })
        XCTAssertTrue(events.contains { $0.eventType == "collect.artifact" })
    }

    func testPreflightLiveRequiresFDA() {
        let pack = CollectionPack(name: "x", description: "", requiresFDA: true, requiresES: false, artifacts: [])
        let live = Preflight.check(for: pack, offlineFixtureMode: false)
        XCTAssertFalse(live.passed)
        let offline = Preflight.check(for: pack, offlineFixtureMode: true)
        XCTAssertTrue(offline.passed)
    }

    func testArtifactPathsExpandedMappings() {
        XCTAssertTrue(CollectRunner.artifactPaths(for: "btm").contains {
            $0.contains("backgroundtaskmanagement")
        })
        XCTAssertTrue(CollectRunner.artifactPaths(for: "wifi").contains {
            $0.contains("airport.preferences") || $0.contains("wifi")
        })
        XCTAssertEqual(
            CollectRunner.artifactPaths(for: "security_posture"),
            ["Library/Preferences/security_posture.json"]
        )
        XCTAssertEqual(
            CollectRunner.artifactPaths(for: "alf"),
            ["Library/Preferences/com.apple.alf.plist"]
        )
        XCTAssertTrue(CollectRunner.artifactPaths(for: "ssh").contains("Users"))
        XCTAssertTrue(CollectRunner.artifactPaths(for: "configprofiles").contains {
            $0.contains("ConfigurationProfiles") || $0.contains("Managed Preferences")
        })
        // btm is no longer aliased to LaunchAgents
        XCTAssertFalse(CollectRunner.artifactPaths(for: "btm").contains("Library/LaunchAgents"))

        // Expansion surfaces
        XCTAssertTrue(CollectRunner.artifactPaths(for: "cron").contains { $0.contains("crontab") || $0.contains("at/tabs") })
        XCTAssertTrue(CollectRunner.artifactPaths(for: "loginitems").contains { $0.contains("sharedfilelist") || $0 == "Users" })
        XCTAssertTrue(CollectRunner.artifactPaths(for: "systemextensions").contains { $0.contains("SystemExtensions") })
        XCTAssertTrue(CollectRunner.artifactPaths(for: "utmpx").contains { $0.contains("utmpx") })
        XCTAssertTrue(CollectRunner.artifactPaths(for: "biome").contains { $0.contains("Biome") })
        XCTAssertTrue(CollectRunner.artifactPaths(for: "gatekeeper").contains { $0.contains("Gatekeeper") || $0.contains("gk.json") })
        XCTAssertTrue(CollectRunner.artifactPaths(for: "netlocation").contains { $0.contains("network_locations") || $0.contains("SystemConfiguration") })
        XCTAssertTrue(CollectRunner.artifactPaths(for: "browser_extensions").contains { $0.contains("Chrome") || $0 == "Users" })

        XCTAssertTrue(CollectRunner.artifactPaths(for: "shell_profiles").contains { $0 == "Users" || $0.contains("profile") })
        XCTAssertTrue(CollectRunner.artifactPaths(for: "emond").contains { $0.contains("emond") })
        XCTAssertTrue(CollectRunner.artifactPaths(for: "sudoers").contains { $0.contains("sudoers") })
        XCTAssertTrue(CollectRunner.artifactPaths(for: "launchd_overrides").contains { $0.contains("xpc.launchd") || $0.contains("launchd_disabled") })

        XCTAssertTrue(CollectRunner.artifactPaths(for: "privhelpers").contains { $0.contains("PrivilegedHelperTools") })
        XCTAssertTrue(CollectRunner.artifactPaths(for: "folder_actions").contains { $0 == "Users" || $0.contains("Scripts") })
        XCTAssertTrue(CollectRunner.artifactPaths(for: "login_hooks").contains { $0.contains("loginwindow") || $0.contains("login_hooks") })
        XCTAssertTrue(CollectRunner.artifactPaths(for: "software_update").contains { $0.contains("SoftwareUpdate") })
        XCTAssertTrue(CollectRunner.artifactPaths(for: "file_sharing").contains { $0.contains("smb") || $0.contains("AppleFileServer") })
    }

    func testNetworkAndAccessSurfacePacksLoad() throws {
        let cwd = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        for name in ["network-context", "access-surface", "persistence", "forensic-triage"] {
            let url = cwd.appendingPathComponent("Content/collections/\(name).yaml")
            try XCTSkipIf(!FileManager.default.fileExists(atPath: url.path))
            let pack = try CollectionPackLoader.load(from: url)
            XCTAssertEqual(pack.name, name)
            XCTAssertFalse(pack.artifacts.isEmpty)
        }
    }

    func testPostIncidentIRPackLoadsAndCollectsPosture() throws {
        let content = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("Content/collections/post-incident-ir.yaml")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: content.path))
        let pack = try CollectionPackLoader.load(from: content)
        XCTAssertEqual(pack.name, "post-incident-ir")
        XCTAssertTrue(pack.artifacts.contains("security_posture"))
        XCTAssertTrue(pack.artifacts.contains("btm"))
        XCTAssertTrue(pack.artifacts.contains("alf"))

        let fixture = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("Fixtures/artifacts/macos_sample")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: fixture.path))
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("cf-post-ir-\(UUID().uuidString).rsbcase")
        defer { try? FileManager.default.removeItem(at: tmp) }
        let pkg = try CasePackage.create(at: tmp, name: "post-ir")
        let result = try CollectRunner(skipStrictPreflight: true).run(
            pack: pack,
            sourceRoot: fixture,
            into: pkg
        )
        // security_posture.json and alf.plist exist in fixture
        XCTAssertGreaterThan(result.filesCopied, 0)
        let events = try pkg.loadAllEvents()
        XCTAssertTrue(events.contains {
            $0.fields["collect.artifact"] == "security_posture"
                || ($0.fields["collect.relative"] ?? "").contains("security_posture")
        })
    }
}
