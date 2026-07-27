import XCTest
@testable import RootstockBlueFX
@testable import RootstockBlueCore
@testable import RootstockBlueCase
@testable import RootstockBlueDetect

/// Wave-16 multi-plane red↔blue pairs (25 themes / 50 half-pairs beyond Wave-15).
final class Wave16MultiPlanePairTests: XCTestCase {
    var relativeRoot: URL { URL(fileURLWithPath: "Fixtures/artifacts/macos_sample") }
    var absoluteRoot: URL { relativeRoot.standardizedFileURL.resolvingSymlinksInPath() }
    private let wave16IDs = [
        "AIRPLAYRX",
        "HANDOFFCB",
        "IMSGPATH",
        "FTCAM",
        "FNDSYNC",
        "FPDOM",
        "NOTICTR",
        "SIRISUG",
        "SPIMP",
        "CTPATH",
        "CALDAV",
        "REMCLOUD",
        "MAPSLOC",
        "WTHRWDG",
        "MUSLIB",
        "BKPATH",
        "PODPATH",
        "TVPATH",
        "HKPATH",
        "HLTHPATH",
        "WLTPASS",
        "FMPATH",
        "SCICLOUD",
        "MDMPROF",
        "SUCAT"
    ]
    private let wave16HardenControls = [
        "airplay_receiver_surface",
        "handoff_clipboard_depth",
        "imessage_path_plane",
        "facetime_camera_surface",
        "finder_sync_extension",
        "fileprovider_domain",
        "notification_center_depth",
        "siri_suggestions_plane",
        "spotlight_importer_depth",
        "contacts_path_plane",
        "calendar_server_path",
        "reminders_cloud_path",
        "maps_location_path",
        "weather_widget_path",
        "music_library_path",
        "books_path_plane",
        "podcasts_path_plane",
        "tv_app_path_plane",
        "homekit_path_plane",
        "health_path_plane",
        "wallet_pass_path",
        "findmy_path_plane",
        "shortcuts_icloud_sync",
        "devicemanagement_profile",
        "softwareupdate_catalog"
    ]

    func testPluginRuntimeIncludesWave16Parsers() {
        let ids = Set(PluginRuntime().parserIDs())
        for id in wave16IDs { XCTAssertTrue(ids.contains(id), "missing \(id)") }
        XCTAssertTrue(ids.contains("SHELLPLUGINMGR"))
        XCTAssertTrue(ids.contains("PHOTOSLIBRARY"))
    }

    func testWave16ParsersEmitEventsFromFixtures() throws {
        try XCTSkipIf(!FileManager.default.fileExists(atPath: relativeRoot.path))
        let parsers: [any ArtifactParser] = [
            AirplayReceiverSurfaceParser(),
            HandoffClipboardDepthParser(),
            ImessagePathPlaneParser(),
            FacetimeCameraSurfaceParser(),
            FinderSyncExtensionParser(),
            FileproviderDomainParser(),
            NotificationCenterDepthParser(),
            SiriSuggestionsPlaneParser(),
            SpotlightImporterDepthParser(),
            ContactsPathPlaneParser(),
            CalendarServerPathParser(),
            RemindersCloudPathParser(),
            MapsLocationPathParser(),
            WeatherWidgetPathParser(),
            MusicLibraryPathParser(),
            BooksPathPlaneParser(),
            PodcastsPathPlaneParser(),
            TvAppPathPlaneParser(),
            HomekitPathPlaneParser(),
            HealthPathPlaneParser(),
            WalletPassPathParser(),
            FindmyPathPlaneParser(),
            ShortcutsIcloudSyncParser(),
            DevicemanagementProfileParser(),
            SoftwareupdateCatalogParser()
        ]
        for parser in parsers {
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
        let parsers: [any ArtifactParser] = [
            AirplayReceiverSurfaceParser(),
            HandoffClipboardDepthParser(),
            ImessagePathPlaneParser(),
            FacetimeCameraSurfaceParser(),
            FinderSyncExtensionParser(),
            FileproviderDomainParser(),
            NotificationCenterDepthParser(),
            SiriSuggestionsPlaneParser(),
            SpotlightImporterDepthParser(),
            ContactsPathPlaneParser(),
            CalendarServerPathParser(),
            RemindersCloudPathParser(),
            MapsLocationPathParser(),
            WeatherWidgetPathParser(),
            MusicLibraryPathParser(),
            BooksPathPlaneParser(),
            PodcastsPathPlaneParser(),
            TvAppPathPlaneParser(),
            HomekitPathPlaneParser(),
            HealthPathPlaneParser(),
            WalletPassPathParser(),
            FindmyPathPlaneParser(),
            ShortcutsIcloudSyncParser(),
            DevicemanagementProfileParser(),
            SoftwareupdateCatalogParser()
        ]
        for parser in parsers {
            let rel = try parser.parse(source: .directory(relativeRoot))
            let abs = try parser.parse(source: .directory(absoluteRoot))
            XCTAssertEqual(rel.count, abs.count, parser.manifest.id)
            XCTAssertFalse(rel.isEmpty)
        }
    }

    func testHardenAssessSyntheticEmitsTwentyFiveWave16Controls() {
        let synthetic: [EventEnvelope] = [
            EventEnvelope(
                source: .parser, sourcePlugin: "AIRPLAYRX", eventType: "airplay.receiver",
                fields: [
                    "airplayrx.path": "/Users/alice/Library/Preferences/airplay_receiver_surface.json",
                    "airplayrx.name": "AirPlay receiver dual-use",
                    "airplayrx.risk_tags": "airplay_surface,wave16",
                    "airplayrx.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "HANDOFFCB", eventType: "handoff.clipboard",
                fields: [
                    "hdoffcb.path": "/Users/alice/Library/Preferences/handoff_clipboard_depth.json",
                    "hdoffcb.name": "Handoff clipboard depth",
                    "hdoffcb.risk_tags": "handoff_surface,wave16",
                    "hdoffcb.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "IMSGPATH", eventType: "imessage.path",
                fields: [
                    "imsgpath.path": "/Users/alice/Library/Preferences/imessage_path_plane.json",
                    "imsgpath.name": "iMessage path plane",
                    "imsgpath.risk_tags": "imessage_surface,wave16",
                    "imsgpath.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "FTCAM", eventType: "facetime.camera",
                fields: [
                    "ftcam.path": "/Users/alice/Library/Preferences/facetime_camera_surface.json",
                    "ftcam.name": "FaceTime camera dual-use",
                    "ftcam.risk_tags": "facetime_surface,wave16",
                    "ftcam.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "FNDSYNC", eventType: "finder.sync_ext",
                fields: [
                    "fndsync.path": "/Users/alice/Library/Preferences/finder_sync_extension.json",
                    "fndsync.name": "Finder Sync dual-use",
                    "fndsync.risk_tags": "finder_sync_surface,wave16",
                    "fndsync.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "FPDOM", eventType: "fileprovider.domain",
                fields: [
                    "fpdom.path": "/Users/alice/Library/Preferences/fileprovider_domain.json",
                    "fpdom.name": "File Provider domain",
                    "fpdom.risk_tags": "fileprovider_surface,wave16",
                    "fpdom.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "NOTICTR", eventType: "notification.center",
                fields: [
                    "notictr.path": "/Users/alice/Library/Preferences/notification_center_depth.json",
                    "notictr.name": "Notification Center depth",
                    "notictr.risk_tags": "notification_surface,wave16",
                    "notictr.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "SIRISUG", eventType: "siri.suggestions",
                fields: [
                    "sirisug.path": "/Users/alice/Library/Preferences/siri_suggestions_plane.json",
                    "sirisug.name": "Siri Suggestions residual",
                    "sirisug.risk_tags": "siri_surface,wave16",
                    "sirisug.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "SPIMP", eventType: "spotlight.importer",
                fields: [
                    "spimp.path": "/Users/alice/Library/Preferences/spotlight_importer_depth.json",
                    "spimp.name": "Spotlight importer depth",
                    "spimp.risk_tags": "spotlight_importer_surface,wave16",
                    "spimp.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "CTPATH", eventType: "contacts.path",
                fields: [
                    "ctpath.path": "/Users/alice/Library/Preferences/contacts_path_plane.json",
                    "ctpath.name": "Contacts path plane",
                    "ctpath.risk_tags": "contacts_surface,wave16",
                    "ctpath.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "CALDAV", eventType: "calendar.caldav",
                fields: [
                    "caldav.path": "/Users/alice/Library/Preferences/calendar_server_path.json",
                    "caldav.name": "Calendar CalDAV residual",
                    "caldav.risk_tags": "caldav_surface,wave16",
                    "caldav.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "REMCLOUD", eventType: "reminders.cloud",
                fields: [
                    "remcloud.path": "/Users/alice/Library/Preferences/reminders_cloud_path.json",
                    "remcloud.name": "Reminders cloud path",
                    "remcloud.risk_tags": "reminders_cloud_surface,wave16",
                    "remcloud.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "MAPSLOC", eventType: "maps.location",
                fields: [
                    "mapsloc.path": "/Users/alice/Library/Preferences/maps_location_path.json",
                    "mapsloc.name": "Maps location residual",
                    "mapsloc.risk_tags": "maps_location_surface,wave16",
                    "mapsloc.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "WTHRWDG", eventType: "weather.widget",
                fields: [
                    "wthrwdg.path": "/Users/alice/Library/Preferences/weather_widget_path.json",
                    "wthrwdg.name": "Weather widget residual",
                    "wthrwdg.risk_tags": "weather_surface,wave16",
                    "wthrwdg.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "MUSLIB", eventType: "music.library",
                fields: [
                    "muslib.path": "/Users/alice/Library/Preferences/music_library_path.json",
                    "muslib.name": "Music library path",
                    "muslib.risk_tags": "music_surface,wave16",
                    "muslib.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "BKPATH", eventType: "books.path",
                fields: [
                    "bkpath.path": "/Users/alice/Library/Preferences/books_path_plane.json",
                    "bkpath.name": "Books path plane",
                    "bkpath.risk_tags": "books_surface,wave16",
                    "bkpath.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "PODPATH", eventType: "podcasts.path",
                fields: [
                    "podpath.path": "/Users/alice/Library/Preferences/podcasts_path_plane.json",
                    "podpath.name": "Podcasts path plane",
                    "podpath.risk_tags": "podcasts_surface,wave16",
                    "podpath.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "TVPATH", eventType: "tv.path",
                fields: [
                    "tvpath.path": "/Users/alice/Library/Preferences/tv_app_path_plane.json",
                    "tvpath.name": "TV.app path plane",
                    "tvpath.risk_tags": "tv_surface,wave16",
                    "tvpath.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "HKPATH", eventType: "homekit.path",
                fields: [
                    "hkpath.path": "/Users/alice/Library/Preferences/homekit_path_plane.json",
                    "hkpath.name": "HomeKit path plane",
                    "hkpath.risk_tags": "homekit_surface,wave16",
                    "hkpath.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "HLTHPATH", eventType: "health.path",
                fields: [
                    "hlthpath.path": "/Users/alice/Library/Preferences/health_path_plane.json",
                    "hlthpath.name": "Health path plane",
                    "hlthpath.risk_tags": "health_surface,wave16",
                    "hlthpath.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "WLTPASS", eventType: "wallet.pass",
                fields: [
                    "wltpass.path": "/Users/alice/Library/Preferences/wallet_pass_path.json",
                    "wltpass.name": "Wallet pass path",
                    "wltpass.risk_tags": "wallet_surface,wave16",
                    "wltpass.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "FMPATH", eventType: "findmy.path",
                fields: [
                    "fmpath.path": "/Users/alice/Library/Preferences/findmy_path_plane.json",
                    "fmpath.name": "Find My path plane",
                    "fmpath.risk_tags": "findmy_surface,wave16",
                    "fmpath.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "SCICLOUD", eventType: "shortcuts.icloud",
                fields: [
                    "scicloud.path": "/Users/alice/Library/Preferences/shortcuts_icloud_sync.json",
                    "scicloud.name": "Shortcuts iCloud sync",
                    "scicloud.risk_tags": "shortcuts_icloud_surface,wave16",
                    "scicloud.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "MDMPROF", eventType: "mdm.profile_depth",
                fields: [
                    "mdmprof.path": "/Users/alice/Library/Preferences/devicemanagement_profile.json",
                    "mdmprof.name": "Device management profile",
                    "mdmprof.risk_tags": "device_mgmt_surface,wave16",
                    "mdmprof.secrets_exported": "false",
                ]
            ),
            EventEnvelope(
                source: .parser, sourcePlugin: "SUCAT", eventType: "softwareupdate.catalog",
                fields: [
                    "sucat.path": "/Users/alice/Library/Preferences/softwareupdate_catalog.json",
                    "sucat.name": "Software Update catalog",
                    "sucat.risk_tags": "softwareupdate_surface,wave16",
                    "sucat.secrets_exported": "false",
                ]
            ),
        ]
        let findings = HardeningAssessment.assess(events: synthetic)
        let controls = Set(findings.map(\.control))
        for c in wave16HardenControls {
            XCTAssertTrue(controls.contains(c), "missing \(c)")
        }
        for f in findings where wave16HardenControls.contains(f.control) {
            XCTAssertFalse(f.remediation.isEmpty)
        }
    }

    func testWave16DetectionFixturesViaFixtureRunner() throws {
        let rulesDir = URL(fileURLWithPath: "Content/detections/samples")
        let fixturesDir = rulesDir.appendingPathComponent("fixtures")
        try XCTSkipIf(!FileManager.default.fileExists(atPath: rulesDir.path))
        let wave16Rules = [
            "airplay_receiver_surface.yaml",
            "handoff_clipboard_depth.yaml",
            "imessage_path_plane.yaml",
            "facetime_camera_surface.yaml",
            "finder_sync_extension.yaml",
            "fileprovider_domain.yaml",
            "notification_center_depth.yaml",
            "siri_suggestions_plane.yaml",
            "spotlight_importer_depth.yaml",
            "contacts_path_plane.yaml",
            "calendar_server_path.yaml",
            "reminders_cloud_path.yaml",
            "maps_location_path.yaml",
            "weather_widget_path.yaml",
            "music_library_path.yaml",
            "books_path_plane.yaml",
            "podcasts_path_plane.yaml",
            "tv_app_path_plane.yaml",
            "homekit_path_plane.yaml",
            "health_path_plane.yaml",
            "wallet_pass_path.yaml",
            "findmy_path_plane.yaml",
            "shortcuts_icloud_sync.yaml",
            "devicemanagement_profile.yaml",
            "softwareupdate_catalog.yaml"
        ]
        var hitIDs: [String] = []
        for name in wave16Rules {
            let rule = try RuleLoader.load(from: rulesDir.appendingPathComponent(name))
            let events = try FixtureRunner.loadEvents(from: fixturesDir.appendingPathComponent(rule.fixture))
            let findings = FixtureRunner.evaluate(rule: rule, events: events)
            XCTAssertFalse(findings.isEmpty, "\(rule.id)")
            XCTAssertEqual(findings.first?.ruleID, rule.id)
            hitIDs.append(rule.id)
        }
        print("WAVE16_DETECTION_RULE_IDS=" + hitIDs.joined(separator: ","))
        print("WAVE16_HALF_PAIRS=" + String(wave16IDs.count * 2))
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
