import Foundation
import RootstockCore

/// Browser history DB path metadata only - never opens SQLite / reads rows / cookies / passwords.
public struct BrowserMetaCollector: Collector {
    public static let id = "collect.browser_meta"
    public static let cost: CollectorCost = .medium

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let home = FileManager.default.homeDirectoryForCurrentUser
        var entries: [BrowserMetaEntry] = []

        // Safari
        entries.append(
            meta(
                browser: "Safari",
                kind: "history",
                path: home.appendingPathComponent("Library/Safari/History.db").path
            )
        )

        // Chrome Default profile
        entries.append(
            meta(
                browser: "Chrome",
                kind: "history",
                path: home
                    .appendingPathComponent("Library/Application Support/Google/Chrome/Default/History")
                    .path
            )
        )

        // Edge Default profile
        entries.append(
            meta(
                browser: "Edge",
                kind: "history",
                path: home
                    .appendingPathComponent("Library/Application Support/Microsoft Edge/Default/History")
                    .path
            )
        )

        // Firefox: enumerate profile dirs for places.sqlite (path/size/mtime only)
        let fxProfiles = home
            .appendingPathComponent("Library/Application Support/Firefox/Profiles", isDirectory: true)
        if let profiles = try? FileManager.default.contentsOfDirectory(
            at: fxProfiles,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        ) {
            for profile in profiles.sorted(by: { $0.path < $1.path }).prefix(8) {
                let places = profile.appendingPathComponent("places.sqlite")
                entries.append(
                    meta(browser: "Firefox", kind: "history", path: places.path)
                )
            }
        } else {
            // Record expected path even if Profiles dir missing.
            entries.append(
                BrowserMetaEntry(
                    browser: "Firefox",
                    kind: "history",
                    path: fxProfiles.appendingPathComponent("<profile>/places.sqlite").path,
                    exists: false
                )
            )
        }

        var state = CollectedState()
        state.browserMeta = entries
        let present = entries.filter(\.exists).count
        state.collectorNotes[Self.id] =
            "metadata only (\(present)/\(entries.count) present); no DB row reads"
        return state
    }

    private func meta(browser: String, kind: String, path: String) -> BrowserMetaEntry {
        let m = LaunchPlistSupport.fileMeta(at: path)
        return BrowserMetaEntry(
            browser: browser,
            kind: kind,
            path: path,
            exists: m.exists,
            sizeBytes: m.size,
            modifiedAt: m.mtime
        )
    }
}
