import Foundation
import RootstockCore

/// Browser extension dual-use persistence / collection plane (Wave-11).
///
/// Research basis: Chromium/Safari extension persistence and broad-permission collection research.
/// Safety and behavior: multi-browser path plane + compound with FDA/remote; never dumps extension storage secrets.
public struct BrowserExtensionDualUseCollector: Collector {
    public static let id = "collect.browser_extension_dualuse"
    public static let cost: CollectorCost = .low

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        let home = NSHomeDirectory()
        var notes: [String] = [
            "Browser extension dual-use plane: path presence only - never dumps extension secrets or cookies",
        ]

        let chromiumRoots = [
            home + "/Library/Application Support/Google/Chrome/Default/Extensions",
            home + "/Library/Application Support/Google/Chrome/Profile 1/Extensions",
            home + "/Library/Application Support/Chromium/Default/Extensions",
            home + "/Library/Application Support/Microsoft Edge/Default/Extensions",
            home + "/Library/Application Support/BraveSoftware/Brave-Browser/Default/Extensions",
            home + "/Library/Application Support/Arc/User Data/Default/Extensions",
        ]
        var chromium: [String] = []
        for path in chromiumRoots where fm.fileExists(atPath: path) {
            chromium.append(path)
            notes.append("chromium_extensions: \(path)")
        }

        let safariRoots = [
            home + "/Library/Safari/Extensions",
            home + "/Library/Containers/com.apple.Safari/Data/Library/Safari/AppExtensions",
            home + "/Library/Containers/com.apple.Safari/Data/Library/Safari/WebExtensions",
            "/Applications/Safari.app",
        ]
        var safari: [String] = []
        for path in safariRoots where fm.fileExists(atPath: path) {
            safari.append(path)
            notes.append("safari_extensions: \(path)")
        }

        let prefPaths = [
            home + "/Library/Application Support/Google/Chrome/Default/Preferences",
            home + "/Library/Application Support/Google/Chrome/Default/Secure Preferences",
            home + "/Library/Preferences/com.apple.Safari.plist",
            home + "/Library/Preferences/com.apple.Safari.Extensions.plist",
        ]
        var prefs: [String] = []
        for path in prefPaths where fm.fileExists(atPath: path) {
            prefs.append(path)
            notes.append("extension_pref: \(path)")
        }

        chromium = Array(Set(chromium)).sorted()
        safari = Array(Set(safari)).sorted()
        prefs = Array(Set(prefs)).sorted()

        let surface = chromium.count + safari.count >= 1 || prefs.count >= 2

        var state = CollectedState()
        state.browserExtensionDualUse = BrowserExtensionDualUseState(
            chromiumExtensionPaths: chromium,
            safariExtensionPaths: safari,
            preferencePaths: prefs,
            extensionSurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "chromium=\(chromium.count) safari=\(safari.count) prefs=\(prefs.count) surface=\(surface)"
        return state
    }
}
