import Foundation
import RootstockCore

/// Shortcuts / App Intents automation lateral posture (Wave-11).
///
/// Research basis: Shortcuts.app automation / App Intents 2024–26 lateral and execution research.
/// Safety and behavior: path inventory + remote amplifiers; never runs shortcuts or forges intents.
public struct ShortcutsAppIntentsCollector: Collector {
    public static let id = "collect.shortcuts_app_intents"
    public static let cost: CollectorCost = .low

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        let home = NSHomeDirectory()
        var notes: [String] = [
            "Shortcuts / App Intents surface: path presence only - never runs shortcuts or forges App Intents",
        ]

        let shortcutsPaths = [
            "/System/Applications/Shortcuts.app",
            "/Applications/Shortcuts.app",
            home + "/Library/Shortcuts",
            home + "/Library/Shortcuts/Shortcuts.sqlite",
            home + "/Library/Containers/com.apple.shortcuts",
            home + "/Library/Group Containers/group.is.workflow.my.app",
            home + "/Library/Group Containers/group.is.workflow.shortcuts",
        ]
        var shortcuts: [String] = []
        for path in shortcutsPaths where fm.fileExists(atPath: path) {
            shortcuts.append(path)
            notes.append("shortcuts: \(path)")
        }

        let intentsPaths = [
            "/System/Library/Frameworks/AppIntents.framework",
            "/System/Library/Frameworks/AppIntents.framework/AppIntents",
            "/System/Library/PrivateFrameworks/WorkflowKit.framework",
            "/System/Library/PrivateFrameworks/VoiceShortcutClient.framework",
            home + "/Library/Developer/Xcode/DerivedData",
        ]
        var intents: [String] = []
        for path in intentsPaths where fm.fileExists(atPath: path) {
            // Skip DerivedData alone as surface signal (too common on dev hosts)
            if path.contains("DerivedData") {
                notes.append("developer_derived_data_present: \(path) (not counted as surface alone)")
                continue
            }
            intents.append(path)
            notes.append("app_intents: \(path)")
        }

        let autoPrefs = [
            home + "/Library/Preferences/com.apple.shortcuts.plist",
            home + "/Library/Preferences/com.apple.siriactionsd.plist",
            home + "/Library/Preferences/com.apple.voicebankingd.plist",
            "/Library/Preferences/com.apple.shortcuts.plist",
        ]
        var prefs: [String] = []
        for path in autoPrefs where fm.fileExists(atPath: path) {
            prefs.append(path)
            notes.append("automation_pref: \(path)")
        }

        shortcuts = Array(Set(shortcuts)).sorted()
        intents = Array(Set(intents)).sorted()
        prefs = Array(Set(prefs)).sorted()

        let surface = shortcuts.count >= 1 || intents.count >= 1

        var state = CollectedState()
        state.shortcutsAppIntents = ShortcutsAppIntentsState(
            shortcutsAppPaths: shortcuts,
            appIntentsPaths: intents,
            automationPrefPaths: prefs,
            automationSurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "shortcuts=\(shortcuts.count) intents=\(intents.count) prefs=\(prefs.count) surface=\(surface)"
        return state
    }
}
