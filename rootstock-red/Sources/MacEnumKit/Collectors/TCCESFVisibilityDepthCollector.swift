import Foundation
import RootstockCore

/// TCC / ESF visibility-depth posture (Wave-9).
///
/// Research basis: ESF/eslogger/Unified Logging operator visibility literature; TCC.db path research.
/// Safety and behavior: typed depth label (strong/partial/thin); never dumps TCC.db rows or live-subscribes ESF.
public struct TCCESFVisibilityDepthCollector: Collector {
    public static let id = "collect.tcc_esf_visibility_depth"
    public static let cost: CollectorCost = .low

    private static let tccDbCandidates: [String] = [
        NSHomeDirectory() + "/Library/Application Support/com.apple.TCC/TCC.db",
        "/Library/Application Support/com.apple.TCC/TCC.db",
        "/private/var/db/SystemPolicyConfiguration",
        NSHomeDirectory() + "/Library/Application Support/com.apple.TCC",
        "/Library/Application Support/com.apple.TCC",
    ]

    private static let visibilityTools: [String] = [
        "/usr/bin/eslogger",
        "/usr/bin/log",
        "/usr/bin/log stream",
        "/usr/bin/sqlite3",
        "/usr/bin/fs_usage",
        "/usr/sbin/system_profiler",
        "/System/Library/Frameworks/EndpointSecurity.framework",
        "/Library/Developer/CommandLineTools/usr/bin/eslogger",
    ]

    private static let privacyPrefs: [String] = [
        NSHomeDirectory() + "/Library/Preferences/com.apple.TCC.plist",
        "/Library/Preferences/com.apple.TCC.plist",
        "/Library/Preferences/com.apple.security.plist",
        NSHomeDirectory() + "/Library/Preferences/com.apple.Logging.plist",
        "/System/Library/LaunchDaemons/com.apple.syslogd.plist",
        "/etc/asl.conf",
        "/private/etc/asl.conf",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "TCC/ESF visibility depth: path/listability only - never dumps TCC.db rows, never live-subscribes ESF without ROE",
        ]

        var tccHits: [String] = []
        var readableTCC = 0
        for path in Self.tccDbCandidates where fm.fileExists(atPath: path) {
            tccHits.append(path)
            let readable = fm.isReadableFile(atPath: path)
            if readable { readableTCC += 1 }
            notes.append("tcc_path: \(path) readable=\(readable)")
        }

        var tools: [String] = []
        for path in Self.visibilityTools {
            // Skip fake "log stream" path component only if not a real file.
            if path.contains(" ") { continue }
            if fm.fileExists(atPath: path) {
                tools.append(path)
                notes.append("visibility_tool: \(path)")
            }
        }

        var prefs: [String] = []
        for path in Self.privacyPrefs where fm.fileExists(atPath: path) {
            prefs.append(path)
            notes.append("privacy_pref: \(path)")
        }

        tccHits = Array(Set(tccHits)).sorted()
        tools = Array(Set(tools)).sorted()
        prefs = Array(Set(prefs)).sorted()

        // Depth heuristic: strong = readable TCC path + tools; partial = paths only; thin = few signals.
        let depth: String
        if readableTCC > 0 && tools.count >= 2 {
            depth = "strong"
        } else if !tccHits.isEmpty || tools.count >= 2 {
            depth = "partial"
        } else {
            depth = "thin"
        }

        let surface = !tccHits.isEmpty || !tools.isEmpty || !prefs.isEmpty

        var state = CollectedState()
        state.tccEsfVisibilityDepth = TCCESFVisibilityDepthState(
            tccDbPathHits: tccHits,
            visibilityToolPaths: tools,
            privacyPrefPaths: prefs,
            visibilityDepth: depth,
            visibilitySurfacePresent: surface,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "tcc=\(tccHits.count) readableTCC=\(readableTCC) tools=\(tools.count) "
            + "prefs=\(prefs.count) depth=\(depth) surface=\(surface)"
        return state
    }
}
