import Foundation
import RootstockCore

/// Time Machine / local snapshot data-access surface (path heuristics only).
///
/// Research basis: TM / local-snapshot research as alternate data-access paths (backups often
/// retain deleted secrets); volume-name heuristics.
/// Safety and behavior: typed `TimeMachineState`; never mounts volumes, never reads backup payloads,
/// never invokes `tmutil` restore - binary/prefs presence only.
public struct TimeMachineCollector: Collector {
    public static let id = "collect.time_machine"
    public static let cost: CollectorCost = .low

    private static let preferencePaths: [String] = [
        "/Library/Preferences/com.apple.TimeMachine.plist",
        "/Library/Preferences/com.apple.TimeMachine.MachineID.plist",
    ]

    private static let backupPathCandidates: [String] = [
        "/Volumes/Time Machine Backups",
        "/Volumes/Backups of Macintosh HD",
        "/.MobileBackups",
        "/.MobileBackups.trash",
        "/System/Volumes/Data/.MobileBackups",
    ]

    private static let localSnapshotCandidates: [String] = [
        "/.MobileBackups",
        "/System/Volumes/Data/.MobileBackups",
        "/private/var/db/com.apple.backupd.snapshotstore",
        "/usr/bin/tmutil",
        "/System/Library/CoreServices/backupd.bundle",
        "/System/Library/LaunchDaemons/com.apple.backupd.plist",
        "/System/Library/LaunchDaemons/com.apple.backupd-auto.plist",
    ]

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "Time Machine surface: path presence only - no backup content read, no tmutil restore",
        ]

        var preferencesPresent: Bool?
        for path in Self.preferencePaths {
            if fm.fileExists(atPath: path) {
                preferencesPresent = true
                notes.append("TM prefs present: \(path) (not parsing destinations)")
            }
        }
        if preferencesPresent == nil {
            preferencesPresent = false
            notes.append("Time Machine preference plists not observed at catalog paths")
        }

        var backupPaths: [String] = []
        for path in Self.backupPathCandidates {
            if fm.fileExists(atPath: path) {
                backupPaths.append(path)
                notes.append("backup_path: \(path)")
            }
        }

        var localSnapshotHints: [String] = []
        for path in Self.localSnapshotCandidates {
            if fm.fileExists(atPath: path) {
                localSnapshotHints.append(path)
                notes.append("local_snapshot_hint: \(path)")
            }
        }

        // Shallow /Volumes scan for Backup / Time Machine named mounts (name only).
        var volumeMountHints: [String] = []
        let volumesRoot = "/Volumes"
        if let volumes = try? fm.contentsOfDirectory(atPath: volumesRoot) {
            for name in volumes {
                let lower = name.lowercased()
                if lower.contains("backup")
                    || lower.contains("time machine")
                    || lower.contains("timemachine")
                    || lower.contains("tm ")
                {
                    let full = (volumesRoot as NSString).appendingPathComponent(name)
                    volumeMountHints.append(full)
                    notes.append("volume_mount_hint: \(full)")
                    if !backupPaths.contains(full) {
                        backupPaths.append(full)
                    }
                }
            }
            notes.append("Volumes listed count=\(volumes.count) (name filter only)")
        } else {
            notes.append("Volumes directory unreadable")
        }

        backupPaths = Array(Set(backupPaths)).sorted()
        localSnapshotHints = Array(Set(localSnapshotHints)).sorted()
        volumeMountHints = Array(Set(volumeMountHints)).sorted()

        var state = CollectedState()
        state.timeMachine = TimeMachineState(
            preferencesPresent: preferencesPresent,
            backupPaths: backupPaths,
            localSnapshotHints: localSnapshotHints,
            volumeMountHints: volumeMountHints,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "prefs=\(preferencesPresent.map(String.init(describing:)) ?? "nil") "
            + "backups=\(backupPaths.count) "
            + "snapshots=\(localSnapshotHints.count) "
            + "volumes=\(volumeMountHints.count)"
        return state
    }
}
