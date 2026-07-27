import Foundation
import RootstockCore

/// Sharing / remote-access posture via LaunchDaemon and prefs path heuristics.
///
/// No shell storm, no listening-port scan (often needs root). System LaunchDaemon
/// plists often exist even when the service is disabled - path presence is inventory,
/// not proof of enablement. Details live in `NetworkState.notes` / collectorNotes.
public struct NetworkCollector: Collector {
    public static let id = "collect.network"
    public static let cost: CollectorCost = .medium

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        var notes: [String] = [
            "Path-heuristic network/sharing posture only",
            "LaunchDaemon presence ≠ service enabled; listening ports not scanned (avoid root/shell storm)",
        ]

        // Remote Login (sshd) - system plists exist on stock macOS even when disabled.
        let sshPlists = [
            "/System/Library/LaunchDaemons/ssh.plist",
            "/System/Library/LaunchDaemons/com.openssh.sshd.plist",
        ]
        let remoteLoginPlistPresent = sshPlists.contains { fm.fileExists(atPath: $0) }
        for path in sshPlists {
            notes.append("Remote Login: \(path) exists=\(fm.fileExists(atPath: path))")
        }
        let sshdConfig = "/etc/ssh/sshd_config"
        let sshdConfigAlt = "/private/etc/ssh/sshd_config"
        let sshdConfigPresent = fm.fileExists(atPath: sshdConfig) || fm.fileExists(atPath: sshdConfigAlt)
        notes.append("Remote Login: sshd_config present=\(sshdConfigPresent)")

        // Screen Sharing / ARD
        let screenSharingPlists = [
            "/System/Library/LaunchDaemons/com.apple.screensharing.plist",
            "/System/Library/LaunchAgents/com.apple.screensharing.agent.plist",
            "/System/Library/LaunchAgents/com.apple.screensharing.MessagesAgent.plist",
        ]
        let screenSharingPlistPresent = screenSharingPlists.contains { fm.fileExists(atPath: $0) }
        for path in screenSharingPlists {
            notes.append("Screen Sharing: \(path) exists=\(fm.fileExists(atPath: path))")
        }

        let remoteMgmtPrefs = [
            "/Library/Preferences/com.apple.RemoteManagement.plist",
            "/Library/Application Support/Apple/Remote Desktop/RemoteManagement.launchd",
        ]
        let remoteManagementPrefsPresent = remoteMgmtPrefs.contains { fm.fileExists(atPath: $0) }
        for path in remoteMgmtPrefs {
            notes.append("Remote Management: \(path) exists=\(fm.fileExists(atPath: path))")
        }

        // File Sharing (SMB / AFP)
        let fileSharingPlists = [
            "/System/Library/LaunchDaemons/com.apple.smbd.plist",
            "/System/Library/LaunchDaemons/com.apple.AppleFileServer.plist",
            "/System/Library/LaunchDaemons/com.apple.smb.preferences.plist",
        ]
        let fileSharingPlistPresent = fileSharingPlists.contains { fm.fileExists(atPath: $0) }
        for path in fileSharingPlists {
            notes.append("File Sharing: \(path) exists=\(fm.fileExists(atPath: path))")
        }

        // Extra sharing surfaces (notes only)
        let extras = [
            ("Printer Sharing", "/System/Library/LaunchDaemons/org.cups.cupsd.plist"),
            ("Remote Apple Events", "/System/Library/LaunchDaemons/com.apple.AEServer.plist"),
            ("AirPlay Receiver agent", "/System/Library/LaunchAgents/com.apple.AirPlayUIAgent.plist"),
        ]
        for (label, path) in extras {
            notes.append("\(label): \(path) exists=\(fm.fileExists(atPath: path))")
        }

        // launchd disable overrides (often root-only) - inventory readability only.
        let overridePaths = [
            "/var/db/com.apple.xpc.launchd/disabled.plist",
            "/var/db/launchd.db/com.apple.launchd/overrides.plist",
        ]
        for path in overridePaths {
            let exists = fm.fileExists(atPath: path)
            let readable = fm.isReadableFile(atPath: path)
            notes.append("launchd overrides: \(path) exists=\(exists) readable=\(readable)")
        }

        notes.append(
            "Summary: sshPlist=\(remoteLoginPlistPresent) screenSharingPlist=\(screenSharingPlistPresent) fileSharingPlist=\(fileSharingPlistPresent) remoteMgmtPrefs=\(remoteManagementPrefsPresent)"
        )
        if remoteManagementPrefsPresent {
            notes.append(
                "RemoteManagement prefs present - ARD/screen sharing was likely configured at some point (not definitive live state)"
            )
        }

        // Likely-enabled (conservative): system plists alone are insufficient.
        // RemoteManagement prefs are a stronger ARD/screen-sharing configuration signal.
        // SSH/SMB enablement requires launchctl/systemsetup - leave nil without shell.
        let remoteLoginSSH: Bool? = nil
        let screenSharingARD: Bool? = remoteManagementPrefsPresent ? true : nil
        let fileSharingSMB: Bool? = nil
        notes.append(
            "Likely-enabled: ssh=\(remoteLoginSSH.map(String.init(describing:)) ?? "nil") "
                + "screen=\(screenSharingARD.map(String.init(describing:)) ?? "nil") "
                + "file=\(fileSharingSMB.map(String.init(describing:)) ?? "nil")"
        )

        var state = CollectedState()
        state.network = NetworkState(
            remoteLoginSSH: remoteLoginSSH,
            screenSharingARD: screenSharingARD,
            fileSharingSMB: fileSharingSMB,
            remoteLoginPlistPresent: remoteLoginPlistPresent,
            screenSharingPlistPresent: screenSharingPlistPresent,
            fileSharingPlistPresent: fileSharingPlistPresent,
            remoteManagementPrefsPresent: remoteManagementPrefsPresent,
            sshdConfigPresent: sshdConfigPresent,
            notes: notes
        )
        state.collectorNotes[Self.id] =
            "sharing path heuristics (sshPlist=\(remoteLoginPlistPresent), screenPlist=\(screenSharingPlistPresent), filePlist=\(fileSharingPlistPresent), ardPrefs=\(remoteManagementPrefsPresent))"
        return state
    }
}
