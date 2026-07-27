import Foundation
import RootstockCore

/// LaunchAgents/Daemons (system) + BTM store presence + legacy login-item plist paths.
public struct LoginItemsBTMCollector: Collector {
    public static let id = "collect.loginitems_btm"
    public static let cost: CollectorCost = .medium

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser

        let systemAgentsDir = URL(fileURLWithPath: "/Library/LaunchAgents", isDirectory: true)
        let daemonsDir = URL(fileURLWithPath: "/Library/LaunchDaemons", isDirectory: true)
        let userAgentsDir = home.appendingPathComponent("Library/LaunchAgents", isDirectory: true)

        let systemAgents = LaunchPlistSupport.enumeratePlists(in: systemAgentsDir)
        let daemons = LaunchPlistSupport.enumeratePlists(in: daemonsDir)
        // User agents already covered by PersistAudit; still count for notes.
        let userAgents = LaunchPlistSupport.enumeratePlists(in: userAgentsDir)

        // BTM agent support directory (opaque store - existence/size only).
        let btmDir = home
            .appendingPathComponent(
                "Library/Application Support/com.apple.backgroundtaskmanagementagent",
                isDirectory: true
            )
        var isDir: ObjCBool = false
        let btmDirExists = fm.fileExists(atPath: btmDir.path, isDirectory: &isDir) && isDir.boolValue
        let btmDirSize = btmDirExists ? LaunchPlistSupport.directorySizeBytes(at: btmDir) : nil

        let backgroundItemsURL = btmDir.appendingPathComponent("backgrounditems.btm")
        let btmFileMeta = LaunchPlistSupport.fileMeta(at: backgroundItemsURL.path)

        // System BTM DB (often root-owned / unreadable without privileges).
        let systemBTMRoot = URL(fileURLWithPath: "/var/db/com.apple.backgroundtaskmanagement", isDirectory: true)
        var systemBTMNote = "system BTM path not present"
        if fm.fileExists(atPath: systemBTMRoot.path) {
            if let items = try? fm.contentsOfDirectory(atPath: systemBTMRoot.path) {
                systemBTMNote = "system BTM dir readable (\(items.count) entries, names only)"
            } else {
                systemBTMNote = "system BTM dir present but listing denied"
            }
        }

        // Legacy / adjacent login-item preference paths (presence only).
        let candidateLoginItemPaths = [
            home.appendingPathComponent("Library/Preferences/com.apple.loginitems.plist").path,
            home.appendingPathComponent("Library/Preferences/loginwindow.plist").path,
            backgroundItemsURL.path,
        ]
        let existingLoginPaths = candidateLoginItemPaths.filter { fm.fileExists(atPath: $0) }

        var notes: [String] = [
            "user LaunchAgents: \(userAgents.count) (also via PersistAudit)",
            "system LaunchAgents: \(systemAgents.count)",
            "LaunchDaemons: \(daemons.count)",
            systemBTMNote,
            "BTM binary format not parsed (opaque evidence only)",
        ]
        if btmFileMeta.exists, let size = btmFileMeta.size {
            notes.append("backgrounditems.btm size=\(size)")
        }

        let loginItems = LoginItemsState(
            btmStorePresent: btmDirExists || btmFileMeta.exists,
            btmDirectoryPath: btmDirExists ? btmDir.path : nil,
            btmDirectorySizeBytes: btmDirSize,
            backgroundItemsBtmPath: btmFileMeta.exists ? backgroundItemsURL.path : nil,
            backgroundItemsBtmSizeBytes: btmFileMeta.size,
            loginItemPaths: existingLoginPaths,
            notes: notes
        )

        var state = CollectedState()
        state.systemLaunchAgents = systemAgents
        state.launchDaemons = daemons
        state.btmStorePresent = loginItems.btmStorePresent
        state.loginItemPaths = existingLoginPaths
        state.loginItems = loginItems
        state.collectorNotes[Self.id] =
            "systemAgents=\(systemAgents.count) daemons=\(daemons.count) btm=\(loginItems.btmStorePresent) loginPaths=\(existingLoginPaths.count)"
        return state
    }
}
