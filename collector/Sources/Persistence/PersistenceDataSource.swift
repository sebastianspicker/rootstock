import Foundation
import Models

/// Enumerates all persistence mechanisms on the system.
///
/// Sources scanned:
///   • LaunchDaemons: /System/Library/LaunchDaemons/, /Library/LaunchDaemons/
///   • LaunchAgents:  /Library/LaunchAgents/, ~/Library/LaunchAgents/
///   • Login Items:   ~/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm
///   • Cron jobs:     /etc/crontab, /var/at/tabs/<user>
///   • Login hooks:   /var/root/Library/Preferences/com.apple.loginwindow.plist
public struct PersistenceDataSource: DataSource {
    public let name = "Persistence"
    public let requiresElevation = false

    private let cronParser = CronParser()

    private static let daemonDirs = [
        "/System/Library/LaunchDaemons",
        "/Library/LaunchDaemons",
    ]

    private static let agentDirs = [
        "/Library/LaunchAgents",
        NSHomeDirectory() + "/Library/LaunchAgents",
    ]

    public init() { }

    public func collect() async -> DataSourceResult {
        var items: [LaunchItem] = []
        var errors: [CollectionError] = []

        // 1. LaunchDaemons
        for dir in Self.daemonDirs {
            let (entries, errs) = parseLaunchdDirectory(at: dir)
            items += entries.map { launchItemFrom($0, type: .daemon) }
            errors += errs.map { CollectionError(source: name, message: $0, recoverable: true) }
        }

        // 2. LaunchAgents
        for dir in Self.agentDirs {
            let (entries, errs) = parseLaunchdDirectory(at: dir)
            items += entries.map { launchItemFrom($0, type: .agent) }
            errors += errs.map { CollectionError(source: name, message: $0, recoverable: true) }
        }

        // 3. Login Items (BTM database)
        let (loginItems, loginErrors) = collectLoginItems()
        items += loginItems
        errors += loginErrors.map { CollectionError(source: name, message: $0, recoverable: true) }

        // 4. Cron jobs
        let (cronItems, cronErrors) = collectCronJobs()
        items += cronItems
        errors += cronErrors.map { CollectionError(source: name, message: $0, recoverable: true) }

        // 5. Login hooks (legacy)
        let (hookItems, hookErrors) = collectLoginHooks()
        items += hookItems
        errors += hookErrors.map { CollectionError(source: name, message: $0, recoverable: true) }

        return DataSourceResult(nodes: items, errors: errors)
    }

    // MARK: - Launchd plist parsing (minimal, persistence-focused)

    private struct PlistEntry {
        let label: String
        let plistPath: String
        let program: String?
        let user: String?
        let runAtLoad: Bool
    }

    private func parseLaunchdDirectory(at dirPath: String) -> ([PlistEntry], [String]) {
        let fm = FileManager.default
        guard fm.fileExists(atPath: dirPath) else { return ([], []) }
        guard let filenames = try? fm.contentsOfDirectory(atPath: dirPath) else {
            return ([], ["Cannot read directory: \(dirPath)"])
        }

        var entries: [PlistEntry] = []
        var errors: [String] = []

        for filename in filenames where filename.hasSuffix(".plist") {
            let fullPath = (dirPath as NSString).appendingPathComponent(filename)
            if let entry = parsePlist(at: fullPath) {
                entries.append(entry)
            } else {
                errors.append("Skipped unparseable plist: \(fullPath)")
            }
        }

        return (entries, errors)
    }

    private func parsePlist(at path: String) -> PlistEntry? {
        guard let data = FileManager.default.contents(atPath: path) else { return nil }

        var format = PropertyListSerialization.PropertyListFormat.xml
        guard let plist = try? PropertyListSerialization.propertyList(
            from: data, options: [], format: &format
        ) as? [String: Any] else { return nil }

        guard let label = plist["Label"] as? String, !label.isEmpty else { return nil }

        let program: String?
        if let prog = plist["Program"] as? String {
            program = prog
        } else if let args = plist["ProgramArguments"] as? [String], let first = args.first {
            program = first
        } else {
            program = nil
        }

        return PlistEntry(
            label: label,
            plistPath: path,
            program: program,
            user: plist["UserName"] as? String,
            runAtLoad: plist["RunAtLoad"] as? Bool ?? false
        )
    }

    private func launchItemFrom(_ entry: PlistEntry, type: LaunchItem.ItemType) -> LaunchItem {
        LaunchItem(
            label: entry.label,
            path: entry.plistPath,
            type: type,
            program: entry.program,
            runAtLoad: entry.runAtLoad,
            user: entry.user
        )
    }

    // MARK: - Login Items (BTM)

    private func collectLoginItems() -> ([LaunchItem], [String]) {
        let btmPath = NSHomeDirectory()
            + "/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm"

        let fm = FileManager.default
        guard fm.fileExists(atPath: btmPath) else { return ([], []) }
        guard let data = fm.contents(atPath: btmPath) else {
            return ([], ["Cannot read BTM file: \(btmPath)"])
        }

        // BTM is a binary plist on older macOS; attempt plist deserialization
        var format = PropertyListSerialization.PropertyListFormat.xml
        guard let plist = try? PropertyListSerialization.propertyList(
            from: data, options: [], format: &format
        ) as? [String: Any] else {
            // BTM format on newer macOS is a custom binary — not parseable as plist
            return ([], ["BTM file format not parseable as plist (newer macOS): \(btmPath)"])
        }

        // Extract login items from whatever structure we find
        var items: [LaunchItem] = []
        extractLoginItemsFromPlist(plist, path: btmPath, into: &items)
        return (items, [])
    }

    private func extractLoginItemsFromPlist(
        _ plist: [String: Any],
        path: String,
        into items: inout [LaunchItem]
    ) {
        // Common keys found in BTM / legacy login item plists
        for key in ["Items", "LoginItems", "SMLoginItems"] {
            if let array = plist[key] as? [[String: Any]] {
                for (i, item) in array.enumerated() {
                    let label = (item["BundleIdentifier"] as? String)
                        ?? (item["Name"] as? String)
                        ?? "login_item.\(i)"
                    let program = item["Path"] as? String
                        ?? item["ExecutablePath"] as? String
                    items.append(LaunchItem(
                        label: label,
                        path: path,
                        type: .loginItem,
                        program: program,
                        runAtLoad: true,
                        user: nil
                    ))
                }
            }
        }
    }

    // MARK: - Cron jobs

    private func collectCronJobs() -> ([LaunchItem], [String]) {
        var items: [LaunchItem] = []
        var errors: [String] = []

        // System crontab
        let systemEntries = cronParser.parseSystemCrontab()
        items += systemEntries.map {
            LaunchItem(
                label: $0.label,
                path: $0.path,
                type: .cron,
                program: $0.program,
                runAtLoad: $0.runAtLoad,
                user: $0.user
            )
        }

        // Per-user crontabs (requires read access to /var/at/tabs)
        let (userEntries, userErrors) = cronParser.parseAllUserCrontabs()
        items += userEntries.map {
            LaunchItem(
                label: $0.label,
                path: $0.path,
                type: .cron,
                program: $0.program,
                runAtLoad: $0.runAtLoad,
                user: $0.user
            )
        }
        errors += userErrors

        return (items, errors)
    }

    // MARK: - Login hooks (legacy)

    private func collectLoginHooks() -> ([LaunchItem], [String]) {
        let paths = [
            "/private/var/root/Library/Preferences/com.apple.loginwindow.plist",
            NSHomeDirectory() + "/Library/Preferences/com.apple.loginwindow.plist",
        ]

        var items: [LaunchItem] = []
        var errors: [String] = []

        for path in paths {
            guard FileManager.default.fileExists(atPath: path) else { continue }
            guard let data = FileManager.default.contents(atPath: path) else {
                errors.append("Cannot read loginwindow plist (requires root): \(path)")
                continue
            }

            var format = PropertyListSerialization.PropertyListFormat.xml
            guard let plist = try? PropertyListSerialization.propertyList(
                from: data, options: [], format: &format
            ) as? [String: Any] else {
                errors.append("Cannot parse loginwindow plist: \(path)")
                continue
            }

            for hookKey in ["LoginHook", "LogoutHook"] {
                if let script = plist[hookKey] as? String {
                    items.append(LaunchItem(
                        label: "loginwindow.\(hookKey)",
                        path: path,
                        type: .loginHook,
                        program: script,
                        runAtLoad: hookKey == "LoginHook",
                        user: path.contains("/root/") ? "root" : nil
                    ))
                }
            }
        }

        return (items, errors)
    }
}
