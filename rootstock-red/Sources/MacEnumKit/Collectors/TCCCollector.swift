import Foundation
import CoreServices
import RootstockCore
import RootstockMacFacts

/// Non-prompting TCC / FDA heuristics (assess-safe).
///
/// Strategy:
/// - Prefer `isReadableFile` / existence checks (typically no TCC prompt).
/// - Directory listability on Desktop/Documents/Downloads uses `contentsOfDirectory`
///   which may inherit the host process's existing Files-and-Folders grants; we do not
///   open panels, touch Keychain, or request new TCC prompts intentionally.
/// - System TCC.db readability is a strong FDA signal when true.
/// - Optional CoreServices `MDItemCreateWithURL` metadata peek (no UI) for Library files.
public struct TCCCollector: Collector {
    public static let id = "collect.tcc_graph"
    public static let cost: CollectorCost = .medium

    public init() {}

    public func collect(context: EvaluationContext) async throws -> CollectedState {
        let fm = FileManager.default
        let home = fm.homeDirectoryForCurrentUser

        var notes: [String] = [
            "Non-prompting FDA/TCC heuristics only - no UI, no Keychain, no TCC.db content read",
        ]
        var pathsTouched: [String] = []

        // MARK: TCC database path readability (shared vocabulary)
        let userTCC = MacSecurityPaths.userTCCDatabase(home: home)
        let systemTCC = URL(fileURLWithPath: MacSecurityPaths.systemTCCDatabase)
        pathsTouched.append(userTCC.path)
        pathsTouched.append(systemTCC.path)

        let userTCCExists = fm.fileExists(atPath: userTCC.path)
        let userTCCReadable = fm.isReadableFile(atPath: userTCC.path)
        let systemTCCExists = fm.fileExists(atPath: systemTCC.path)
        let systemTCCReadable = fm.isReadableFile(atPath: systemTCC.path)

        notes.append(
            "User TCC.db exists=\(userTCCExists) readable=\(userTCCReadable) path=\(userTCC.path)"
        )
        notes.append(
            "System TCC.db exists=\(systemTCCExists) readable=\(systemTCCReadable) path=\(systemTCC.path)"
        )

        // MARK: Files-and-Folders style listability (not full FDA)
        let folderProbes: [(String, URL)] = [
            ("Desktop", home.appendingPathComponent("Desktop")),
            ("Documents", home.appendingPathComponent("Documents")),
            ("Downloads", home.appendingPathComponent("Downloads")),
        ]
        var listableFolders: [String] = []
        var unlistableFolders: [String] = []
        for (name, url) in folderProbes {
            pathsTouched.append(url.path)
            let result = Self.listability(of: url, fm: fm)
            switch result {
            case .listable(let count):
                listableFolders.append(name)
                notes.append("\(name): listable (entries≈\(count))")
            case .notListable(let reason):
                unlistableFolders.append(name)
                notes.append("\(name): not listable (\(reason))")
            case .missing:
                notes.append("\(name): path missing")
            }
        }

        // MARK: FDA-sensitive path readability (stronger signal than Desktop)
        let fdaSensitive: [(String, URL)] = [
            ("Safari History.db", home.appendingPathComponent("Library/Safari/History.db")),
            ("Mail", home.appendingPathComponent("Library/Mail")),
            ("Messages chat.db", home.appendingPathComponent("Library/Messages/chat.db")),
            ("Cookies", home.appendingPathComponent("Library/Cookies")),
            ("Knowledge", home.appendingPathComponent("Library/Application Support/Knowledge")),
            (
                "CallHistoryDB",
                home.appendingPathComponent("Library/Application Support/CallHistoryDB")
            ),
            // Additional FDA-gated / privacy areas (SwiftBelt-style path probes).
            ("Calendars", home.appendingPathComponent("Library/Calendars")),
            ("Reminders", home.appendingPathComponent("Library/Reminders")),
            ("Accounts", home.appendingPathComponent("Library/Accounts")),
            ("Containers meta", home.appendingPathComponent("Library/Containers")),
            ("Group Containers", home.appendingPathComponent("Library/Group Containers")),
            ("Suggestions", home.appendingPathComponent("Library/Suggestions")),
            ("Metadata", home.appendingPathComponent("Library/Metadata")),
        ]
        var fdaReadableHits = 0
        var fdaDeniedHits = 0
        var fdaMissingHits = 0
        for (label, url) in fdaSensitive {
            pathsTouched.append(url.path)
            if !fm.fileExists(atPath: url.path) {
                fdaMissingHits += 1
                notes.append("FDA-sensitive \(label): missing path=\(url.path)")
                continue
            }
            if fm.isReadableFile(atPath: url.path) {
                // For directories, also try a shallow list - isReadableFile alone is weak.
                var isDir: ObjCBool = false
                if fm.fileExists(atPath: url.path, isDirectory: &isDir), isDir.boolValue {
                    switch Self.listability(of: url, fm: fm) {
                    case .listable:
                        fdaReadableHits += 1
                        notes.append("FDA-sensitive \(label): listable path=\(url.path)")
                    case .notListable(let reason):
                        fdaDeniedHits += 1
                        notes.append(
                            "FDA-sensitive \(label): dir not listable (\(reason)) path=\(url.path)"
                        )
                    case .missing:
                        fdaMissingHits += 1
                    }
                } else {
                    fdaReadableHits += 1
                    notes.append("FDA-sensitive \(label): readable path=\(url.path)")
                }
            } else {
                fdaDeniedHits += 1
                notes.append("FDA-sensitive \(label): exists but not readable path=\(url.path)")
            }
        }

        // MARK: Spotlight MDItem attribute peek (no UI, no query window)
        let mdProbe = Self.spotlightMDItemProbe(home: home, fm: fm)
        notes.append(contentsOf: mdProbe.notes)
        pathsTouched.append(contentsOf: mdProbe.paths)

        // MARK: Aggregate FDA likelihood
        let fullDiskAccessLikely: Bool?
        if systemTCCReadable || fdaReadableHits >= 2 {
            fullDiskAccessLikely = true
            notes.append(
                "FDA likely=true (systemTCCReadable=\(systemTCCReadable), fdaReadableHits=\(fdaReadableHits))"
            )
        } else if userTCCReadable {
            // Unexpected on modern macOS without FDA; treat as likely.
            fullDiskAccessLikely = true
            notes.append("FDA likely=true (user TCC.db unexpectedly readable)")
        } else if fdaDeniedHits >= 2 && !systemTCCReadable {
            fullDiskAccessLikely = false
            notes.append(
                "FDA likely=false (fdaDeniedHits=\(fdaDeniedHits), system TCC not readable)"
            )
        } else {
            fullDiskAccessLikely = nil
            notes.append(
                "FDA likely=unknown (insufficient signal; denied=\(fdaDeniedHits) readable=\(fdaReadableHits) missing=\(fdaMissingHits))"
            )
        }

        notes.append(
            "Files-and-Folders listable: \(listableFolders.joined(separator: ",").ifEmpty("none")); not: \(unlistableFolders.joined(separator: ",").ifEmpty("none"))"
        )
        notes.append(
            "pathsTouched count=\(Set(pathsTouched).count) (for artifact ledger notes)"
        )

        let probeMethod =
            "tcc_db_readable+desktop_docs_downloads_listability+fda_sensitive_paths(calendars,reminders,containers)+mditem_spotlight_attrs"

        var state = CollectedState()
        state.tcc = TCCState(
            fullDiskAccessLikely: fullDiskAccessLikely,
            notes: notes,
            probeMethod: probeMethod
        )
        state.collectorNotes[Self.id] =
            "FDA likely=\(fullDiskAccessLikely.map(String.init(describing:)) ?? "nil"); method=\(probeMethod)"
        return state
    }

    // MARK: - Helpers

    private enum ListResult {
        case listable(count: Int)
        case notListable(reason: String)
        case missing
    }

    private static func listability(of url: URL, fm: FileManager) -> ListResult {
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: url.path, isDirectory: &isDir) else {
            return .missing
        }
        do {
            let items = try fm.contentsOfDirectory(
                at: url,
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            )
            return .listable(count: items.count)
        } catch {
            let ns = error as NSError
            // Cocoa error 257 / POSIX EPERM/EACCES - permission without inventing a prompt.
            return .notListable(reason: "\(ns.domain)#\(ns.code): \(error.localizedDescription)")
        }
    }

    /// Non-prompting Spotlight metadata via `MDItemCreateWithURL` for a single home Library file.
    private static func spotlightMDItemProbe(
        home: URL,
        fm: FileManager
    ) -> (notes: [String], paths: [String]) {
        var notes: [String] = []
        var paths: [String] = []

        // Prefer a near-universal prefs file; fall back to a few candidates.
        let candidates: [URL] = [
            home.appendingPathComponent("Library/Preferences/.GlobalPreferences.plist"),
            home.appendingPathComponent("Library/Preferences/com.apple.finder.plist"),
            home.appendingPathComponent("Library/Preferences/com.apple.dock.plist"),
        ]

        guard let target = candidates.first(where: { fm.fileExists(atPath: $0.path) }) else {
            notes.append("Spotlight MDItem: no candidate Library prefs file found")
            return (notes, paths)
        }
        paths.append(target.path)

        // MDItemCreateWithURL does not present UI; attribute copy is local metadata.
        guard let item = MDItemCreateWithURL(kCFAllocatorDefault, target as CFURL) else {
            notes.append(
                "Spotlight MDItem: MDItemCreateWithURL returned nil path=\(target.path)"
            )
            return (notes, paths)
        }

        var attrCount = 0
        if let names = MDItemCopyAttributeNames(item) as? [String] {
            attrCount = names.count
        }

        var displayName: String?
        if let name = MDItemCopyAttribute(item, kMDItemDisplayName) as? String {
            displayName = name
        }
        var contentType: String?
        if let ct = MDItemCopyAttribute(item, kMDItemContentType) as? String {
            contentType = ct
        }

        notes.append(
            "Spotlight MDItem: ok attrs≈\(attrCount) displayName=\(displayName ?? "nil") contentType=\(contentType ?? "nil") path=\(target.path)"
        )
        return (notes, paths)
    }
}

private extension String {
    func ifEmpty(_ fallback: String) -> String {
        isEmpty ? fallback : self
    }
}
