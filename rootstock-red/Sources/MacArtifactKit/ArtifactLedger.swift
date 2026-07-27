import Foundation
import RootstockCore

/// Tracks filesystem artifacts touched during assessment.
///
/// Actor-isolated so concurrent collectors/checks can record safely without
/// `@unchecked Sendable` or manual locking.
public actor ArtifactLedger {
    private var records: [ArtifactRecord] = []

    public init() {}

    public func record(
        path: String,
        action: String,
        hash: String? = nil,
        cleanupRecipe: String? = nil
    ) {
        let entry = ArtifactRecord(
            path: path,
            action: action,
            hash: hash,
            cleanupRecipe: cleanupRecipe
        )
        records.append(entry)
    }

    public func allRecords() -> [ArtifactRecord] {
        records
    }

    /// Record observable paths from a completed collection snapshot.
    ///
    /// Only records paths that were inventoried (and, where applicable, present/exists).
    /// Does not create or mutate host files.
    public func recordStatePaths(_ state: CollectedState) {
        for entry in state.launchAgents {
            record(path: entry.path, action: "observe.launchAgent")
        }
        for entry in state.systemLaunchAgents {
            record(path: entry.path, action: "observe.systemLaunchAgent")
        }
        for entry in state.launchDaemons {
            record(path: entry.path, action: "observe.launchDaemon")
        }
        for meta in state.browserMeta where meta.exists {
            record(path: meta.path, action: "observe.browserMeta")
        }
        for cred in state.credPaths where cred.exists {
            record(path: cred.path, action: "observe.credPath")
        }
        for product in state.securityProducts where product.present {
            record(path: product.path, action: "observe.securityProduct")
        }
        for loobin in state.loobins where loobin.present {
            record(path: loobin.path, action: "observe.loobin")
        }
        for sample in state.codesignSamples {
            record(path: sample.path, action: "observe.codesign")
        }
        for hit in state.injectabilityHits {
            record(path: hit.path, action: "observe.injectability")
        }
        for hit in state.dylibRiskHits {
            record(path: hit.path, action: "observe.dylibRisk")
        }
        for path in state.privilegedHelperTools {
            record(path: path, action: "observe.privilegedHelper")
        }
        for path in state.systemExtensionPaths {
            record(path: path, action: "observe.systemExtension")
        }
        for path in state.loginItemPaths {
            record(path: path, action: "observe.loginItem")
        }
        if let loginItems = state.loginItems {
            if let path = loginItems.btmDirectoryPath {
                record(path: path, action: "observe.btm")
            }
            if let path = loginItems.backgroundItemsBtmPath {
                record(path: path, action: "observe.btm")
            }
            for path in loginItems.loginItemPaths {
                record(path: path, action: "observe.loginItem")
            }
        }

        // TCC-related paths: well-known DBs when TCC state was collected, plus path= notes.
        if let tcc = state.tcc {
            let home = FileManager.default.homeDirectoryForCurrentUser.path
            record(
                path: (home as NSString).appendingPathComponent(
                    "Library/Application Support/com.apple.TCC/TCC.db"
                ),
                action: "observe.tcc"
            )
            record(
                path: "/Library/Application Support/com.apple.TCC/TCC.db",
                action: "observe.tcc"
            )
            for note in tcc.notes {
                if let path = Self.pathFromNote(note) {
                    record(path: path, action: "observe.tccNote")
                }
            }
        }
    }

    public func exportJSON() throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(allRecords())
    }

    public func write(to url: URL) throws {
        try exportJSON().write(to: url, options: .atomic)
    }

    // MARK: - Helpers

    private static func pathFromNote(_ note: String) -> String? {
        // Prefer explicit path= fragments from collectors.
        if let range = note.range(of: "path=") {
            let rest = note[range.upperBound...]
            let token = rest.split(whereSeparator: { $0.isWhitespace }).first.map(String.init)
            if let token, token.hasPrefix("/") {
                return token
            }
        }
        // Bare absolute path line endings (e.g. "… /Users/…/TCC.db").
        let parts = note.split(whereSeparator: { $0.isWhitespace }).map(String.init)
        if let last = parts.last, last.hasPrefix("/"), last.contains("/") {
            return last
        }
        return nil
    }
}
