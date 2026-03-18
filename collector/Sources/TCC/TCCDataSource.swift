import Foundation
import Models

/// Reads TCC (Transparency, Consent, and Control) grants from macOS TCC databases.
///
/// Always attempts the user-level database. The system-level database requires
/// Full Disk Access — failure there is caught and logged, not fatal.
public struct TCCDataSource: DataSource {
    public let name = "TCC Database"
    public let requiresElevation = false

    let userDBPath: String
    let systemDBPath: String?

    /// Default initializer — uses the standard macOS TCC database paths.
    public init() {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        userDBPath = home + "/Library/Application Support/com.apple.TCC/TCC.db"
        systemDBPath = "/Library/Application Support/com.apple.TCC/TCC.db"
    }

    /// Testable initializer with injectable paths.
    init(userDBPath: String, systemDBPath: String?) {
        self.userDBPath = userDBPath
        self.systemDBPath = systemDBPath
    }

    public func collect() async -> DataSourceResult {
        var grants: [TCCGrant] = []
        var errors: [CollectionError] = []

        let userResult = readDB(at: userDBPath, scope: "user")
        grants.append(contentsOf: userResult.grants)
        errors.append(contentsOf: userResult.errors)

        if let systemPath = systemDBPath {
            let systemResult = readDB(at: systemPath, scope: "system")
            grants.append(contentsOf: systemResult.grants)
            errors.append(contentsOf: systemResult.errors)
        }

        return DataSourceResult(nodes: grants, errors: errors)
    }

    private func readDB(at path: String, scope: String) -> (grants: [TCCGrant], errors: [CollectionError]) {
        let db: SQLiteDatabase
        do {
            db = try SQLiteDatabase(path: path)
        } catch {
            return ([], [CollectionError(source: name, message: error.localizedDescription, recoverable: true)])
        }

        let sql = """
            SELECT service, client, client_type, auth_value, auth_reason, last_modified
            FROM access
            WHERE auth_value != 1
            """
        let rows = db.query(sql)
        var grants: [TCCGrant] = []

        for row in rows {
            guard
                let service = row["service"] as? String,
                let client = row["client"] as? String,
                let clientType = row["client_type"] as? Int,
                let authValue = row["auth_value"] as? Int,
                let authReason = row["auth_reason"] as? Int,
                let lastModified = row["last_modified"] as? Int
            else { continue }

            grants.append(TCCGrant(
                service: service,
                displayName: TCCServiceRegistry.displayName(for: service),
                client: client,
                clientType: clientType,
                authValue: authValue,
                authReason: authReason,
                scope: scope,
                lastModified: lastModified
            ))
        }
        return (grants, [])
    }
}
