import Foundation
import Models

// MARK: - Protocol

/// Adapts TCC database queries to the schema of a specific macOS version.
///
/// The TCC `access` table schema has been stable across macOS 14–26 for the
/// columns we need. However, Apple may add or reorganise columns in future
/// releases. This protocol lets each macOS-version-specific adapter declare
/// which columns it requires and how to parse rows — without scattering
/// `if macOS15 { }` branches throughout the reader.
///
/// New columns introduced by future macOS versions are detected via
/// `SQLiteDatabase.columnNames(table:)` and will be silently ignored by
/// existing adapters (forward-compatible by design).
protocol TCCSchemaAdapter {
    /// Column names that MUST exist in the access table for this adapter.
    /// If any required column is absent the factory returns nil.
    var requiredColumns: Set<String> { get }

    /// SQL SELECT statement (includes WHERE clause).
    /// The statement must project exactly the columns that `parseRow` expects.
    func buildQuery() -> String

    /// Parse a result row from `SQLiteDatabase.query(_:)` into a TCCGrant.
    /// Returns nil if the row is malformed (missing required fields).
    func parseRow(_ row: [String: Any], scope: String) -> TCCGrant?
}


// MARK: - Sonoma adapter (macOS 14)

/// TCC schema adapter for macOS 14 Sonoma.
///
/// Queries the six columns that have been stable since macOS Catalina.
/// Any additional columns present in the database (e.g. `pid`, `boot_uuid`)
/// are intentionally ignored — we only read what we need.
struct SonomaTCCSchemaAdapter: TCCSchemaAdapter {
    let requiredColumns: Set<String> = [
        "service", "client", "client_type",
        "auth_value", "auth_reason", "last_modified",
    ]

    func buildQuery() -> String {
        "SELECT service, client, client_type, auth_value, auth_reason, last_modified " +
        "FROM access WHERE auth_value != 1"
    }

    func parseRow(_ row: [String: Any], scope: String) -> TCCGrant? {
        _parseStandardRow(row, scope: scope)
    }
}


// MARK: - Sequoia adapter (macOS 15)

/// TCC schema adapter for macOS 15 Sequoia.
///
/// Functionally identical to the Sonoma adapter — the `access` table schema
/// did not change. The main difference in Sequoia is *access control*: Apple
/// enforces kernel-level read restrictions on TCC.db even with
/// `SQLITE_OPEN_READONLY`, returning `SQLITE_AUTH` without Full Disk Access.
/// That restriction is handled by `TCCDataSource` (open fails → graceful error),
/// not by the schema adapter.
struct SequoiaTCCSchemaAdapter: TCCSchemaAdapter {
    let requiredColumns: Set<String> = [
        "service", "client", "client_type",
        "auth_value", "auth_reason", "last_modified",
    ]

    func buildQuery() -> String {
        "SELECT service, client, client_type, auth_value, auth_reason, last_modified " +
        "FROM access WHERE auth_value != 1"
    }

    func parseRow(_ row: [String: Any], scope: String) -> TCCGrant? {
        _parseStandardRow(row, scope: scope)
    }
}


// MARK: - Tahoe adapter (macOS 26, year-based versioning)

/// TCC schema adapter for macOS 26 Tahoe.
///
/// macOS 26 introduced year-based versioning (formerly planned as "macOS 16").
/// The TCC schema remains compatible with earlier adapters. This adapter is
/// structurally identical to SequoiaTCCSchemaAdapter; it is defined separately
/// so that version-specific behaviour can be added here as Apple documents
/// Tahoe-specific TCC changes.
struct TahoeTCCSchemaAdapter: TCCSchemaAdapter {
    let requiredColumns: Set<String> = [
        "service", "client", "client_type",
        "auth_value", "auth_reason", "last_modified",
    ]

    func buildQuery() -> String {
        "SELECT service, client, client_type, auth_value, auth_reason, last_modified " +
        "FROM access WHERE auth_value != 1"
    }

    func parseRow(_ row: [String: Any], scope: String) -> TCCGrant? {
        _parseStandardRow(row, scope: scope)
    }
}


// MARK: - Factory

/// Creates the appropriate `TCCSchemaAdapter` for a given macOS version and
/// database, using PRAGMA-based column introspection to validate compatibility.
enum TCCSchemaAdapterFactory {

    /// Build an adapter for `version`, validating that `db` has the required columns.
    ///
    /// Returns `nil` with an error description if the `access` table is missing
    /// or doesn't have all required columns (e.g. a deliberately malformed DB).
    static func make(
        for version: MacOSVersion,
        db: SQLiteDatabase
    ) -> (adapter: TCCSchemaAdapter, error: String?)? {
        let available = db.columnNames(table: "access")
        guard !available.isEmpty else {
            return nil  // no access table (malformed DB)
        }

        let candidate: TCCSchemaAdapter
        switch version {
        case .sonoma:                 candidate = SonomaTCCSchemaAdapter()
        case .sequoia:                candidate = SequoiaTCCSchemaAdapter()
        case .tahoe:                  candidate = TahoeTCCSchemaAdapter()
        case .unknown:                candidate = SonomaTCCSchemaAdapter() // best-effort fallback
        }

        let missing = candidate.requiredColumns.subtracting(available)
        guard missing.isEmpty else {
            return nil  // schema incompatible (missing required columns)
        }

        // Warn if there are unexpected extra columns — useful for future research.
        // (Not an error — we simply ignore them.)
        return (candidate, nil)
    }
}


// MARK: - Shared parsing logic

/// Parse the six stable TCC columns into a TCCGrant.
/// Shared by all current adapters; extracted to avoid duplication.
private func _parseStandardRow(_ row: [String: Any], scope: String) -> TCCGrant? {
    guard
        let service     = row["service"]       as? String,
        let client      = row["client"]        as? String,
        let clientType  = row["client_type"]   as? Int,
        let authValue   = row["auth_value"]    as? Int,
        let authReason  = row["auth_reason"]   as? Int,
        let lastMod     = row["last_modified"] as? Int
    else { return nil }

    return TCCGrant(
        service: service,
        displayName: TCCServiceRegistry.displayName(for: service),
        client: client,
        clientType: clientType,
        authValue: authValue,
        authReason: authReason,
        scope: scope,
        lastModified: lastMod
    )
}
