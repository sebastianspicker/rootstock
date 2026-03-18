import Foundation
import Models
import TCC
import Entitlements
import CodeSigning

/// Coordinates all data source modules and assembles the final ScanResult.
struct ScanOrchestrator {
    let verbose: Bool

    struct ModuleConfig {
        let tcc: Bool
        let entitlements: Bool
        let codeSigning: Bool

        /// Parse a comma-separated module string ("tcc,entitlements,codesigning" or "all").
        static func from(_ moduleString: String) -> ModuleConfig {
            let parts = Set(moduleString.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) })
            let all = parts.contains("all")
            return ModuleConfig(
                tcc: all || parts.contains("tcc"),
                entitlements: all || parts.contains("entitlements"),
                codeSigning: all || parts.contains("codesigning")
            )
        }
    }

    func run(config: ModuleConfig) async -> ScanResult {
        var tccGrants: [TCCGrant] = []
        var applications: [Application] = []
        var allErrors: [CollectionError] = []

        let total = [config.tcc, config.entitlements, config.codeSigning].filter { $0 }.count
        var step = 1

        if config.tcc {
            err("[\(step)/\(total)] Collecting TCC grants...")
            let result = await TCCDataSource().collect()
            tccGrants = result.nodes.compactMap { $0 as? TCCGrant }
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  → \(tccGrants.count) grant(s), \(result.errors.count) error(s)") }
            step += 1
        }

        if config.entitlements {
            err("[\(step)/\(total)] Scanning entitlements...")
            let result = await EntitlementDataSource().collect()
            applications = result.nodes.compactMap { $0 as? Application }
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  → \(applications.count) app(s), \(result.errors.count) error(s)") }
            step += 1
        }

        if config.codeSigning {
            err("[\(step)/\(total)] Analyzing code signatures...")
            let csErrors = CodeSigningDataSource().enrich(applications: &applications)
            allErrors.append(contentsOf: csErrors)
            if verbose { err("  → enriched \(applications.count) app(s), \(csErrors.count) error(s)") }
            step += 1
        }

        return ScanResult(
            scanId: UUID().uuidString,
            timestamp: ISO8601DateFormatter().string(from: Date()),
            hostname: ProcessInfo.processInfo.hostName,
            macosVersion: ProcessInfo.processInfo.operatingSystemVersionString,
            collectorVersion: RootstockCommand.collectorVersion,
            elevation: ElevationInfo(isRoot: getuid() == 0, hasFda: detectFDA()),
            applications: applications,
            tccGrants: tccGrants,
            errors: allErrors
        )
    }

    // MARK: - Private

    /// Detects Full Disk Access by attempting to read the system TCC database.
    private func detectFDA() -> Bool {
        let systemTCC = "/Library/Application Support/com.apple.TCC/TCC.db"
        return FileManager.default.isReadableFile(atPath: systemTCC)
    }

    /// Write a line to stderr.
    private func err(_ text: String) {
        FileHandle.standardError.write(Data((text + "\n").utf8))
    }
}
