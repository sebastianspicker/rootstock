import Foundation
import Models
import TCC
import Entitlements
import CodeSigning
import XPCServices
import Persistence
import Keychain
import MDM

/// Coordinates all data source modules and assembles the final ScanResult.
struct ScanOrchestrator {
    let verbose: Bool

    struct ModuleConfig {
        let tcc: Bool
        let entitlements: Bool
        let codeSigning: Bool
        let xpc: Bool
        let persistence: Bool
        let keychain: Bool
        let mdm: Bool

        /// Parse a comma-separated module string or "all".
        static func from(_ moduleString: String) -> ModuleConfig {
            let parts = Set(moduleString.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) })
            let all = parts.contains("all")
            return ModuleConfig(
                tcc: all || parts.contains("tcc"),
                entitlements: all || parts.contains("entitlements"),
                codeSigning: all || parts.contains("codesigning"),
                xpc: all || parts.contains("xpc"),
                persistence: all || parts.contains("persistence"),
                keychain: all || parts.contains("keychain"),
                mdm: all || parts.contains("mdm")
            )
        }
    }

    func run(config: ModuleConfig) async -> ScanResult {
        var tccGrants: [TCCGrant] = []
        var applications: [Application] = []
        var xpcServices: [XPCService] = []
        var keychainAcls: [KeychainItem] = []
        var mdmProfiles: [MDMProfile] = []
        var launchItems: [LaunchItem] = []
        var allErrors: [CollectionError] = []

        let total = [config.tcc, config.entitlements, config.codeSigning, config.xpc, config.persistence, config.keychain, config.mdm].filter { $0 }.count
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

        if config.xpc {
            err("[\(step)/\(total)] Enumerating XPC services...")
            let result = await XPCDataSource().collect()
            xpcServices = result.nodes.compactMap { $0 as? XPCService }
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  → \(xpcServices.count) service(s), \(result.errors.count) error(s)") }
            step += 1
        }

        if config.persistence {
            err("[\(step)/\(total)] Scanning persistence mechanisms...")
            let result = await PersistenceDataSource().collect()
            launchItems = result.nodes.compactMap { $0 as? LaunchItem }
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  → \(launchItems.count) item(s), \(result.errors.count) error(s)") }
            step += 1
        }

        if config.keychain {
            err("[\(step)/\(total)] Reading Keychain ACL metadata...")
            let result = await KeychainDataSource().collect()
            keychainAcls = result.nodes.compactMap { $0 as? KeychainItem }
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  → \(keychainAcls.count) item(s), \(result.errors.count) error(s)") }
            step += 1
        }

        if config.mdm {
            err("[\(step)/\(total)] Scanning MDM configuration profiles...")
            let result = await MDMDataSource().collect()
            mdmProfiles = result.nodes.compactMap { $0 as? MDMProfile }
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  → \(mdmProfiles.count) profile(s), \(result.errors.count) error(s)") }
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
            xpcServices: xpcServices,
            keychainAcls: keychainAcls,
            mdmProfiles: mdmProfiles,
            launchItems: launchItems,
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
