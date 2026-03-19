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
        var applications: [Application] = []
        var allErrors: [CollectionError] = []
        let scanStart = Date()

        // Phase 1: Launch independent modules concurrently.
        // TCC, XPC, Persistence, Keychain, and MDM have no data dependencies.
        err("Collecting data sources...")

        async let tccTask = config.tcc
            ? timed { await TCCDataSource().collect() }
            : nil
        async let xpcTask = config.xpc
            ? timed { await XPCDataSource().collect() }
            : nil
        async let persistenceTask = config.persistence
            ? timed { await PersistenceDataSource().collect() }
            : nil
        async let keychainTask = config.keychain
            ? timed { await KeychainDataSource().collect() }
            : nil
        async let mdmTask = config.mdm
            ? timed { await MDMDataSource().collect() }
            : nil

        // Phase 2: Entitlements → CodeSigning (sequential dependency).
        var entElapsed = 0.0
        var csElapsed = 0.0
        if config.entitlements {
            let (result, elapsed) = await timed { await EntitlementDataSource().collect() }
            applications = result.nodes.compactMap { $0 as? Application }
            allErrors.append(contentsOf: result.errors)
            entElapsed = elapsed
        }
        if config.codeSigning {
            let (csErrors, elapsed) = await timed { CodeSigningDataSource().enrich(applications: &applications) }
            allErrors.append(contentsOf: csErrors)
            csElapsed = elapsed
        }

        // Phase 3: Await concurrent results.
        var tccGrants: [TCCGrant] = []
        if let (result, elapsed) = await tccTask {
            tccGrants = result.nodes.compactMap { $0 as? TCCGrant }
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  [TCC]          completed in \(format(elapsed))  (\(tccGrants.count) grants, \(result.errors.count) errors)") }
        }
        if verbose && config.entitlements {
            err("  [Entitlements] completed in \(format(entElapsed))  (\(applications.count) apps)")
        }
        if verbose && config.codeSigning {
            err("  [CodeSigning]  completed in \(format(csElapsed))  (\(applications.count) apps)")
        }

        var xpcServices: [XPCService] = []
        if let (result, elapsed) = await xpcTask {
            xpcServices = result.nodes.compactMap { $0 as? XPCService }
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  [XPC]          completed in \(format(elapsed))  (\(xpcServices.count) services, \(result.errors.count) errors)") }
        }

        var launchItems: [LaunchItem] = []
        if let (result, elapsed) = await persistenceTask {
            launchItems = result.nodes.compactMap { $0 as? LaunchItem }
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  [Persistence]  completed in \(format(elapsed))  (\(launchItems.count) items, \(result.errors.count) errors)") }
        }

        var keychainAcls: [KeychainItem] = []
        if let (result, elapsed) = await keychainTask {
            keychainAcls = result.nodes.compactMap { $0 as? KeychainItem }
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  [Keychain]     completed in \(format(elapsed))  (\(keychainAcls.count) items, \(result.errors.count) errors)") }
        }

        var mdmProfiles: [MDMProfile] = []
        if let (result, elapsed) = await mdmTask {
            mdmProfiles = result.nodes.compactMap { $0 as? MDMProfile }
            allErrors.append(contentsOf: result.errors)
            if verbose { err("  [MDM]          completed in \(format(elapsed))  (\(mdmProfiles.count) profiles, \(result.errors.count) errors)") }
        }

        if verbose {
            let totalElapsed = Date().timeIntervalSince(scanStart)
            err("  Total: \(format(totalElapsed))")
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

    /// Runs `block`, returning the result and wall-clock elapsed time in seconds.
    private func timed<T>(_ block: () async -> T) async -> (T, Double) {
        let start = Date()
        let result = await block()
        return (result, Date().timeIntervalSince(start))
    }

    /// Formats elapsed seconds as "X.XXs".
    private func format(_ seconds: Double) -> String {
        String(format: "%.2fs", seconds)
    }

    /// Write a line to stderr.
    private func err(_ text: String) {
        FileHandle.standardError.write(Data((text + "\n").utf8))
    }
}
