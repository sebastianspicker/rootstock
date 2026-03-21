import Foundation
import Models

/// Reads `com.apple.quarantine` extended attributes from application bundles.
///
/// The quarantine xattr is a semicolon-delimited hex string:
///   `QFLAG;TIMESTAMP;AGENT_BUNDLE_ID;UUID`
///
/// Flags of interest:
///   - 0x0040: User approved (Gatekeeper prompt accepted)
///   - 0x0020: App was translocated (moved to randomised read-only path)
///
/// This data source enriches existing Application objects — it does not discover
/// new applications. It should run after Entitlements and CodeSigning.
public struct QuarantineDataSource {
    public let name = "Quarantine"

    /// The xattr name for quarantine metadata.
    private static let quarantineXattr = "com.apple.quarantine"

    /// Flag bitmask: user approved the quarantined application.
    private static let userApprovedFlag: UInt32 = 0x0040

    /// Flag bitmask: application was translocated.
    private static let translocatedFlag: UInt32 = 0x0020

    public init() {}

    // MARK: - Public API

    /// Enrich an array of applications with quarantine attribute data in place.
    /// Returns the count of applications that have quarantine data.
    public func enrich(applications: inout [Application]) -> Int {
        var count = 0
        for i in applications.indices {
            let info = readQuarantine(at: applications[i].path)
            applications[i] = Application(
                name: applications[i].name,
                bundleId: applications[i].bundleId,
                path: applications[i].path,
                version: applications[i].version,
                teamId: applications[i].teamId,
                hardenedRuntime: applications[i].hardenedRuntime,
                libraryValidation: applications[i].libraryValidation,
                isElectron: applications[i].isElectron,
                isSystem: applications[i].isSystem,
                signed: applications[i].signed,
                isSipProtected: applications[i].isSipProtected,
                isSandboxed: applications[i].isSandboxed,
                sandboxExceptions: applications[i].sandboxExceptions,
                isNotarized: applications[i].isNotarized,
                isAdhocSigned: applications[i].isAdhocSigned,
                signingCertificateCN: applications[i].signingCertificateCN,
                signingCertificateSHA256: applications[i].signingCertificateSHA256,
                certificateExpires: applications[i].certificateExpires,
                isCertificateExpired: applications[i].isCertificateExpired,
                certificateChainLength: applications[i].certificateChainLength,
                certificateTrustValid: applications[i].certificateTrustValid,
                certificateChain: applications[i].certificateChain,
                entitlements: applications[i].entitlements,
                injectionMethods: applications[i].injectionMethods,
                launchConstraintCategory: applications[i].launchConstraintCategory,
                sandboxProfile: applications[i].sandboxProfile,
                quarantineInfo: info
            )
            if info.hasQuarantineFlag {
                count += 1
            }
        }
        return count
    }

    // MARK: - Quarantine attribute reading

    /// Read and parse the quarantine xattr for the given path.
    /// Returns a QuarantineInfo even if the attribute is absent (hasQuarantineFlag = false).
    public func readQuarantine(at path: String) -> QuarantineInfo {
        guard let raw = getQuarantineXattr(path: path) else {
            return QuarantineInfo(hasQuarantineFlag: false)
        }
        return parseQuarantineString(raw)
    }

    /// Parse the quarantine hex string into structured data.
    ///
    /// Format: `QFLAG;TIMESTAMP;AGENT_BUNDLE_ID;UUID`
    /// Example: `0083;5f3b3c00;com.apple.Safari;12345678-1234-1234-1234-123456789ABC`
    public static func parseQuarantineString(_ raw: String) -> QuarantineInfo {
        let components = raw.split(separator: ";", omittingEmptySubsequences: false).map(String.init)

        // Parse flags (first component, hex)
        var flags: UInt32 = 0
        if let flagStr = components.first {
            flags = UInt32(flagStr, radix: 16) ?? 0
        }

        // Parse timestamp (second component, hex epoch seconds)
        var timestamp: String? = nil
        if components.count > 1 {
            let tsHex = components[1]
            if let epoch = UInt64(tsHex, radix: 16), epoch > 0 {
                let date = Date(timeIntervalSince1970: TimeInterval(epoch))
                let formatter = ISO8601DateFormatter()
                timestamp = formatter.string(from: date)
            }
        }

        // Parse agent bundle ID (third component)
        var agent: String? = nil
        if components.count > 2 {
            let agentStr = components[2].trimmingCharacters(in: .whitespaces)
            if !agentStr.isEmpty {
                agent = agentStr
            }
        }

        let wasUserApproved = (flags & userApprovedFlag) != 0
        let wasTranslocated = (flags & translocatedFlag) != 0

        return QuarantineInfo(
            hasQuarantineFlag: true,
            quarantineAgent: agent,
            quarantineTimestamp: timestamp,
            wasUserApproved: wasUserApproved,
            wasTranslocated: wasTranslocated
        )
    }

    // MARK: - Private

    /// Instance method that delegates to the static parser.
    private func parseQuarantineString(_ raw: String) -> QuarantineInfo {
        Self.parseQuarantineString(raw)
    }

    /// Read the `com.apple.quarantine` xattr from the given file path.
    /// Returns the raw string value, or nil if the attribute is absent.
    private func getQuarantineXattr(path: String) -> String? {
        let name = Self.quarantineXattr
        let size = getxattr(path, name, nil, 0, 0, XATTR_NOFOLLOW)
        guard size > 0 else { return nil }

        var buffer = [UInt8](repeating: 0, count: size)
        let result = getxattr(path, name, &buffer, size, 0, XATTR_NOFOLLOW)
        guard result > 0 else { return nil }

        return String(bytes: buffer[0..<result], encoding: .utf8)
    }
}
