import Foundation

/// Privilege context under which the collector ran.
public struct ElevationInfo: Codable, Sendable {
    public let isRoot: Bool
    public let hasFda: Bool

    public init(isRoot: Bool, hasFda: Bool) {
        self.isRoot = isRoot
        self.hasFda = hasFda
    }

    enum CodingKeys: String, CodingKey {
        case isRoot = "is_root"
        case hasFda = "has_fda"
    }
}

/// Top-level output of a collector scan, containing all discovered metadata and errors.
public struct ScanResult: Codable, Sendable {
    public let scanId: String
    public let timestamp: String
    public let hostname: String
    public let macosVersion: String
    public let collectorVersion: String
    public let elevation: ElevationInfo
    public let applications: [Application]
    public let tccGrants: [TCCGrant]
    public let xpcServices: [XPCService]
    public let keychainAcls: [KeychainItem]
    public let mdmProfiles: [MDMProfile]
    public let launchItems: [LaunchItem]
    public let errors: [CollectionError]

    public init(
        scanId: String,
        timestamp: String,
        hostname: String,
        macosVersion: String,
        collectorVersion: String,
        elevation: ElevationInfo,
        applications: [Application],
        tccGrants: [TCCGrant],
        xpcServices: [XPCService],
        keychainAcls: [KeychainItem],
        mdmProfiles: [MDMProfile],
        launchItems: [LaunchItem],
        errors: [CollectionError]
    ) {
        self.scanId = scanId
        self.timestamp = timestamp
        self.hostname = hostname
        self.macosVersion = macosVersion
        self.collectorVersion = collectorVersion
        self.elevation = elevation
        self.applications = applications
        self.tccGrants = tccGrants
        self.xpcServices = xpcServices
        self.keychainAcls = keychainAcls
        self.mdmProfiles = mdmProfiles
        self.launchItems = launchItems
        self.errors = errors
    }

    enum CodingKeys: String, CodingKey {
        case scanId = "scan_id"
        case timestamp
        case hostname
        case macosVersion = "macos_version"
        case collectorVersion = "collector_version"
        case elevation
        case applications
        case tccGrants = "tcc_grants"
        case xpcServices = "xpc_services"
        case keychainAcls = "keychain_acls"
        case mdmProfiles = "mdm_profiles"
        case launchItems = "launch_items"
        case errors
    }
}
