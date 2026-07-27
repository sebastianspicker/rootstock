import Foundation

/// Vulnerability assessment planes (not network exploit scanning).
public enum VulnPlane: String, Codable, Sendable, CaseIterable {
    case cvePatchDebt = "A_cve"
    case misconfiguration = "B_misconfig"
    case tccExposure = "C_tcc"
    case codeIdentity = "D_codesign_dylib"
    case mdmPosture = "E_mdm"
    case sandboxEntitlements = "F_sandbox"
    case xpcSurface = "G_xpc"
    case persistenceExposure = "H_persist"
    case authPosture = "I_auth"
    case localNetwork = "J_network"
}
