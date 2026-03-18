import Foundation
import Security

/// Information extracted from an app's code signature.
struct CodeSigningInfo {
    let signed: Bool
    let teamId: String?
    let signingIdentifier: String?
    let hardenedRuntime: Bool
    /// True if CS_REQUIRE_LV flag is set in the code signature.
    let libraryValidationFlag: Bool
    /// True if Security.framework analysis failed (app may still be unsigned).
    let analysisError: Bool
}

/// Extracts code signing metadata from .app bundles using Security.framework.
struct CodeSigningAnalyzer {
    /// CS_RUNTIME (0x10000) — hardened runtime flag from <Security/CSCommon.h>
    private static let csRuntime: UInt32 = 0x10000
    /// CS_REQUIRE_LV (0x2000) — require library validation flag
    private static let csRequireLV: UInt32 = 0x2000

    /// Analyzes the code signing metadata for the app bundle at `appPath`.
    /// Returns a default "unsigned" CodeSigningInfo (with analysisError=true) if extraction fails.
    func analyze(appPath: String) -> CodeSigningInfo {
        let url = URL(fileURLWithPath: appPath) as CFURL
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url, SecCSFlags(rawValue: 0), &staticCode) == errSecSuccess,
              let code = staticCode else {
            return CodeSigningInfo(
                signed: false, teamId: nil, signingIdentifier: nil,
                hardenedRuntime: false, libraryValidationFlag: false, analysisError: true
            )
        }

        var cfInfo: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: 0x2), &cfInfo) == errSecSuccess,
              let info = cfInfo as? [String: Any] else {
            return CodeSigningInfo(
                signed: false, teamId: nil, signingIdentifier: nil,
                hardenedRuntime: false, libraryValidationFlag: false, analysisError: true
            )
        }

        let teamId = info[kSecCodeInfoTeamIdentifier as String] as? String
        let signingIdentifier = info[kSecCodeInfoIdentifier as String] as? String

        var codeFlags: UInt32 = 0
        if let n = info[kSecCodeInfoFlags as String] as? NSNumber {
            codeFlags = n.uint32Value
        }

        return CodeSigningInfo(
            signed: signingIdentifier != nil,
            teamId: teamId,
            signingIdentifier: signingIdentifier,
            hardenedRuntime: (codeFlags & Self.csRuntime) != 0,
            libraryValidationFlag: (codeFlags & Self.csRequireLV) != 0,
            analysisError: false
        )
    }
}
