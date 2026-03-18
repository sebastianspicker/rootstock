import Foundation
import Security

/// Extracts the entitlements dictionary from a signed executable.
///
/// Primary method: Security.framework `SecCodeCopySigningInformation`
/// Fallback: `codesign -d --entitlements :- <path>` CLI output parsed as plist
public struct EntitlementExtractor {

    public init() { }

    /// Returns the entitlements dictionary for the executable at the given URL.
    /// Returns an empty dictionary if the executable has no entitlements or if extraction fails.
    public func extract(from executableURL: URL) -> [String: Any] {
        return extractWithSecurityFramework(url: executableURL)
            ?? extractWithCodesignCLI(path: executableURL.path)
            ?? [:]
    }

    // MARK: - Security.framework (primary)

    private func extractWithSecurityFramework(url: URL) -> [String: Any]? {
        var staticCode: SecStaticCode?
        guard SecStaticCodeCreateWithPath(
            url as CFURL, SecCSFlags(rawValue: 0), &staticCode
        ) == errSecSuccess, let code = staticCode else {
            return nil
        }

        // Swift bridges SecCodeCopySigningInformation to take SecStaticCode directly.
        // kSecCSSigningInformation (0x2) makes kSecCodeInfoEntitlementsDict available.
        var cfInfo: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: 0x2), &cfInfo) == errSecSuccess,
              let info = cfInfo as? [String: Any] else {
            return nil
        }

        return info[kSecCodeInfoEntitlementsDict as String] as? [String: Any]
    }

    // MARK: - codesign CLI (fallback)

    private func extractWithCodesignCLI(path: String) -> [String: Any]? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        // `:- ` = write to stdout in plist/XML format
        process.arguments = ["-d", "--entitlements", ":-", path]

        let stdoutPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = Pipe()  // discard stderr

        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return nil
        }

        let data = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        guard !data.isEmpty else { return nil }

        var format = PropertyListSerialization.PropertyListFormat.xml
        return try? PropertyListSerialization.propertyList(
            from: data, options: [], format: &format
        ) as? [String: Any]
    }
}
