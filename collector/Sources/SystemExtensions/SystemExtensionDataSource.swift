import Foundation
import Models

/// Enumerates system extensions via `systemextensionsctl list`.
public struct SystemExtensionDataSource: DataSource {
    public let name = "System Extensions"
    public let requiresElevation = false

    public init() {}

    public func collect() async -> DataSourceResult {
        guard let output = Shell.run("/usr/bin/systemextensionsctl", ["list"]) else {
            return DataSourceResult(
                nodes: [],
                errors: [CollectionError(source: name, message: "Failed to run systemextensionsctl", recoverable: true)]
            )
        }

        let extensions = Self.parseSystemExtensionsOutput(output)
        return DataSourceResult(nodes: extensions, errors: [])
    }

    /// Parse `systemextensionsctl list` output.
    /// Lines look like: `---  com.crowdstrike.falcon.Agent (1.0/1.0)  TeamID  [activated enabled]`
    internal static func parseSystemExtensionsOutput(_ output: String) -> [SystemExtension] {
        var extensions: [SystemExtension] = []

        for line in output.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            // Skip header lines and pure separator lines (but not data lines prefixed with ---)
            guard !trimmed.isEmpty,
                  !trimmed.allSatisfy({ $0 == "-" || $0 == "=" }),
                  !trimmed.hasPrefix("System Extension"),
                  !trimmed.hasPrefix("enabled")
            else { continue }
            // Strip leading "--- " or "*   " prefix used by systemextensionsctl
            let stripped: String
            if trimmed.hasPrefix("---") || trimmed.hasPrefix("*") {
                let afterPrefix = trimmed.drop(while: { $0 == "-" || $0 == "*" || $0 == " " })
                stripped = String(afterPrefix)
            } else {
                stripped = trimmed
            }

            // Parse: `identifier (version)  teamID  [state]`
            let parts = stripped.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard parts.count >= 2 else { continue }

            // Find the identifier (contains a dot like com.xxx.yyy)
            var identifier: String?
            var teamId: String?
            // Check the full line for "enabled" — the bracketed state like
            // "[activated enabled]" splits across multiple tokens
            let enabled = stripped.contains("enabled")

            for part in parts {
                if part.contains(".") && !part.hasPrefix("[") && !part.hasPrefix("(") {
                    if identifier == nil {
                        identifier = part
                    }
                }
            }

            // TeamID is typically a 10-char alphanumeric string
            for part in parts {
                if part.count == 10 && part.allSatisfy({ $0.isLetter || $0.isNumber }) && part != identifier {
                    teamId = part
                    break
                }
            }

            guard let id = identifier else { continue }

            // Determine extension type from identifier patterns
            let extType: SystemExtension.ExtensionType
            if id.contains("network") || id.contains("dns") || id.contains("vpn") || id.contains("firewall") {
                extType = .network
            } else if id.contains("endpoint") || id.contains("security") || id.contains("falcon") || id.contains("sentinel") {
                extType = .endpointSecurity
            } else {
                extType = .driver
            }

            extensions.append(SystemExtension(
                identifier: id,
                teamId: teamId,
                extensionType: extType,
                enabled: enabled
            ))
        }

        return extensions
    }
}
