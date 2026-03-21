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

            // Parse ESF subscribed events from lines like "events: [AUTH_EXEC, NOTIFY_FORK, ...]"
            let subscribedEvents = Self.parseSubscribedEvents(stripped)

            extensions.append(SystemExtension(
                identifier: id,
                teamId: teamId,
                extensionType: extType,
                enabled: enabled,
                subscribedEvents: subscribedEvents
            ))
        }

        return extensions
    }

    /// Parse ESF event subscriptions from systemextensionsctl output.
    /// Looks for patterns like "events=[AUTH_EXEC,NOTIFY_FORK]" or "events: AUTH_EXEC, NOTIFY_FORK".
    internal static func parseSubscribedEvents(_ line: String) -> [String] {
        // Pattern 1: events=[EVENT1,EVENT2]
        if let range = line.range(of: "events=\\[[^\\]]*\\]", options: .regularExpression) {
            let eventsStr = line[range]
            let inner = eventsStr.dropFirst("events=[".count).dropLast(1)
            return inner.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        }
        // Pattern 2: events: EVENT1, EVENT2
        if let range = line.range(of: "events:\\s*[A-Z_,\\s]+", options: .regularExpression) {
            let eventsStr = String(line[range]).replacingOccurrences(of: "events:", with: "").trimmingCharacters(in: .whitespaces)
            return eventsStr.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        }
        return []
    }
}
