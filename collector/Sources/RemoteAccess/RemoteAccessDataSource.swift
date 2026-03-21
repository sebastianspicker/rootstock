import Foundation
import Models

/// Collects SSH and Screen Sharing remote access service status.
///
/// Checks launchctl for service presence and parses config files.
/// No elevation required for read access to sshd_config or ALF prefs.
public struct RemoteAccessDataSource: DataSource {
    public let name = "Remote Access"
    public let requiresElevation = false

    private let sshdConfigPath: String

    public init(sshdConfigPath: String = "/etc/ssh/sshd_config") {
        self.sshdConfigPath = sshdConfigPath
    }

    public func collect() async -> DataSourceResult {
        let ssh = collectSSH()
        let screenSharing = collectScreenSharing()
        return DataSourceResult(nodes: [ssh, screenSharing], errors: [])
    }

    // MARK: - SSH

    private func collectSSH() -> RemoteAccessService {
        let enabled = Shell.succeeds("/bin/launchctl", ["list", "com.openssh.sshd"])
        var config: [String: String] = [:]
        var port: Int? = nil

        if let contents = try? String(contentsOfFile: sshdConfigPath, encoding: .utf8) {
            let directives = parseSSHConfig(contents)
            config = directives
            if let portStr = directives["Port"], let p = Int(portStr) {
                port = p
            }
        }

        return RemoteAccessService(
            service: RemoteServiceName.ssh,
            enabled: enabled,
            port: port ?? (enabled ? 22 : nil),
            config: config
        )
    }

    /// Parses sshd_config for security-relevant directives.
    /// SSH config keys are case-insensitive per sshd_config(5); output uses canonical casing.
    func parseSSHConfig(_ contents: String) -> [String: String] {
        let canonicalKeys: [String: String] = [
            "port": "Port",
            "permitrootlogin": "PermitRootLogin",
            "passwordauthentication": "PasswordAuthentication",
            "pubkeyauthentication": "PubkeyAuthentication",
        ]

        var result: [String: String] = [:]
        for line in contents.components(separatedBy: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty, !trimmed.hasPrefix("#") else { continue }

            let parts = trimmed.split(maxSplits: 1, whereSeparator: \.isWhitespace)
            guard parts.count == 2 else { continue }

            let key = String(parts[0])
            if let canonical = canonicalKeys[key.lowercased()] {
                result[canonical] = String(parts[1])
            }
        }
        return result
    }

    // MARK: - Screen Sharing

    private func collectScreenSharing() -> RemoteAccessService {
        let enabled = Shell.succeeds("/bin/launchctl", ["list", "com.apple.screensharing"])
        return RemoteAccessService(
            service: RemoteServiceName.screenSharing,
            enabled: enabled,
            port: enabled ? 5900 : nil,
            config: [:]
        )
    }
}
