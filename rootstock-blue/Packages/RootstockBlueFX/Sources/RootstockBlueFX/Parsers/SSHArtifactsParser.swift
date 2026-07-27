import Foundation
import RootstockBlueCore

/// SSH keys and config forensics - metadata only (never dumps private key material as secrets).
public struct SSHArtifactsParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "SSH",
        tier: .tier2,
        description: "SSH authorized_keys, known_hosts, and sshd_config directives"
    )

    /// Interesting sshd_config directives for IR (auth posture).
    private static let interestingDirectives: Set<String> = [
        "PermitRootLogin",
        "PasswordAuthentication",
        "PubkeyAuthentication",
        "PermitEmptyPasswords",
        "ChallengeResponseAuthentication",
        "UsePAM",
        "X11Forwarding",
        "AllowUsers",
        "DenyUsers",
        "AllowGroups",
        "DenyGroups",
        "AuthorizedKeysFile",
        "Port",
        "ListenAddress",
        "Protocol",
        "MaxAuthTries",
    ]

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        // authorized_keys / authorized_keys2 under Users/*/.ssh/
        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            return (name == "authorized_keys" || name == "authorized_keys2")
                && url.path.contains(".ssh")
        }) {
            if !seen.insert(url) { continue }
            events.append(contentsOf: parseAuthorizedKeys(at: url))
        }

        // known_hosts
        for url in root.enumerate(matching: { url in
            url.lastPathComponent == "known_hosts" && url.path.contains(".ssh")
        }) {
            if !seen.insert(url) { continue }
            events.append(contentsOf: parseKnownHosts(at: url))
        }

        // sshd_config
        if let sshd = root.firstExisting([
            "etc/ssh/sshd_config",
            "private/etc/ssh/sshd_config",
            "etc/sshd_config",
        ]) {
            if seen.insert(sshd) {
                events.append(contentsOf: parseSSHDConfig(at: sshd))
            }
        }
        for url in root.enumerate(matching: { $0.lastPathComponent == "sshd_config" }) {
            if !seen.insert(url) { continue }
            events.append(contentsOf: parseSSHDConfig(at: url))
        }

        return events
    }

    // MARK: - authorized_keys

    private func parseAuthorizedKeys(at url: URL) -> [EventEnvelope] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        let user = inferUser(from: url)
        var events: [EventEnvelope] = []
        var lineNo = 0

        for rawLine in text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline) {
            lineNo += 1
            let line = String(rawLine).trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }

            let parsed = parseAuthorizedKeyLine(line)
            guard let keyType = parsed.keyType else { continue }

            var fields: [String: String] = [
                "ssh.key_type": keyType,
                "ssh.key_comment": parsed.comment,
                "ssh.options": parsed.options,
                "ssh.user": user ?? "",
                "ssh.line": String(lineNo),
                FieldTaxonomy.filePath: ArtifactRoot.pathKey(url),
                FieldTaxonomy.eventType: "auth.ssh_authorized_key",
            ]
            if let user {
                fields[FieldTaxonomy.userName] = user
            }

            var entities: [EntityID] = [
                EntityID(kind: .auth, value: "ssh_authorized_key|\(user ?? "unknown")|\(keyType)|\(parsed.comment)"),
                .file(path: ArtifactRoot.pathKey(url)),
            ]
            if let user {
                entities.append(.user(name: user))
            }

            events.append(
                EventEnvelope(
                    eventTime: fileMTime(url),
                    collectedAt: Date(),
                    source: .parser,
                    sourcePlugin: "SSH",
                    eventType: "auth.ssh_authorized_key",
                    entityRefs: entities,
                    fields: fields,
                    rawRef: ArtifactRoot.pathKey(url),
                    confidence: 0.96
                )
            )
        }
        return events
    }

    /// Parse OpenSSH authorized_keys line: [options] key-type base64-key [comment]
    private func parseAuthorizedKeyLine(_ line: String) -> (options: String, keyType: String?, comment: String) {
        let knownTypes = [
            "ssh-ed25519", "ssh-rsa", "ssh-dss", "ssh-ecdsa",
            "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
            "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
            "ssh-ed25519-cert-v01@openssh.com", "ssh-rsa-cert-v01@openssh.com",
        ]

        // Fast path: line starts with key type.
        let tokens = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        guard !tokens.isEmpty else { return ("", nil, "") }

        if knownTypes.contains(tokens[0]) {
            let comment = tokens.count > 2 ? tokens[2...].joined(separator: " ") : ""
            return ("", tokens[0], comment)
        }

        // Options may precede key type (comma-separated options with possible quoted values).
        // Find first known key type token.
        if let typeIdx = tokens.firstIndex(where: { knownTypes.contains($0) }) {
            let options = tokens[..<typeIdx].joined(separator: " ")
            let keyType = tokens[typeIdx]
            let comment: String
            if typeIdx + 2 < tokens.count {
                comment = tokens[(typeIdx + 2)...].joined(separator: " ")
            } else {
                comment = ""
            }
            return (options, keyType, comment)
        }

        // Fallback: treat second token as key type if present (common simplified fixtures).
        if tokens.count >= 2 {
            // options=none, type at 0 may be wrong - try heuristic key-type pattern.
            if tokens[0].hasPrefix("ssh-") || tokens[0].hasPrefix("ecdsa-") || tokens[0].hasPrefix("sk-") {
                let comment = tokens.count > 2 ? tokens[2...].joined(separator: " ") : ""
                return ("", tokens[0], comment)
            }
        }
        return ("", nil, "")
    }

    // MARK: - known_hosts

    private func parseKnownHosts(at url: URL) -> [EventEnvelope] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        let user = inferUser(from: url)
        var events: [EventEnvelope] = []
        var lineNo = 0

        for rawLine in text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline) {
            lineNo += 1
            var line = String(rawLine).trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }

            // Strip optional @cert-authority / @revoked markers.
            var marker = ""
            if line.hasPrefix("@") {
                let parts = line.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
                if parts.count == 2 {
                    marker = String(parts[0])
                    line = String(parts[1])
                }
            }

            let tokens = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard tokens.count >= 2 else { continue }
            let hostPattern = tokens[0]
            let keyType = tokens[1]

            var fields: [String: String] = [
                "ssh.host_pattern": hostPattern,
                "ssh.key_type": keyType,
                "ssh.line": String(lineNo),
                FieldTaxonomy.filePath: ArtifactRoot.pathKey(url),
                FieldTaxonomy.eventType: "auth.ssh_known_host",
            ]
            if !marker.isEmpty {
                fields["ssh.marker"] = marker
            }
            if let user {
                fields[FieldTaxonomy.userName] = user
                fields["ssh.user"] = user
            }

            var entities: [EntityID] = [
                EntityID(kind: .auth, value: "ssh_known_host|\(hostPattern)|\(keyType)"),
                .file(path: ArtifactRoot.pathKey(url)),
            ]
            if let user {
                entities.append(.user(name: user))
            }

            events.append(
                EventEnvelope(
                    eventTime: fileMTime(url),
                    collectedAt: Date(),
                    source: .parser,
                    sourcePlugin: "SSH",
                    eventType: "auth.ssh_known_host",
                    entityRefs: entities,
                    fields: fields,
                    rawRef: ArtifactRoot.pathKey(url),
                    confidence: 0.94
                )
            )
        }
        return events
    }

    // MARK: - sshd_config

    private func parseSSHDConfig(at url: URL) -> [EventEnvelope] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        var events: [EventEnvelope] = []
        var lineNo = 0

        for rawLine in text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline) {
            lineNo += 1
            let trimmed = String(rawLine).trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }

            // directive value…  (whitespace separated)
            let parts = trimmed.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard parts.count >= 2 else { continue }
            let directive = parts[0]
            // Match case-insensitively against interesting set.
            let matched = Self.interestingDirectives.first { $0.caseInsensitiveCompare(directive) == .orderedSame }
            guard let canonical = matched else { continue }
            let value = parts[1...].joined(separator: " ")

            events.append(
                EventEnvelope(
                    eventTime: fileMTime(url),
                    collectedAt: Date(),
                    source: .parser,
                    sourcePlugin: "SSH",
                    eventType: "auth.sshd_config",
                    entityRefs: [
                        EntityID(kind: .auth, value: "sshd_config|\(canonical)"),
                        .file(path: ArtifactRoot.pathKey(url)),
                        EntityID(kind: .host, value: "sshd"),
                    ],
                    fields: [
                        "ssh.directive": canonical,
                        "ssh.value": value,
                        "ssh.line": String(lineNo),
                        FieldTaxonomy.filePath: ArtifactRoot.pathKey(url),
                        FieldTaxonomy.eventType: "auth.sshd_config",
                    ],
                    rawRef: ArtifactRoot.pathKey(url),
                    confidence: 0.97
                )
            )
        }
        return events
    }

    // MARK: - helpers

    private func fileMTime(_ url: URL) -> Date {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs?[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)
    }
}
