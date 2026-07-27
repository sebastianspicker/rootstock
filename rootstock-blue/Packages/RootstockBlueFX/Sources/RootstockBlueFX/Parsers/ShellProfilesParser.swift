import Foundation
import RootstockBlueCore

/// Shell initialization / profile files - persistence & environment hijack surface.
///
/// Complements `TerminalParser` (command history) with init-time execution
/// (`.zshrc`, `.bash_profile`, `/etc/profile`, …). High-ROI LotL path (T1546.004):
/// PATH prepend, aliases, `DYLD_INSERT_LIBRARIES`, `curl|sh` in profiles.
///
/// Emits stable `persistence.*` fields, entity IDs, and heuristic risk tags for
/// fixture-backed detections.
public struct ShellProfilesParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "SHELLPROFILES",
        tier: .tier1,
        description: "Shell init profiles (.zshrc, .bash_profile, /etc/profile, …)"
    )

    public init() {}

    private static let profileNames: Set<String> = [
        ".zshrc", ".zprofile", ".zshenv", ".zlogin", ".zlogout",
        ".bashrc", ".bash_profile", ".bash_login", ".bash_logout",
        ".profile",
        "zshrc", "zprofile", "zshenv", "bashrc", "profile",
    ]

    private static let systemRelatives = [
        "etc/profile", "private/etc/profile",
        "etc/zshrc", "private/etc/zshrc",
        "etc/zprofile", "private/etc/zprofile",
        "etc/bashrc", "private/etc/bashrc",
        "etc/zshenv", "private/etc/zshenv",
    ]

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in Self.systemRelatives {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseProfile(at: url, scope: "system", user: "root"))
                }
            }
        }

        for url in root.enumerate(matching: { url in
            let name = url.lastPathComponent
            if Self.profileNames.contains(name) { return true }
            // Nested: etc/profile.d/*.sh
            let path = url.path
            return path.contains("/profile.d/") && (name.hasSuffix(".sh") || name.hasSuffix(".zsh"))
        }) {
            if !seen.insert(url) { continue }
            let user = inferUser(from: url) ?? (url.path.contains("/etc/") ? "root" : "unknown")
            let scope = user == "root" || url.path.contains("/etc/") ? "system" : "user"
            events.append(contentsOf: parseProfile(at: url, scope: scope, user: user))
        }

        return events
    }

    private func parseProfile(at url: URL, scope: String, user: String) -> [EventEnvelope] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        var events: [EventEnvelope] = []
        var lineNo = 0
        let pathKey = ArtifactRoot.pathKey(url)

        for rawLine in text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline) {
            lineNo += 1
            let line = String(rawLine).trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }

            let risk = riskTags(for: line)
            var fields: [String: String] = [
                "persistence.kind": "shell_profile",
                "persistence.path": pathKey,
                "persistence.command": line,
                "persistence.line": String(lineNo),
                "shell.profile_scope": scope,
                "shell.profile_name": url.lastPathComponent,
                FieldTaxonomy.filePath: pathKey,
                FieldTaxonomy.eventType: "persistence.item",
                FieldTaxonomy.userName: user,
            ]
            if !risk.isEmpty {
                fields["persistence.risk_tags"] = risk.joined(separator: ",")
                fields["shell.risk"] = risk.joined(separator: ",")
            }
            // First absolute path token as program hint
            for token in line.split(whereSeparator: { $0 == " " || $0 == "\t" || $0 == "|" || $0 == ";" }) {
                let t = String(token)
                if t.hasPrefix("/") {
                    fields[FieldTaxonomy.processPath] = t
                    fields["persistence.program"] = t
                    break
                }
            }

            var entities: [EntityID] = [
                EntityID(kind: .persistence, value: "shell_profile|\(pathKey)|\(lineNo)"),
                .file(path: pathKey),
                .user(name: user),
            ]
            if let prog = fields["persistence.program"] {
                entities.append(.file(path: prog))
            }

            events.append(
                EventEnvelope(
                    eventTime: fileMTime(url),
                    collectedAt: Date(),
                    source: .parser,
                    sourcePlugin: "SHELLPROFILES",
                    eventType: "persistence.item",
                    entityRefs: entities,
                    fields: fields,
                    rawRef: pathKey,
                    confidence: risk.isEmpty ? 0.9 : 0.96
                )
            )
        }

        // Always emit a file-level inventory event even if only comments
        if events.isEmpty {
            events.append(
                EventEnvelope(
                    eventTime: fileMTime(url),
                    collectedAt: Date(),
                    source: .parser,
                    sourcePlugin: "SHELLPROFILES",
                    eventType: "persistence.item",
                    entityRefs: [
                        EntityID(kind: .persistence, value: "shell_profile|\(pathKey)"),
                        .file(path: pathKey),
                        .user(name: user),
                    ],
                    fields: [
                        "persistence.kind": "shell_profile",
                        "persistence.path": pathKey,
                        "persistence.command": "(empty or comments only)",
                        "shell.profile_scope": scope,
                        "shell.profile_name": url.lastPathComponent,
                        FieldTaxonomy.filePath: pathKey,
                        FieldTaxonomy.eventType: "persistence.item",
                        FieldTaxonomy.userName: user,
                    ],
                    rawRef: pathKey,
                    confidence: 0.75
                )
            )
        }
        return events
    }

    /// Heuristic risk tags for blue-team triage (not a full sandbox).
    private func riskTags(for line: String) -> [String] {
        let lower = line.lowercased()
        var tags: [String] = []
        if lower.contains("dyld_insert_libraries") { tags.append("dyld_insert") }
        if lower.contains("curl") && (lower.contains("|sh") || lower.contains("| bash") || lower.contains("|bash")) {
            tags.append("curl_pipe_shell")
        }
        if lower.contains("wget") && (lower.contains("|sh") || lower.contains("| bash")) {
            tags.append("wget_pipe_shell")
        }
        if lower.contains("/tmp/") || lower.contains("/var/tmp/") || lower.contains("/dev/shm") {
            tags.append("tmp_path")
        }
        if lower.contains("base64") && (lower.contains("-d") || lower.contains("decode")) {
            tags.append("base64_decode")
        }
        if lower.hasPrefix("eval ") || lower.contains("$(curl") || lower.contains("`curl") {
            tags.append("eval_remote")
        }
        if lower.contains("export path=") || lower.hasPrefix("path=") {
            tags.append("path_override")
        }
        if lower.contains("alias ") && (lower.contains("sudo=") || lower.contains("ssh=")) {
            tags.append("alias_hijack")
        }
        return tags
    }

    private func fileMTime(_ url: URL) -> Date {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs?[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)
    }
}
