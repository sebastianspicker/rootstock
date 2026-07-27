import Foundation
import RootstockBlueCore

/// sudoers policy surface - privilege escalation & persistence-adjacent access control.
///
/// Offline parse of `/etc/sudoers` and `/etc/sudoers.d/*` (and private/etc variants).
/// Emits structured `privilege.sudoers` events with risk tags (NOPASSWD, ALL=(ALL), !authenticate).
///
/// Emits normalized fields, entity IDs, and fixture-backed detections for
/// dangerous grants. It does not implement a complete sudo policy engine.
public struct SudoersParser: ArtifactParser {
    public let manifest = PluginManifest(
        id: "SUDOERS",
        tier: .tier1,
        description: "sudoers and sudoers.d privilege policy entries"
    )

    public init() {}

    public func parse(source: ImageSource) throws -> [EventEnvelope] {
        let root = ArtifactRoot(source: source)
        var events: [EventEnvelope] = []
        var seen = PathDeduper()

        for rel in ["etc/sudoers", "private/etc/sudoers"] {
            if let url = root.firstExisting([rel]) {
                if seen.insert(url) {
                    events.append(contentsOf: parseSudoersFile(at: url))
                }
            }
        }

        for base in ["etc/sudoers.d", "private/etc/sudoers.d"] {
            let dir = root.file(base)
            guard let items = try? FileManager.default.contentsOfDirectory(
                at: dir,
                includingPropertiesForKeys: [.isRegularFileKey],
                options: [.skipsHiddenFiles]
            ) else { continue }
            for item in items {
                if !seen.insert(item) { continue }
                // Skip README / editor backups
                let name = item.lastPathComponent
                if name.hasSuffix("~") || name.hasPrefix(".") { continue }
                events.append(contentsOf: parseSudoersFile(at: item))
            }
        }

        // Enumerate any other sudoers.d-like paths under the image
        for url in root.enumerate(matching: { url in
            let path = url.path
            return path.contains("/sudoers.d/") && !url.hasDirectoryPath
        }) {
            if !seen.insert(url) { continue }
            events.append(contentsOf: parseSudoersFile(at: url))
        }

        return events
    }

    private func parseSudoersFile(at url: URL) -> [EventEnvelope] {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return [] }
        var events: [EventEnvelope] = []
        var lineNo = 0
        let pathKey = ArtifactRoot.pathKey(url)

        for rawLine in text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline) {
            lineNo += 1
            var line = String(rawLine).trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            // Line continuation with trailing \
            while line.hasSuffix("\\") {
                // Multi-line not fully joined without lookahead; keep as-is for single-line fixtures
                line = String(line.dropLast()).trimmingCharacters(in: .whitespaces)
            }

            let kind: String
            if line.hasPrefix("Defaults") {
                kind = "defaults"
            } else if line.hasPrefix("User_Alias") || line.hasPrefix("Runas_Alias")
                || line.hasPrefix("Host_Alias") || line.hasPrefix("Cmnd_Alias") {
                kind = "alias"
            } else if line.hasPrefix("@") {
                kind = "include"
            } else {
                kind = "rule"
            }

            let risk = riskTags(for: line)
            var fields: [String: String] = [
                "privilege.kind": kind,
                "privilege.line": line,
                "privilege.path": pathKey,
                "privilege.line_no": String(lineNo),
                "sudoers.entry": line,
                FieldTaxonomy.filePath: pathKey,
                FieldTaxonomy.eventType: "privilege.sudoers",
            ]
            if !risk.isEmpty {
                fields["privilege.risk_tags"] = risk.joined(separator: ",")
                fields["sudoers.risk"] = risk.joined(separator: ",")
            }
            // User (first token for rules)
            if kind == "rule" {
                let tokens = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
                if let user = tokens.first, !user.isEmpty {
                    fields[FieldTaxonomy.userName] = user
                    fields["sudoers.user"] = user
                }
            }

            var entities: [EntityID] = [
                EntityID(kind: .auth, value: "sudoers|\(pathKey)|\(lineNo)"),
                .file(path: pathKey),
            ]
            if let user = fields[FieldTaxonomy.userName] {
                entities.append(.user(name: user))
            }

            events.append(
                EventEnvelope(
                    eventTime: fileMTime(url),
                    collectedAt: Date(),
                    source: .parser,
                    sourcePlugin: "SUDOERS",
                    eventType: "privilege.sudoers",
                    entityRefs: entities,
                    fields: fields,
                    rawRef: pathKey,
                    confidence: risk.isEmpty ? 0.9 : 0.97
                )
            )
        }
        return events
    }

    private func riskTags(for line: String) -> [String] {
        let upper = line.uppercased()
        var tags: [String] = []
        if upper.contains("NOPASSWD") { tags.append("nopasswd") }
        if upper.contains("!AUTHENTICATE") || upper.contains("! AUTHENTICATE") {
            tags.append("no_authenticate")
        }
        if upper.contains("ALL=(ALL)") || upper.contains("ALL = (ALL)") {
            tags.append("all_runas")
        }
        // ALL ALL or ALL:ALL ALL patterns for full root
        if upper.contains("ALL") && (upper.contains("ALL:ALL") || upper.hasSuffix("ALL") || upper.contains(" ALL")) {
            if upper.contains("(ALL)") || upper.contains("ALL:ALL") {
                tags.append("broad_grant")
            }
        }
        if upper.contains("/TMP/") || upper.contains("/VAR/TMP/") {
            tags.append("tmp_command")
        }
        if upper.contains("!REQUIRETTY") {
            tags.append("no_requiretty")
        }
        return tags
    }

    private func fileMTime(_ url: URL) -> Date {
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attrs?[.modificationDate] as? Date) ?? Date(timeIntervalSince1970: 0)
    }
}
